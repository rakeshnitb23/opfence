package catalog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ProviderFile is the name of the provider metadata file in each folder.
const ProviderFile = "provider.yaml"

// FixturesDir is the folder, inside a provider folder, holding fixtures.
const FixturesDir = "fixtures"

// Problem is one validation finding, with its location.
type Problem struct {
	File string
	Line int
	Msg  string
}

func (p Problem) String() string {
	switch {
	case p.File == "":
		return p.Msg
	case p.Line > 0:
		return fmt.Sprintf("%s:%d: %s", p.File, p.Line, p.Msg)
	default:
		return fmt.Sprintf("%s: %s", p.File, p.Msg)
	}
}

// ValidationError lists every problem found while loading a catalog.
type ValidationError struct {
	Problems []Problem
}

func (e *ValidationError) Error() string {
	if len(e.Problems) == 1 {
		return "catalog: " + e.Problems[0].String()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "catalog: %d problems:", len(e.Problems))
	for _, p := range e.Problems {
		b.WriteString("\n  ")
		b.WriteString(p.String())
	}
	return b.String()
}

type loader struct {
	fsys     fs.FS
	problems []Problem
	fixtures map[string]bool // every file under */fixtures, by FS path
	// lazy skips what only authors need: fixtures and their tests, and
	// rule line numbers (docs/ARCHITECTURE.md §4.6).
	lazy bool
}

func (l *loader) addf(file string, line int, format string, args ...any) {
	l.problems = append(l.problems, Problem{File: file, Line: line, Msg: fmt.Sprintf(format, args...)})
}

// Load reads every provider folder at the root of fsys and validates the
// result. On any problem it returns a *ValidationError listing all of them.
func Load(fsys fs.FS) (*Catalog, error) {
	l := &loader{fsys: fsys, fixtures: map[string]bool{}}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	var providers []*Provider
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		if p := l.loadProvider(e.Name()); p != nil {
			l.loadProviderFiles(p)
			providers = append(providers, p)
		}
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].ID < providers[j].ID })
	c := &Catalog{Providers: providers, FS: fsys, rules: map[string]*Rule{}}
	l.validate(c)
	if err := l.err(); err != nil {
		return nil, err
	}
	return c, nil
}

// LoadLazy reads and validates every provider in fsys but none of their
// rules, which (*Catalog).LoadRules parses for one provider on first use.
// A hook deciding one MCP call needs one provider's rules, and parsing
// every rule file costs far more than the decision.
//
// A lazy load skips the checks that only catalog authors need: that
// fixtures exist and are used, that rule ids are unique across providers,
// and rule line numbers. Use it only for a catalog that has been loaded
// whole elsewhere, such as the embedded one (tests load it whole).
func LoadLazy(fsys fs.FS) (*Catalog, error) {
	l := &loader{fsys: fsys, lazy: true}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	c := &Catalog{FS: fsys, rules: map[string]*Rule{}, lazy: true}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		if p := l.loadProvider(e.Name()); p != nil {
			p.lazy = &lazyRules{}
			c.Providers = append(c.Providers, p)
		}
	}
	sort.Slice(c.Providers, func(i, j int) bool { return c.Providers[i].ID < c.Providers[j].ID })
	l.validateProviders(c)
	if err := l.err(); err != nil {
		return nil, err
	}
	return c, nil
}

// LoadRules parses and validates p's rules if c was loaded lazily and they
// are not loaded yet. It is safe for concurrent use, and returns the same
// error every time once loading has failed. For a catalog loaded whole it
// does nothing.
func (c *Catalog) LoadRules(p *Provider) error {
	if !c.lazy || p == nil || p.lazy == nil {
		return nil
	}
	p.lazy.once.Do(func() {
		l := &loader{fsys: c.FS, lazy: true}
		l.loadProviderFiles(p)
		c.mu.Lock()
		defer c.mu.Unlock()
		l.validateRules(c, p, nil)
		if p.lazy.err = l.err(); p.lazy.err != nil {
			// Rules that failed their checks must not decide anything, even
			// for a caller that matches without asking LoadRules first.
			for id, r := range c.rules {
				if r.Provider == p {
					delete(c.rules, id)
				}
			}
			p.Rules = nil
		}
	})
	return p.lazy.err
}

// err returns the problems found as a *ValidationError, sorted, or nil.
func (l *loader) err() error {
	if len(l.problems) == 0 {
		return nil
	}
	sort.SliceStable(l.problems, func(i, j int) bool {
		if l.problems[i].File != l.problems[j].File {
			return l.problems[i].File < l.problems[j].File
		}
		if l.problems[i].Line != l.problems[j].Line {
			return l.problems[i].Line < l.problems[j].Line
		}
		return l.problems[i].Msg < l.problems[j].Msg
	})
	return &ValidationError{Problems: l.problems}
}

// loadProvider reads a provider folder's provider.yaml.
func (l *loader) loadProvider(dir string) *Provider {
	pfile := path.Join(dir, ProviderFile)
	data, err := fs.ReadFile(l.fsys, pfile)
	if err != nil {
		l.addf(dir, 0, "missing %s", ProviderFile)
		return nil
	}
	p := &Provider{Dir: dir}
	if !l.decodeStrict(pfile, data, p) {
		return nil
	}
	return p
}

// loadProviderFiles reads the rest of a provider folder: its rule files, and
// its fixtures unless the load is lazy.
func (l *loader) loadProviderFiles(p *Provider) {
	dir := p.Dir
	entries, err := fs.ReadDir(l.fsys, dir)
	if err != nil {
		l.addf(dir, 0, "%v", err)
		return
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		full := path.Join(dir, name)
		info, err := fs.Stat(l.fsys, full)
		if err != nil {
			l.addf(full, 0, "%v", err)
			continue
		}
		switch {
		case info.IsDir() && name == FixturesDir:
			if !l.lazy {
				l.collectFixtures(full)
			}
		case info.IsDir():
			l.addf(full, 0, "unexpected folder (only %s/ is allowed in a provider folder)", FixturesDir)
		case name == ProviderFile:
		case strings.HasSuffix(name, ".yaml"):
			l.loadRuleFile(p, full)
		case strings.HasSuffix(name, ".yml"):
			l.addf(full, 0, "use the .yaml extension")
		case strings.HasPrefix(name, ".") || strings.EqualFold(name, "README.md"):
		default:
			l.addf(full, 0, "unexpected file in provider folder")
		}
	}
}

func (l *loader) collectFixtures(dir string) {
	_ = fs.WalkDir(l.fsys, dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			l.addf(p, 0, "%v", err)
			return nil
		}
		if !d.IsDir() && !strings.HasPrefix(d.Name(), ".") {
			l.fixtures[p] = true
		}
		return nil
	})
}

// ruleFile is the strict shape of a rule file.
type ruleFile struct {
	Operations []*Rule `yaml:"operations"`
}

// ruleFileNodes is the same file decoded loosely, to recover line numbers.
type ruleFileNodes struct {
	Operations []yaml.Node `yaml:"operations"`
}

func (l *loader) loadRuleFile(p *Provider, file string) {
	data, err := fs.ReadFile(l.fsys, file)
	if err != nil {
		l.addf(file, 0, "%v", err)
		return
	}
	var rf ruleFile
	if !l.decodeStrict(file, data, &rf) {
		return
	}
	var nodes ruleFileNodes
	if !l.lazy {
		_ = yaml.Unmarshal(data, &nodes) // a second parse, only for line numbers
	}
	if len(rf.Operations) == 0 {
		l.addf(file, 0, "no operations")
	}
	for i, r := range rf.Operations {
		if r == nil {
			l.addf(file, 0, "operation %d is empty", i+1)
			continue
		}
		r.Provider = p
		r.File = file
		if i < len(nodes.Operations) {
			r.Line = nodes.Operations[i].Line
		}
		p.Rules = append(p.Rules, r)
	}
}

// decodeStrict decodes exactly one YAML document, rejecting unknown fields.
func (l *loader) decodeStrict(file string, data []byte, v any) bool {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			l.addf(file, 0, "empty file")
		} else {
			l.addf(file, 0, "%s", strings.TrimPrefix(err.Error(), "yaml: "))
		}
		return false
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		l.addf(file, 0, "only one YAML document per file is allowed")
		return false
	}
	return true
}

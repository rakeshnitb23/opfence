package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/request"
)

// Finding is one credential opfence init found in a file.
type Finding struct {
	File     string // absolute path
	Line     int    // line number in a .env file; 0 in JSON files
	Where    string // the variable name or JSON path
	Provider string
	Name     string // proposed secret name
	Value    string
	Skip     string // why it is left alone; empty when it will be moved
}

// Files opfence init reads, relative to the repository root, besides .env
// files anywhere in the tree.
var jsonFiles = []string{
	".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json",
	".claude/settings.json", ".claude/settings.local.json",
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"dist": true, "build": true, "target": true, ".next": true, ".terraform": true,
}

const maxDepth = 6

// editorSkip explains why keys in other editors' MCP configs stay in place:
// opfence run starts Claude Code, whose MCP servers reach their APIs through
// the proxy, but not Cursor or VS Code, whose servers would get a
// placeholder they cannot use.
const editorSkip = "this editor's MCP servers are not started by opfence run, so a placeholder would break them; move it by hand if you only use the server from Claude Code"

// editorConfigs are MCP configs that belong to other editors.
var editorConfigs = []string{".cursor/mcp.json", ".vscode/mcp.json"}

// isEnvFile reports whether name is a dotenv file that may hold real values
// (.env, .env.local, .env.production), not a committed template.
func isEnvFile(name string) bool {
	if name != ".env" && !strings.HasPrefix(name, ".env.") {
		return false
	}
	for _, s := range []string{".example", ".sample", ".template", ".dist", ".defaults", ".schema"} {
		if strings.HasSuffix(name, s) {
			return false
		}
	}
	return true
}

// CandidateFiles lists the files opfence init reads under root.
func CandidateFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == root {
				return err
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if path != root && (skipDirs[d.Name()] || strings.Count(rel, string(filepath.Separator)) >= maxDepth) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() && isEnvFile(d.Name()) {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, f := range jsonFiles {
		p := filepath.Join(root, filepath.FromSlash(f))
		if info, err := os.Lstat(p); err == nil && info.Mode().IsRegular() {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// detector knows every provider's variable names, token prefixes and hosts.
type detector struct {
	c        *catalog.Catalog
	byEnv    map[string]*catalog.Provider
	prefixRe []prefixMatcher
	known    *Set
}

type prefixMatcher struct {
	prov *catalog.Provider
	re   *regexp.Regexp
}

func newDetector(c *catalog.Catalog, known *Set) *detector {
	d := &detector{c: c, byEnv: map[string]*catalog.Provider{}, known: known}
	for _, p := range c.Providers {
		for _, e := range p.Detect.Env {
			d.byEnv[e] = p
		}
		for _, pre := range p.Detect.Prefixes {
			if len(pre) < 3 {
				continue
			}
			d.prefixRe = append(d.prefixRe, prefixMatcher{p, regexp.MustCompile(`(^|[^A-Za-z0-9_])(` + regexp.QuoteMeta(pre) + `[A-Za-z0-9_\-.]{12,})`)})
		}
	}
	return d
}

// byPrefix finds a token with a known prefix inside s.
func (d *detector) byPrefix(s string) (*catalog.Provider, string) {
	for _, m := range d.prefixRe {
		if sub := m.re.FindStringSubmatch(s); sub != nil {
			return m.prov, sub[2]
		}
	}
	return nil, ""
}

func (d *detector) finding(file string, line int, where, name string, prov *catalog.Provider, value string) Finding {
	f := Finding{File: file, Line: line, Where: where, Provider: prov.ID, Name: name, Value: value}
	switch {
	case prov.SigV4:
		f.Skip = "AWS keys stay where they are until Opfence can re-sign requests (stage 10)"
	case strings.Contains(value, "${") || strings.Contains(value, "$(") || strings.HasPrefix(value, "$"):
		f.Skip = "a reference to another variable, not a value"
	case d.known.IsPlaceholder(value):
		f.Skip = "already an Opfence placeholder"
	case len(value) < MinLength:
		f.Skip = "too short to be an API token"
	}
	return f
}

// Discover reads the candidate files under root and reports every
// credential for a catalog provider. known holds secrets Opfence already
// has, so placeholders are recognised.
func Discover(root string, c *catalog.Catalog, known *Set) ([]Finding, error) {
	files, err := CandidateFiles(root)
	if err != nil {
		return nil, err
	}
	d := newDetector(c, known)
	var out []Finding
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(f, ".json") {
			fs, err := d.json(f, data)
			if err != nil {
				return nil, err
			}
			for _, e := range editorConfigs {
				if strings.HasSuffix(filepath.ToSlash(f), "/"+e) {
					for i := range fs {
						if fs[i].Skip == "" {
							fs[i].Skip = editorSkip
						}
					}
				}
			}
			out = append(out, fs...)
		} else {
			out = append(out, d.dotenv(f, data)...)
		}
	}
	return out, nil
}

var envKeyRe = regexp.MustCompile(`^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$`)

func (d *detector) dotenv(file string, data []byte) []Finding {
	var out []Finding
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		m := envKeyRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		key, raw := m[1], m[2]
		value, escaped := dotenvValue(raw)
		if value == "" {
			continue
		}
		prov := d.byEnv[key]
		token := value
		if prov == nil {
			if prov, token = d.byPrefix(value); prov == nil {
				continue
			}
		}
		f := d.finding(file, i+1, key, key, prov, token)
		if f.Skip == "" && escaped {
			f.Skip = "the value uses escape sequences; move it by hand"
		}
		out = append(out, f)
	}
	return out
}

// dotenvValue returns a .env value without quotes or a trailing comment, and
// whether it held escape sequences.
func dotenvValue(raw string) (string, bool) {
	switch {
	case strings.HasPrefix(raw, "'"):
		if end := strings.IndexByte(raw[1:], '\''); end >= 0 {
			return raw[1 : 1+end], false
		}
		return "", false // multi-line value
	case strings.HasPrefix(raw, `"`):
		for i := 1; i < len(raw); i++ {
			switch raw[i] {
			case '\\':
				return raw[1:], true
			case '"':
				return raw[1:i], false
			}
		}
		return "", false
	}
	if i := strings.Index(raw, " #"); i >= 0 {
		raw = raw[:i]
	}
	return strings.TrimSpace(raw), false
}

func (d *detector) json(file string, data []byte) ([]Finding, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	var out []Finding
	var walk func(v any, path []string, inEnv bool, urlProv *catalog.Provider)
	walk = func(v any, path []string, inEnv bool, urlProv *catalog.Provider) {
		where := strings.Join(path, ".")
		switch x := v.(type) {
		case map[string]any:
			var hostProv *catalog.Provider
			if u, ok := x["url"].(string); ok {
				if pu, err := url.Parse(u); err == nil {
					h, _ := request.SplitHostPort(pu.Host)
					hostProv = d.c.ProviderForHost(h)
				}
			}
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				child := append(append([]string{}, path...), k)
				switch {
				case inEnv:
					if s, ok := x[k].(string); ok {
						if prov := d.byEnv[k]; prov != nil && s != "" {
							out = append(out, d.finding(file, 0, strings.Join(child, "."), k, prov, s))
							continue
						}
					}
					walk(x[k], child, false, nil)
				case k == "env":
					walk(x[k], child, true, nil)
				case k == "headers":
					walk(x[k], child, false, hostProv)
				default:
					walk(x[k], child, false, nil)
				}
			}
		case []any:
			for i, e := range x {
				walk(e, append(append([]string{}, path...), fmt.Sprint(i)), false, nil)
			}
		case string:
			if prov, tok := d.byPrefix(x); prov != nil {
				out = append(out, d.finding(file, 0, where, where, prov, tok))
				return
			}
			if urlProv != nil && len(path) > 0 && isAuthHeader(urlProv, path[len(path)-1]) {
				// The auth header of a server whose URL is a catalog host:
				// "Bearer <token>" or a bare token.
				tok := x
				if i := strings.LastIndexByte(tok, ' '); i >= 0 {
					tok = tok[i+1:]
				}
				if tok != "" {
					out = append(out, d.finding(file, 0, where, where, urlProv, tok))
				}
			}
		}
	}
	walk(v, nil, false, nil)
	// The token must appear verbatim in the file for the rewrite.
	for i := range out {
		if out[i].Skip == "" && !bytes.Contains(data, []byte(out[i].Value)) {
			out[i].Skip = "the value is escaped in the file; move it by hand"
		}
	}
	return out, nil
}

func isAuthHeader(p *catalog.Provider, name string) bool {
	for _, a := range p.Auth {
		if a.Header != "" && strings.EqualFold(a.Header, name) {
			return true
		}
	}
	return false
}

// ScanEnv reports credentials for catalog providers in environment entries
// ("NAME=value"), with the same skip reasons as files. File is empty and
// Where is the variable name.
func ScanEnv(environ []string, c *catalog.Catalog, known *Set) []Finding {
	d := newDetector(c, known)
	var out []Finding
	for _, kv := range environ {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || value == "" {
			continue
		}
		prov, token := d.byEnv[key], value
		if prov == nil {
			if prov, token = d.byPrefix(value); prov == nil {
				continue
			}
		}
		out = append(out, d.finding("", 0, key, key, prov, token))
	}
	return out
}

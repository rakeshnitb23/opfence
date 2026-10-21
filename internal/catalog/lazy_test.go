package catalog

import (
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"sync"
	"testing"

	catalogdata "github.com/rakeshnitb23/opfence/catalog"
	"github.com/rakeshnitb23/opfence/internal/classes"
)

// A lazy load gives every provider the same metadata and, once loaded, the
// same rules as a full load: only line numbers differ.
func TestLazyMatchesFull(t *testing.T) {
	full, err := Load(catalogdata.FS)
	if err != nil {
		t.Fatal(err)
	}
	lazy, err := LoadLazy(catalogdata.FS)
	if err != nil {
		t.Fatal(err)
	}
	if len(lazy.Providers) != len(full.Providers) {
		t.Fatalf("lazy load has %d providers, full %d", len(lazy.Providers), len(full.Providers))
	}
	for i, fp := range full.Providers {
		lp := lazy.Providers[i]
		if len(lp.Rules) != 0 {
			t.Fatalf("%s: rules loaded before LoadRules", lp.ID)
		}
		if !reflect.DeepEqual(meta(fp), meta(lp)) {
			t.Fatalf("%s: provider metadata differs", fp.ID)
		}
		if err := lazy.LoadRules(lp); err != nil {
			t.Fatalf("%s: %v", lp.ID, err)
		}
		if len(lp.Rules) != len(fp.Rules) {
			t.Fatalf("%s: %d rules lazily, %d in full", fp.ID, len(lp.Rules), len(fp.Rules))
		}
		for j, fr := range fp.Rules {
			lr := lp.Rules[j]
			if lr.Provider != lp {
				t.Fatalf("%s: rule points at another provider", lr.ID)
			}
			if !reflect.DeepEqual(ruleValue(fr), ruleValue(lr)) {
				t.Fatalf("%s: rule differs between a lazy and a full load", fr.ID)
			}
			if lazy.Rule(fr.ID) != lr {
				t.Fatalf("%s: not indexed after LoadRules", fr.ID)
			}
		}
	}
}

func meta(p *Provider) Provider {
	v := *p
	v.Rules, v.lazy = nil, nil
	return v
}

func ruleValue(r *Rule) Rule {
	v := *r
	v.Provider, v.Line = nil, 0
	return v
}

// openCounter records every file a file system opens.
type openCounter struct {
	fs.FS
	mu     sync.Mutex
	opened []string
}

func (o *openCounter) Open(name string) (fs.File, error) {
	o.mu.Lock()
	o.opened = append(o.opened, name)
	o.mu.Unlock()
	return o.FS.Open(name)
}

func (o *openCounter) take() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := o.opened
	o.opened = nil
	return out
}

// A lazy load reads provider files only, and LoadRules one provider's rule
// files: no fixtures, nothing of another provider.
func TestLazyReadsOneProvider(t *testing.T) {
	counter := &openCounter{FS: catalogdata.FS}
	c, err := LoadLazy(counter)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range counter.take() {
		if name != "." && !strings.HasSuffix(name, "/"+ProviderFile) {
			t.Errorf("lazy load opened %s", name)
		}
	}
	p := c.Provider("planetscale-mcp")
	if err := c.LoadRules(p); err != nil {
		t.Fatal(err)
	}
	opened := counter.take()
	if len(opened) == 0 {
		t.Fatal("LoadRules opened nothing")
	}
	for _, name := range opened {
		if name != "planetscale-mcp" && (!strings.HasPrefix(name, "planetscale-mcp/") || strings.Contains(name, "/"+FixturesDir+"/")) {
			t.Errorf("LoadRules for planetscale-mcp opened %s", name)
		}
	}
	if err := c.LoadRules(p); err != nil {
		t.Fatal(err)
	}
	if again := counter.take(); len(again) != 0 {
		t.Errorf("a second LoadRules opened %v", again)
	}
}

func TestLazyLoadError(t *testing.T) {
	m := goodFS()
	replace("acme/db.yaml", "class: irreversible\n    resource", "class: fatal\n    resource")(m)
	if _, err := Load(m); err == nil {
		t.Fatal("full load accepted a bad class")
	}
	c, err := LoadLazy(m)
	if err != nil {
		t.Fatalf("lazy load reads no rules, yet: %v", err)
	}
	p := c.Provider("acme")
	err = c.LoadRules(p)
	var ve *ValidationError
	if !errors.As(err, &ve) || !strings.Contains(err.Error(), `unknown class "fatal"`) {
		t.Fatalf("got %v, want the validation error", err)
	}
	if again := c.LoadRules(p); again != err {
		t.Fatalf("second LoadRules returned %v, want the same error", again)
	}
}

// What only authors need is skipped: a missing fixture fails a full load
// but not a lazy one, which never decides with fixtures.
func TestLazySkipsFixtures(t *testing.T) {
	m := goodFS()
	delete(m, "acme/fixtures/db-delete.http")
	if _, err := Load(m); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("full load: %v", err)
	}
	c, err := LoadLazy(m)
	if err != nil {
		t.Fatal(err)
	}
	p := c.Provider("acme")
	if err := c.LoadRules(p); err != nil {
		t.Fatal(err)
	}
	if r := c.Rule("acme.db.delete"); r == nil || r.Class != classes.Irreversible {
		t.Fatalf("rule %+v", r)
	}
}

// Provider problems still fail a lazy load.
func TestLazyChecksProviders(t *testing.T) {
	m := goodFS()
	replace("acme/provider.yaml", "hosts: [api.acme.dev]", "hosts: [API.acme.dev]")(m)
	if _, err := LoadLazy(m); err == nil || !strings.Contains(err.Error(), "lower-case DNS name") {
		t.Fatalf("got %v", err)
	}
}

func TestLazyConcurrent(t *testing.T) {
	c, err := LoadLazy(catalogdata.FS)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, p := range c.Providers {
				if err := c.LoadRules(p); err != nil {
					t.Error(err)
					return
				}
				_ = c.Rule(p.ID + ".x")
			}
		}()
	}
	wg.Wait()
}

func TestLoadRulesOnFullCatalog(t *testing.T) {
	c, err := Load(goodFS())
	if err != nil {
		t.Fatal(err)
	}
	if c.Lazy() {
		t.Fatal("a full load is not lazy")
	}
	p := c.Provider("acme")
	n := len(p.Rules)
	if err := c.LoadRules(p); err != nil || len(p.Rules) != n {
		t.Fatalf("LoadRules on a full catalog: %v, %d rules (was %d)", err, len(p.Rules), n)
	}
	if err := c.LoadRules(nil); err != nil {
		t.Fatal(err)
	}
}

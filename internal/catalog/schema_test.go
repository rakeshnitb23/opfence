package catalog

import (
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"

	catalogdata "github.com/rakeshnitb23/opfence/catalog"
	schemafs "github.com/rakeshnitb23/opfence/schema"
)

func compileSchemas(t *testing.T) (provider, rules *jsonschema.Schema) {
	t.Helper()
	c := jsonschema.NewCompiler()
	for _, name := range []string{"provider.schema.json", "rules.schema.json"} {
		data, err := fs.ReadFile(schemafs.FS, name)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := c.AddResource("https://github.com/rakeshnitb23/opfence/schema/"+name, doc); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	if provider, err = c.Compile("https://github.com/rakeshnitb23/opfence/schema/provider.schema.json"); err != nil {
		t.Fatal(err)
	}
	if rules, err = c.Compile("https://github.com/rakeshnitb23/opfence/schema/rules.schema.json"); err != nil {
		t.Fatal(err)
	}
	return provider, rules
}

// yamlToJSON converts a YAML document to the value json.Unmarshal would
// produce, keeping timestamps and other non-JSON scalars as strings.
func yamlToJSON(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.DocumentNode:
		return yamlToJSON(n.Content[0])
	case yaml.MappingNode:
		m := map[string]any{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			v, err := yamlToJSON(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			m[n.Content[i].Value] = v
		}
		return m, nil
	case yaml.SequenceNode:
		out := []any{}
		for _, c := range n.Content {
			v, err := yamlToJSON(c)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!int", "!!float":
			f, err := strconv.ParseFloat(n.Value, 64)
			return f, err
		case "!!bool":
			return n.Value == "true", nil
		case "!!null":
			return nil, nil
		}
		return n.Value, nil
	case yaml.AliasNode:
		return yamlToJSON(n.Alias)
	}
	return nil, fmt.Errorf("unsupported YAML node kind %v", n.Kind)
}

func validateYAML(t *testing.T, s *jsonschema.Schema, name string, data []byte) error {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal(data, &n); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	v, err := yamlToJSON(&n)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return s.Validate(v)
}

// TestEmbeddedCatalogMatchesSchema keeps the published JSON Schema honest:
// every file the loader accepts must also pass the schema editors use.
func TestEmbeddedCatalogMatchesSchema(t *testing.T) {
	ps, rs := compileSchemas(t)
	n := 0
	err := fs.WalkDir(catalogdata.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return err
		}
		data, err := fs.ReadFile(catalogdata.FS, p)
		if err != nil {
			return err
		}
		s := rs
		if path.Base(p) == ProviderFile {
			s = ps
		}
		if err := validateYAML(t, s, p, data); err != nil {
			t.Errorf("%s: %v", p, err)
		}
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no catalog files found")
	}
}

func TestSchemaAcceptsTestCatalog(t *testing.T) {
	ps, rs := compileSchemas(t)
	if err := validateYAML(t, ps, "provider", []byte(goodProvider)); err != nil {
		t.Error(err)
	}
	if err := validateYAML(t, rs, "rules", []byte(goodRules)); err != nil {
		t.Error(err)
	}
}

func TestSchemaRejects(t *testing.T) {
	ps, rs := compileSchemas(t)
	bad := []struct {
		s    *jsonschema.Schema
		name string
		doc  string
	}{
		{ps, "unknown provider field", goodProvider + "colour: red\n"},
		{ps, "auth with two locations", strings.Replace(goodProvider, "scheme: Bearer", "query: t", 1)},
		{rs, "unknown rule field", strings.Replace(goodRules, "class: delete", "class: delete\n    severity: high", 1)},
		{rs, "two matchers", strings.Replace(goodRules, "match: { graphql: { type: mutation, field: dbWipe } }", "match: { graphql: { type: mutation, field: dbWipe }, mcp: { tool: x } }", 1)},
		{rs, "verified without tests", strings.Replace(goodRules, "    tests:\n      - fixture: fixtures/db-delete.http\n        expect: irreversible\n", "", 1)},
		{rs, "condition with two tests", strings.Replace(goodRules, `equals: "true"`, `equals: "true", absent: true`, 1)},
		{rs, "classify bad dialect", strings.Replace(goodRules, "class: delete\n", "class: delete\n    classify: { sql: q, dialect: oracle }\n", 1)},
		{rs, "classify bad format", strings.Replace(goodRules, "class: delete\n", "class: delete\n    classify: { sql: q, format: hrana }\n", 1)},
		{rs, "classify empty sql list", strings.Replace(goodRules, "class: delete\n", "class: delete\n    classify: { sql: [] }\n", 1)},
	}
	good := []string{
		"classify: { sql: q }",
		"classify: { sql: [body.sql, body.batch.sql], dialect: sqlite }",
		"classify: { sql: q, dialect: [mysql, postgres] }",
		"classify: { sql: body, format: libsql }",
	}
	for _, g := range good {
		doc := strings.Replace(goodRules, "class: delete\n", "class: delete\n    "+g+"\n", 1)
		if err := validateYAML(t, rs, g, []byte(doc)); err != nil {
			t.Errorf("%s: schema rejected it: %v", g, err)
		}
	}
	for _, b := range bad {
		if err := validateYAML(t, b.s, b.name, []byte(b.doc)); err == nil {
			t.Errorf("%s: schema accepted it", b.name)
		}
	}
}

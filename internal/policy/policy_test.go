package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

func mustParse(t *testing.T, name, s string) *File {
	t.Helper()
	f, err := Parse([]byte(s), name)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"version":          "version: 2\n",
		"unknown field":    "version: 1\ncolour: red\n",
		"bad env":          "version: 1\nenvironments:\n  prod: {}\n",
		"bad default":      "version: 1\ndefault_environment: qa\n",
		"bad class":        "version: 1\ndecisions:\n  production: { fatal: deny }\n",
		"bad decision":     "version: 1\ndecisions:\n  production: { write: maybe }\n",
		"bad rule glob":    "version: 1\nrules:\n  - { rule: \"GitHub.Repo\", decision: deny }\n",
		"bad mode":         "version: 1\nmode: loose\n",
		"bad timeout":      "version: 1\napprovals: { timeout: 1h }\n",
		"bad channel":      "version: 1\napprovals: { channels: [email] }\n",
		"empty values":     "version: 1\nenvironments:\n  production:\n    railway: { environmentId: [] }\n",
		"bad arg path":     "version: 1\nenvironments:\n  production:\n    railway: { \"env id\": [x] }\n",
		"bad passthrough":  "version: 1\npassthrough: [\"registry.corp:8080\"]\n",
		"star passthrough": "version: 1\npassthrough: [\"*\"]\n",
	}
	for name, s := range cases {
		if _, err := Parse([]byte(s), "opfence.yaml"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	f, err := Parse(nil, "empty.yaml")
	if err != nil || f.Version != 1 {
		t.Errorf("empty file: %v %+v", err, f)
	}
}

func TestDefaultsAndUserLoosening(t *testing.T) {
	e := Resolve(nil, nil)
	if d, _ := e.Decide("", classes.Irreversible, Production); d != classes.Confirm {
		t.Errorf("irreversible in production = %v", d)
	}
	if d, _ := e.Decide("", classes.Credential, Production); d != classes.Deny {
		t.Errorf("credential in production = %v", d)
	}
	user := mustParse(t, "config.yaml", `version: 1
decisions:
  production: { write: allow }
rules:
  - { rule: "railway.deployment.*", environment: production, decision: allow }
  - { rule: "github.*", decision: deny }
`)
	e = Resolve(user, nil)
	if d, src := e.Decide("", classes.Write, Production); d != classes.Allow || !strings.Contains(src, "config.yaml") {
		t.Errorf("user loosening ignored: %v %s", d, src)
	}
	if d, _ := e.Decide("railway.deployment.redeploy", classes.Write, Production); d != classes.Allow {
		t.Errorf("rule glob: %v", d)
	}
	if d, _ := e.Decide("github.repo.delete", classes.Irreversible, Development); d != classes.Deny {
		t.Errorf("rule override in every env: %v", d)
	}
}

func TestRepoCanOnlyTighten(t *testing.T) {
	repo := mustParse(t, "opfence.yaml", `version: 1
default_environment: development
mode: open
include_draft: true
decisions:
  production: { irreversible: allow }
  development: { write: ask }
rules:
  - { rule: railway.volume.delete, decision: allow }
  - { rule: "vercel.*", decision: deny }
approvals: { timeout: 10s }
`)
	e := Resolve(nil, repo)
	if d, _ := e.Decide("railway.volume.delete", classes.Irreversible, Production); d != classes.Confirm {
		t.Errorf("repo loosened irreversible to %v", d)
	}
	if d, src := e.Decide("", classes.Write, Development); d != classes.Ask || !strings.Contains(src, "opfence.yaml") {
		t.Errorf("repo tightening ignored: %v %s", d, src)
	}
	if d, _ := e.Decide("vercel.project.delete", classes.Delete, Development); d != classes.Deny {
		t.Errorf("repo rule tightening ignored: %v", d)
	}
	if e.DefaultEnvironment != Production || e.Mode != "strict" || e.IncludeDraft {
		t.Errorf("repo loosened settings: %+v", e)
	}
	if e.ApprovalTimeout != 10*time.Second {
		t.Errorf("shorter repo timeout should apply: %v", e.ApprovalTimeout)
	}
	joined := strings.Join(e.Warnings, "\n")
	for _, want := range []string{"default_environment development", "mode open", "include_draft", "decisions.production.irreversible"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no warning about %s:\n%s", want, joined)
		}
	}
}

func TestEnvironmentResolution(t *testing.T) {
	user := mustParse(t, "config.yaml", `version: 1
environments:
  production:
    railway: { environmentId: [env-prod] }
  development:
    railway: { environmentId: [env-dev], projectId: [proj-sandbox] }
`)
	repo := mustParse(t, "opfence.yaml", `version: 1
environments:
  production:
    railway: { volumeId: [vol-main] }
  development:
    railway: { environmentId: [env-prod], volumeId: [vol-scratch] }
`)
	e := Resolve(user, repo)
	args := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	cases := []struct {
		args map[string]string
		want string
	}{
		{map[string]string{"environmentId": "env-dev"}, Development},
		{map[string]string{"environmentId": "env-prod"}, Production},                              // repo cannot move a user prod id to dev
		{map[string]string{"environmentId": "env-dev", "volumeId": "vol-main"}, Production},       // repo can tighten
		{map[string]string{"volumeId": "vol-scratch"}, Production},                                // repo cannot loosen the default
		{map[string]string{"projectId": "proj-sandbox", "environmentId": "env-prod"}, Production}, // production checked first
		{map[string]string{"other": "x"}, Production},
	}
	for _, c := range cases {
		if got, src := e.Environment("railway", args(c.args)); got != c.want {
			t.Errorf("%v: got %s (%s), want %s", c.args, got, src, c.want)
		}
	}
	if got, _ := e.Environment("vercel", args(map[string]string{"environmentId": "env-dev"})); got != Production {
		t.Errorf("mapping leaked across providers: %s", got)
	}

	trusted := mustParse(t, "config.yaml", "version: 1\ntrust_repo: true\n")
	e = Resolve(trusted, repo)
	if got, _ := e.Environment("railway", args(map[string]string{"volumeId": "vol-scratch"})); got != Development {
		t.Errorf("trust_repo should honour repo mappings, got %s", got)
	}
	if d, _ := e.Decide("railway.volume.delete", classes.Irreversible, Production); d != classes.Confirm {
		t.Errorf("trusted repo without loosening entries changed decision: %v", d)
	}
}

func TestPassthrough(t *testing.T) {
	has := func(e *Effective, h string) bool {
		for _, x := range e.Passthrough {
			if x == h {
				return true
			}
		}
		return false
	}
	e := Resolve(nil, nil)
	if !has(e, "registry.npmjs.org") {
		t.Fatal("defaults missing")
	}
	user := mustParse(t, "user", "version: 1\npassthrough: [npm.corp.example, \"*.internal.example\"]\npassthrough_defaults: false\n")
	e = Resolve(user, nil)
	if has(e, "registry.npmjs.org") || !has(e, "npm.corp.example") || !has(e, "*.internal.example") {
		t.Fatalf("user list: %v", e.Passthrough)
	}
	// A repository can switch the defaults off, but cannot add hosts or
	// switch them back on.
	repo := mustParse(t, "opfence.yaml", "version: 1\npassthrough: [evil.example]\npassthrough_defaults: false\n")
	e = Resolve(nil, repo)
	if has(e, "registry.npmjs.org") || has(e, "evil.example") || !strings.Contains(strings.Join(e.Warnings, "\n"), "passthrough is only honoured") {
		t.Fatalf("repo: %v %v", e.Passthrough, e.Warnings)
	}
	repo = mustParse(t, "opfence.yaml", "version: 1\npassthrough_defaults: true\n")
	e = Resolve(user, repo)
	if has(e, "registry.npmjs.org") || !strings.Contains(strings.Join(e.Warnings, "\n"), "passthrough_defaults true would loosen") {
		t.Fatalf("repo re-enabling defaults: %v %v", e.Passthrough, e.Warnings)
	}
}

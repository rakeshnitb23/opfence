package launch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func userCreds(token string) string {
	b, _ := json.Marshal(map[string]string{"type": "authorized_user", "client_id": "32555940559.apps.googleusercontent.com",
		"client_secret": "not-so-secret", "refresh_token": token})
	return string(b)
}

// gcloud's active account and the application default credentials get
// placeholder refresh tokens in a folder of the session's own; the real
// tokens are held, the real folder is denied, and nothing in the session's
// folder holds a real token.
func TestGoogleCredentials(t *testing.T) {
	home := t.TempDir()
	cfg := filepath.Join(home, ".config", "gcloud")
	gcloudToken := "1//0g" + strings.Repeat("Ab3-", 20)
	adcToken := "1//0e" + strings.Repeat("Zx9_", 20)
	writeFile(t, filepath.Join(cfg, "active_config"), "work\n")
	writeFile(t, filepath.Join(cfg, "configurations", "config_work"), "[core]\naccount = dev@acme.dev\nproject = acme-dev\n[compute]\nregion = us-central1\n")
	writeFile(t, filepath.Join(cfg, "configurations", "config_default"), "[core]\naccount = other@acme.dev\n")
	writeFile(t, filepath.Join(cfg, "properties"), "[core]\ndisable_usage_reporting = True\n[auth]\ncredential_file_override =\n")
	writeFile(t, filepath.Join(cfg, "legacy_credentials", "dev@acme.dev", "adc.json"), userCreds(gcloudToken))
	writeFile(t, filepath.Join(cfg, "credentials.db"), "SQLite format 3 "+gcloudToken)
	writeFile(t, filepath.Join(cfg, "access_tokens.db"), "SQLite format 3 ya29.real")
	writeFile(t, filepath.Join(cfg, "application_default_credentials.json"), userCreds(adcToken))

	session := t.TempDir()
	g, err := GoogleCredentials(session, home, "linux", func(string) string { return "" })
	if err != nil || g == nil {
		t.Fatalf("%v %v", g, err)
	}
	if len(g.Secrets) != 2 || g.Secrets[0].Value != gcloudToken || g.Secrets[1].Value != adcToken {
		t.Fatalf("secrets %+v", g.Secrets)
	}
	for _, s := range g.Secrets {
		if s.Provider != "google-oauth" || s.Placeholder == s.Value || len(s.Placeholder) != len(s.Value) {
			t.Errorf("secret %+v", s)
		}
	}
	if !slices.Equal(g.DenyRead, []string{cfg}) {
		t.Errorf("deny %v", g.DenyRead)
	}
	sessionCfg := g.Env["CLOUDSDK_CONFIG"]
	if !strings.HasPrefix(sessionCfg, session) || !strings.HasPrefix(g.Env["CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"], sessionCfg) ||
		!strings.HasPrefix(g.Env["GOOGLE_APPLICATION_CREDENTIALS"], session) {
		t.Fatalf("env %v", g.Env)
	}
	var creds map[string]string
	b, _ := os.ReadFile(g.Env["CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"])
	if err := json.Unmarshal(b, &creds); err != nil || creds["refresh_token"] != g.Secrets[0].Placeholder || creds["type"] != "authorized_user" ||
		creds["client_id"] != "32555940559.apps.googleusercontent.com" {
		t.Fatalf("credentials file %s (%v)", b, err)
	}
	if b, _ := os.ReadFile(filepath.Join(sessionCfg, "configurations", "config_work")); !strings.Contains(string(b), "project = acme-dev") {
		t.Errorf("configuration not copied: %s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(sessionCfg, "properties")); strings.Contains(string(b), "credential_file_override") {
		t.Errorf("properties keep the override: %s", b)
	}
	// Nothing in the session's folder holds a real token or gcloud's
	// databases.
	filepath.WalkDir(session, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), gcloudToken) || strings.Contains(string(b), adcToken) || strings.Contains(string(b), "ya29.real") {
			t.Errorf("%s holds a real credential", p)
		}
		if base := filepath.Base(p); base == "credentials.db" || base == "access_tokens.db" || base == "adc.json" {
			t.Errorf("%s was copied", p)
		}
		return nil
	})
	if len(g.Notes) != 2 {
		t.Errorf("notes %v", g.Notes)
	}
}

func TestGoogleCredentialsCases(t *testing.T) {
	token := "1//0g" + strings.Repeat("Q", 60)
	t.Run("nothing to hide", func(t *testing.T) {
		if g, err := GoogleCredentials(t.TempDir(), t.TempDir(), "linux", func(string) string { return "" }); g != nil || err != nil {
			t.Fatalf("%+v %v", g, err)
		}
	})
	t.Run("same token, one secret; the environment picks the account", func(t *testing.T) {
		home := t.TempDir()
		cfg := filepath.Join(home, "gc")
		writeFile(t, filepath.Join(cfg, "configurations", "config_default"), "[core]\naccount = a@acme.dev\n")
		writeFile(t, filepath.Join(cfg, "legacy_credentials", "b@acme.dev", "adc.json"), userCreds(token))
		adc := filepath.Join(home, "adc.json")
		writeFile(t, adc, userCreds(token))
		env := map[string]string{"CLOUDSDK_CONFIG": cfg, "CLOUDSDK_CORE_ACCOUNT": "b@acme.dev", "GOOGLE_APPLICATION_CREDENTIALS": adc}
		g, err := GoogleCredentials(t.TempDir(), home, "linux", func(k string) string { return env[k] })
		if err != nil || len(g.Secrets) != 1 || len(g.Secrets[0].Sources) != 2 {
			t.Fatalf("%+v %v", g, err)
		}
		if !slices.Equal(g.DenyRead, []string{cfg, adc}) {
			t.Errorf("deny %v", g.DenyRead)
		}
	})
	t.Run("service account keys stay, and the libraries get a copy", func(t *testing.T) {
		home := t.TempDir()
		cfg := filepath.Join(home, ".config", "gcloud")
		writeFile(t, filepath.Join(cfg, "configurations", "config_default"), "[core]\naccount = dev@acme.dev\n")
		writeFile(t, filepath.Join(cfg, "legacy_credentials", "dev@acme.dev", "adc.json"), userCreds(token))
		writeFile(t, filepath.Join(cfg, "application_default_credentials.json"), `{"type": "service_account", "private_key": "x"}`)
		g, err := GoogleCredentials(t.TempDir(), home, "linux", func(string) string { return "" })
		if err != nil || len(g.Secrets) != 1 {
			t.Fatalf("%+v %v", g, err)
		}
		if b, _ := os.ReadFile(g.Env["GOOGLE_APPLICATION_CREDENTIALS"]); !strings.Contains(string(b), "service_account") {
			t.Errorf("copy %s", b)
		}
		if !strings.Contains(strings.Join(g.Notes, "\n"), "service account") {
			t.Errorf("notes %v", g.Notes)
		}
	})
	t.Run("gcloud's own account is a service account", func(t *testing.T) {
		home := t.TempDir()
		cfg := filepath.Join(home, ".config", "gcloud")
		writeFile(t, filepath.Join(cfg, "configurations", "config_default"), "[core]\naccount = ci@acme.iam.gserviceaccount.com\n")
		writeFile(t, filepath.Join(cfg, "legacy_credentials", "ci@acme.iam.gserviceaccount.com", "adc.json"), `{"type": "service_account", "private_key": "x"}`)
		g, err := GoogleCredentials(t.TempDir(), home, "linux", func(string) string { return "" })
		if err != nil || len(g.Secrets) != 0 || len(g.DenyRead) != 0 || len(g.Env) != 0 || g.Dir != "" {
			t.Fatalf("%+v %v", g, err)
		}
	})
	t.Run("credentials that do not parse are left alone", func(t *testing.T) {
		home := t.TempDir()
		cfg := filepath.Join(home, ".config", "gcloud")
		writeFile(t, filepath.Join(cfg, "configurations", "config_default"), "[core]\naccount = dev@acme.dev\n")
		writeFile(t, filepath.Join(cfg, "legacy_credentials", "dev@acme.dev", "adc.json"), `{"type": "authorized_user"}`)
		g, err := GoogleCredentials(t.TempDir(), home, "linux", func(string) string { return "" })
		if err != nil || len(g.Env) != 0 || len(g.DenyRead) != 0 {
			t.Fatalf("%+v %v", g, err)
		}
	})
}

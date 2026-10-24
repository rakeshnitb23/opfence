package launch

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rakeshnitb23/opfence/internal/secrets"
)

// GoogleSession is what GoogleCredentials prepared for one session.
type GoogleSession struct {
	// Env points gcloud and Google's client libraries at the session's
	// copies: CLOUDSDK_CONFIG, CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE and
	// GOOGLE_APPLICATION_CREDENTIALS.
	Env map[string]string
	// Secrets are the real refresh tokens, held in memory for the session
	// as google-oauth's, which the proxy swaps in at Google's token
	// endpoint (auth: form).
	Secrets []*secrets.Secret
	// DenyRead are the real files the sandbox must not read: gcloud's
	// folder and the application default credentials file.
	DenyRead []string
	// Dir is the session's folder; the caller removes it at the end.
	Dir string
	// Notes say what was hidden and what was not, for the banner.
	Notes []string
}

// googleProvider owns the refresh tokens.
const googleProvider = "google-oauth"

// GoogleCredentials prepares a session in which the program never holds a
// usable Google credential (stage 27d). gcloud keeps a refresh token for
// its active account and, after "gcloud auth application-default login",
// another one for the client libraries; either lets its holder act as the
// user, anywhere. For each that is a user account's (authorized_user), it
// writes a copy whose refresh token is a placeholder of the same shape into
// a folder of the session's own, points gcloud (CLOUDSDK_CONFIG with the
// configuration's properties copied, and its credential file override) and
// the libraries (GOOGLE_APPLICATION_CREDENTIALS) at it, and returns the
// real tokens to hold and the real files for the sandbox to deny. Service
// account keys and external accounts are left as they are, and the notes
// say so. With no gcloud folder and no credentials file, it returns nil.
func GoogleCredentials(dir, home, goos string, getenv func(string) string) (*GoogleSession, error) {
	g := &GoogleSession{Env: map[string]string{}}
	cfg := getenv("CLOUDSDK_CONFIG")
	if cfg == "" {
		if goos == "windows" {
			cfg = filepath.Join(getenv("APPDATA"), "gcloud")
		} else {
			cfg = filepath.Join(home, ".config", "gcloud")
		}
	}
	hasCfg := isDir(cfg)
	adcPath := getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if adcPath == "" {
		adcPath = filepath.Join(cfg, "application_default_credentials.json")
	}
	if !hasCfg && !isFile(adcPath) {
		return nil, nil
	}
	g.Dir = filepath.Join(dir, "google")
	if err := os.MkdirAll(g.Dir, 0o700); err != nil {
		return nil, err
	}
	byValue := map[string]*secrets.Secret{}
	hold := func(name, source, token string) (*secrets.Secret, error) {
		if s, ok := byValue[token]; ok {
			s.Sources = append(s.Sources, source)
			return s, nil
		}
		ph, err := secrets.NewPlaceholder(token, nil)
		if err != nil {
			return nil, err
		}
		s := &secrets.Secret{Provider: googleProvider, Name: name, Value: token, Placeholder: ph, Sources: []string{source}, Group: "env", Created: time.Now().UTC()}
		byValue[token] = s
		g.Secrets = append(g.Secrets, s)
		return s, nil
	}

	// gcloud's active account.
	gcloudHidden := false
	if hasCfg {
		account, credFile := gcloudActive(cfg, getenv)
		switch kind, data, err := readCredentials(credFile); {
		case credFile == "":
			g.Notes = append(g.Notes, "gcloud has no active account")
		case err != nil:
			g.Notes = append(g.Notes, fmt.Sprintf("gcloud's credentials for %s could not be read (%v), so they are left as they are", account, err))
		case kind != "authorized_user":
			g.Notes = append(g.Notes, fmt.Sprintf("gcloud's %s is a %s, which Opfence does not hide yet", account, strings.ReplaceAll(kind, "_", " ")))
		default:
			s, err := hold("gcloud "+account, credFile, data["refresh_token"].(string))
			if err != nil {
				return nil, err
			}
			sessionCfg := filepath.Join(g.Dir, "gcloud")
			if err := copyGcloudConfig(cfg, sessionCfg); err != nil {
				return nil, err
			}
			creds := filepath.Join(sessionCfg, "opfence-credentials.json")
			if err := writePlaceholderCredentials(creds, data, s.Placeholder); err != nil {
				return nil, err
			}
			g.Env["CLOUDSDK_CONFIG"] = sessionCfg
			g.Env["CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"] = creds
			g.DenyRead = append(g.DenyRead, cfg)
			gcloudHidden = true
			g.Notes = append(g.Notes, fmt.Sprintf("gcloud signs in as %s with a placeholder refresh token", account))
		}
	}

	// The client libraries' application default credentials.
	if isFile(adcPath) {
		kind, data, err := readCredentials(adcPath)
		inCfg := hasCfg && within(cfg, adcPath)
		switch {
		case err != nil:
			g.Notes = append(g.Notes, fmt.Sprintf("the application default credentials could not be read (%v), so they are left as they are", err))
			if gcloudHidden && inCfg {
				g.Notes = append(g.Notes, "the client libraries cannot read them in the sandbox")
			}
		case kind != "authorized_user":
			g.Notes = append(g.Notes, fmt.Sprintf("the application default credentials are a %s, which Opfence does not hide yet", strings.ReplaceAll(kind, "_", " ")))
			if gcloudHidden && inCfg {
				// gcloud's folder is denied, so the libraries get a copy.
				copied := filepath.Join(g.Dir, "application_default_credentials.json")
				raw, rerr := os.ReadFile(adcPath)
				if rerr != nil {
					return nil, rerr
				}
				if err := os.WriteFile(copied, raw, 0o600); err != nil {
					return nil, err
				}
				g.Env["GOOGLE_APPLICATION_CREDENTIALS"] = copied
			}
		default:
			s, err := hold("application default credentials", adcPath, data["refresh_token"].(string))
			if err != nil {
				return nil, err
			}
			adc := filepath.Join(g.Dir, "application_default_credentials.json")
			if err := writePlaceholderCredentials(adc, data, s.Placeholder); err != nil {
				return nil, err
			}
			g.Env["GOOGLE_APPLICATION_CREDENTIALS"] = adc
			if !inCfg || !gcloudHidden {
				g.DenyRead = append(g.DenyRead, adcPath)
			}
			g.Notes = append(g.Notes, "the application default credentials use a placeholder refresh token")
		}
	}
	if len(g.Env) == 0 {
		os.RemoveAll(g.Dir)
		g.Dir = ""
	}
	return g, nil
}

// gcloudActive reads gcloud's active configuration: its account and the
// file holding that account's credentials (the credential file override,
// or gcloud's own copy in legacy_credentials). The environment's
// CLOUDSDK_CORE_ACCOUNT and CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE come
// first, as they do for gcloud.
func gcloudActive(cfg string, getenv func(string) string) (account, credFile string) {
	name := "default"
	if b, err := os.ReadFile(filepath.Join(cfg, "active_config")); err == nil && strings.TrimSpace(string(b)) != "" {
		name = strings.TrimSpace(string(b))
	}
	if v := getenv("CLOUDSDK_ACTIVE_CONFIG_NAME"); v != "" {
		name = v
	}
	global := iniValues(filepath.Join(cfg, "properties"))
	active := iniValues(filepath.Join(cfg, "configurations", "config_"+filepath.Base(name)))
	pick := func(env, key string) string {
		if v := getenv(env); v != "" {
			return v
		}
		if v := active[key]; v != "" {
			return v
		}
		return global[key]
	}
	account = pick("CLOUDSDK_CORE_ACCOUNT", "core.account")
	credFile = pick("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "auth.credential_file_override")
	if credFile == "" && account != "" {
		credFile = filepath.Join(cfg, "legacy_credentials", filepath.Base(account), "adc.json")
	}
	return account, credFile
}

// iniValues reads a gcloud properties file as section.key = value.
func iniValues(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || line[0] == '#' || line[0] == ';':
		case line[0] == '[' && strings.HasSuffix(line, "]"):
			section = strings.TrimSpace(line[1 : len(line)-1])
		default:
			if k, v, ok := strings.Cut(line, "="); ok {
				out[section+"."+strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	return out
}

// readCredentials reads a Google credentials file: its type and fields.
// An authorized_user file must hold a refresh token.
func readCredentials(path string) (kind string, data map[string]any, err error) {
	if path == "" {
		return "", nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		return "", nil, fmt.Errorf("not JSON: %w", err)
	}
	kind, _ = data["type"].(string)
	if kind == "" {
		return "", nil, errors.New("no type")
	}
	if kind == "authorized_user" {
		if rt, _ := data["refresh_token"].(string); len(rt) < secrets.MinLength {
			return "", nil, errors.New("no refresh token")
		}
	}
	return kind, data, nil
}

func writePlaceholderCredentials(path string, data map[string]any, placeholder string) error {
	out := map[string]any{}
	for k, v := range data {
		out[k] = v
	}
	out["refresh_token"] = placeholder
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// copyGcloudConfig copies gcloud's settings, and nothing that holds a
// credential, into the session's folder: the active configuration's name,
// every named configuration and the global properties. The credential file
// override is left out of the copies (the environment sets the session's
// own), and so are credentials.db, access_tokens.db, legacy_credentials
// and application_default_credentials.json.
func copyGcloudConfig(from, to string) error {
	if err := os.MkdirAll(filepath.Join(to, "configurations"), 0o700); err != nil {
		return err
	}
	cp := func(src, dst string) error {
		b, err := os.ReadFile(src)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return os.WriteFile(dst, withoutCredentialOverride(b), 0o600)
	}
	if err := cp(filepath.Join(from, "active_config"), filepath.Join(to, "active_config")); err != nil {
		return err
	}
	if err := cp(filepath.Join(from, "properties"), filepath.Join(to, "properties")); err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(from, "configurations"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), "config_") {
			if err := cp(filepath.Join(from, "configurations", e.Name()), filepath.Join(to, "configurations", e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// withoutCredentialOverride drops credential_file_override lines from a
// properties file.
func withoutCredentialOverride(b []byte) []byte {
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if k, _, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "credential_file_override" {
			continue
		}
		out = append(out, line)
	}
	return []byte(strings.Join(out, "\n"))
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// within reports whether p is dir or inside it.
func within(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

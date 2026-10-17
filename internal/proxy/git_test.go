package proxy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/secrets"
)

type denyAll struct{ calls atomic.Int32 }

func (d *denyAll) Approve(context.Context, Pending) Approval {
	d.calls.Add(1)
	return Approval{Reason: "denied by the test"}
}

// The stage 10 exit criterion for git: a real git client clones and pushes
// to github.com through the proxy with only a placeholder token. The fake
// GitHub is git's own http-backend, which accepts only the real token.
// Fetches run freely, a push is put to the approver (write in production),
// and a branch delete the approver refuses never reaches the repository.
func TestRealGitThroughProxy(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	backend := filepath.Join(strings.TrimSpace(run(t, "", "git", "--exec-path")), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git-http-backend is not installed")
	}
	token := "ghp" + "_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
	ph, err := secrets.NewPlaceholder(token, []string{"ghp_"})
	if err != nil {
		t.Fatal(err)
	}
	gh := &secrets.Secret{Provider: "github", Name: "GITHUB_TOKEN", Value: token, Placeholder: ph}

	root := t.TempDir()
	bare := filepath.Join(root, "acme", "shop.git")
	run(t, "", gitBin, "init", "-q", "--bare", "-b", "main", bare)
	run(t, bare, gitBin, "config", "http.receivepack", "true")
	seed := filepath.Join(t.TempDir(), "seed")
	run(t, "", gitBin, "init", "-q", "-b", "main", seed)
	run(t, seed, gitBin, "commit", "-q", "--allow-empty", "-m", "first")
	run(t, seed, gitBin, "push", "-q", bare, "main")

	cgiHandler := &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
	e := newEnv(t, opts{secrets: secrets.NewSet([]*secrets.Secret{gh}), respond: func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
			w.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
			http.Error(w, "auth required", http.StatusUnauthorized)
			return
		}
		cgiHandler.ServeHTTP(w, r)
	}})
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, e.ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	remote := "https://x-access-token:" + ph + "@github.com/acme/shop.git"
	gitc := func(dir string, args ...string) (string, error) {
		cmd := exec.Command(gitBin, append([]string{"-c", "http.proxy=http://" + e.httpAddr, "-c", "http.sslCAInfo=" + caFile,
			"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "credential.helper="}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(cleanEnv(), "HOME="+t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	work := filepath.Join(t.TempDir(), "work")
	if out, err := gitc("", "clone", "-q", remote, work); err != nil {
		t.Fatalf("clone: %v\n%s", err, out)
	}

	// A new branch with a 2 MB file: git probes with an empty push, then
	// streams a pack far larger than the decoder reads.
	run(t, work, gitBin, "checkout", "-q", "-b", "feature")
	big := make([]byte, 2<<20)
	_, _ = rand.Read(big)
	if err := os.WriteFile(filepath.Join(work, "big.bin"), big, 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, work, gitBin, "add", "big.bin")
	run(t, work, gitBin, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "big")
	approver := &approveAll{}
	e.srv.cfg.Approver = approver
	if out, err := gitc(work, "push", "-q", "origin", "feature"); err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}
	if approver.calls.Load() != 1 {
		t.Fatalf("approver asked %d times for one push", approver.calls.Load())
	}
	if refs := run(t, bare, gitBin, "show-ref"); !strings.Contains(refs, "refs/heads/feature") {
		t.Fatalf("feature branch not pushed:\n%s", refs)
	}

	// Deleting the branch is refused by the approver and never applied.
	deny := &denyAll{}
	e.srv.cfg.Approver = deny
	out, err := gitc(work, "push", "-q", "origin", "--delete", "feature")
	if err == nil || deny.calls.Load() != 1 || !strings.Contains(out, "[remote rejected] feature (Blocked by Opfence: Delete refs/heads/feature from acme/shop") {
		t.Fatalf("delete was not refused (asked %d): %v\n%s", deny.calls.Load(), err, out)
	}
	if refs := run(t, bare, gitBin, "show-ref"); !strings.Contains(refs, "refs/heads/feature") {
		t.Fatal("refused delete reached the repository")
	}

	got := map[string]int{}
	for _, en := range e.entries() {
		for _, op := range en.Operations {
			got[op.Rule+" "+en.Outcome]++
		}
		if en.Host == "github.com" && en.Outcome != "blocked" && en.Status != http.StatusUnauthorized && len(en.Credentials) != 1 {
			t.Errorf("token not injected: %+v", en)
		}
	}
	for _, k := range []string{"github.git.fetch forwarded", "github.git.list-refs forwarded", "github.git.create-ref approved", "github.git.delete-ref blocked"} {
		if got[k] == 0 {
			t.Errorf("audit has no %q: %v", k, got)
		}
	}
}

// cleanEnv drops the environment's own proxy and CA settings, which would
// override the test's.
func cleanEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(k) {
		case "GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE", "CURL_CA_BUNDLE":
			continue
		}
		out = append(out, kv)
	}
	return out
}

func run(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

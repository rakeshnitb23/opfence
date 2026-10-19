package launch

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestCodexIntegration checks CodexConfig against a real Codex binary named
// by OPFENCE_CODEX: Codex must accept every -c option, trust both hooks
// without asking, and pass Opfence's variables to a stdio MCP server.
func TestCodexIntegration(t *testing.T) {
	codex := os.Getenv("OPFENCE_CODEX")
	if codex == "" {
		t.Skip("set OPFENCE_CODEX to a Codex binary to run")
	}
	home := t.TempDir()
	work := t.TempDir()
	// Spaces and quotes test the TOML escaping and the trust hash together.
	hook := `'/opt/My Tools/opfence' hook codex --config "/tmp/a b/policy.yaml"`
	base := []string{"-c", `mcp_servers.db.command="python3"`, "-c", `mcp_servers.db.env_vars=["PATH"]`}
	servers, err := ParseCodexServers(runCodex(t, codex, home, work, nil, append(base, "mcp", "list", "--json")...))
	if err != nil {
		t.Fatal(err)
	}
	extra, skipped := CodexConfig(CodexOptions{Servers: servers, EnvVars: []string{"HTTPS_PROXY", "SSL_CERT_FILE"}, HookCommand: hook})
	if len(skipped) > 0 {
		t.Fatalf("skipped %v", skipped)
	}
	args := append(slices.Clone(base), extra...)

	servers, err = ParseCodexServers(runCodex(t, codex, home, work, nil, append(slices.Clone(args), "mcp", "list", "--json")...))
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 || !slices.Equal(servers[0].Transport.EnvVars, []any{"PATH", "HTTPS_PROXY", "SSL_CERT_FILE"}) {
		t.Fatalf("servers %+v", servers)
	}

	requests := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"opfence-test","title":null,"version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"hooks/list","params":{}}`,
	}, "\n") + "\n"
	out := runCodex(t, codex, home, work, strings.NewReader(requests), append(args, "app-server")...)
	var list struct {
		Result struct {
			Data []struct {
				Hooks []struct {
					EventName   string `json:"eventName"`
					Command     string `json:"command"`
					TrustStatus string `json:"trustStatus"`
				} `json:"hooks"`
				Errors []any `json:"errors"`
			} `json:"data"`
		} `json:"result"`
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.HasPrefix(line, `{"id":2,`) {
			if err := json.Unmarshal([]byte(line), &list); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(list.Result.Data) != 1 || len(list.Result.Data[0].Errors) > 0 {
		t.Fatalf("hooks/list: %s", out)
	}
	var events []string
	for _, h := range list.Result.Data[0].Hooks {
		if h.Command != hook || h.TrustStatus != "trusted" {
			t.Errorf("hook %+v is not Opfence's trusted hook", h)
		}
		events = append(events, h.EventName)
	}
	slices.Sort(events)
	if !slices.Equal(events, []string{"permissionRequest", "preToolUse"}) {
		t.Fatalf("hooks for %v", events)
	}
}

// runCodex runs Codex with its own empty home and returns its output. For
// app-server it closes stdin once the reply to request 2 has arrived.
func runCodex(t *testing.T, codex, home, work string, stdin io.Reader, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, codex, args...)
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "CODEX_HOME="+home)
	if stdin == nil {
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("codex %v: %v", args, err)
		}
		return out
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.Copy(in, stdin) }()
	var out []byte
	sc := bufio.NewScanner(pipe)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		out = append(out, sc.Bytes()...)
		out = append(out, '\n')
		if strings.HasPrefix(sc.Text(), `{"id":2,`) {
			break
		}
	}
	_ = in.Close()
	cancel()
	_ = cmd.Wait()
	return out
}

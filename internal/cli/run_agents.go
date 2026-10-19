package cli

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/rakeshnitb23/opfence/internal/launch"
)

// codexProxyVars are the proxy variables the sandbox runtime may set, which
// Codex must pass on to stdio MCP servers.
var codexProxyVars = []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "GRPC_PROXY"}

// codexEnvVars lists the variables Codex passes to stdio MCP servers: the
// proxy variables, those opfence run sets (CA, session) and those holding
// placeholders.
func codexEnvVars(vars map[string]string, changes []launch.EnvChange) []string {
	out := slices.Clone(codexProxyVars)
	for k := range vars {
		out = append(out, k)
	}
	for _, c := range changes {
		out = append(out, c.Var)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// codexArgs reads Codex's MCP servers with `codex mcp list --json` (with
// the user's -c and profile options) and returns the -c options for them
// and for Opfence's hook. Without the server list the hook covers every MCP
// tool; the servers keep Codex's own approval settings and may fail without
// the proxy variables, which the warning says.
func codexArgs(ctx context.Context, w io.Writer, logf func(string, ...any), args, env []string, cwd string, envVars []string, hook string) []string {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	list := append(codexConfigOptions(args[1:]), "mcp", "list", "--json")
	c := exec.CommandContext(ctx, args[0], list...)
	c.Env, c.Dir = env, cwd
	out, err := c.Output()
	var servers []launch.CodexServer
	if err == nil {
		servers, err = launch.ParseCodexServers(out)
	}
	if err != nil {
		logf("codex mcp list --json: %v", err)
		fmt.Fprintf(w, "opfence: could not list Codex's MCP servers (%v); local servers may not reach the proxy, see %s\n", err, "opfence.log")
	}
	extra, skipped := launch.CodexConfig(launch.CodexOptions{Servers: servers, ServersUnknown: err != nil, EnvVars: envVars, HookCommand: hook})
	for _, name := range skipped {
		fmt.Fprintf(w, "opfence: Codex MCP server %q has a name -c cannot address; it keeps Codex's own approvals and may not reach the proxy\n", name)
	}
	return extra
}

// codexConfigOptions picks the options that change which config Codex
// loads (-c, --config, -p, --profile, --enable, --disable) from the
// arguments, up to a "--". Subcommands such as exec take them too.
func codexConfigOptions(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		name, _, inline := strings.Cut(a, "=")
		switch name {
		case "-c", "--config", "-p", "--profile", "--enable", "--disable":
			out = append(out, a)
			if !inline && i+1 < len(args) {
				i++
				out = append(out, args[i])
			}
		}
	}
	return out
}

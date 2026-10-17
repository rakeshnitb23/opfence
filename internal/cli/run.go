package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/rakeshnitb23/opfence/internal/audit"
	"github.com/rakeshnitb23/opfence/internal/launch"
	"github.com/rakeshnitb23/opfence/internal/policy"
)

// exitCodeError makes Main exit with a child's exit code, silently.
type exitCodeError struct{ code int }

func (e exitCodeError) Error() string { return "exit status " + strconv.Itoa(e.code) }

// Environment variables opfence run sets for the child.
const (
	envSession   = "OPFENCE_SESSION"
	envAgentPort = "OPFENCE_AGENT_PROXY_PORT"
)

func newRunCmd(g *globalOptions) *cobra.Command {
	var useSrt, weak bool
	var mode, auditPath string
	cmd := &cobra.Command{
		Use:   "run [--srt | --weak] -- COMMAND [ARGS...]",
		Short: "Run Claude Code, another agent or your own tool behind Opfence",
		Long: `Run starts the Opfence proxy for one session and runs COMMAND behind it.

  opfence run -- claude [ARGS]        Claude Code in its sandbox, with every
                                      connection going through Opfence
  opfence run --srt -- AGENT [ARGS]   any agent in Anthropic's sandbox runtime
  opfence run --weak -- COMMAND       no sandbox: proxy variables only, for
                                      your own tools (a dev server that reads
                                      .env placeholders) or agents that cannot
                                      be sandboxed; they could bypass Opfence

For Claude Code, Opfence passes its sandbox settings with --settings (your
settings files are not changed): the sandbox is required, its proxy ports are
Opfence's, it cannot read Opfence's state folder or the keychain socket, and a
hook decides MCP tool calls. Claude Code itself and its MCP servers run
outside the sandbox; their traffic to APIs in the catalog also goes through
Opfence.

API keys in the environment are replaced with placeholders the proxy swaps
back, so the program never sees a real key. Requests that need approval are
asked in a desktop dialog or with "opfence approve" in another terminal.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kind, err := runKind(args, useSrt, weak, runtime.GOOS)
			if err != nil {
				return err
			}
			stderr := cmd.ErrOrStderr()
			if err := hideEnviron(); err != nil {
				return fmt.Errorf("hiding Opfence's environment from other processes: %w", err)
			}
			stateDir, err := audit.StateDir()
			if err != nil {
				return err
			}
			// The agent owns the terminal; problems during the run go to a file.
			logFile, logf, err := openRunLog(filepath.Join(stateDir, "opfence.log"))
			if err != nil {
				return err
			}
			defer logFile.Close()
			s, err := openSession(g, sessionOptions{auditPath: auditPath, warn: stderr, logf: logf})
			if err != nil {
				return err
			}
			defer s.Close()

			env, extra, changes, err := launch.ProtectEnv(os.Environ(), s.eng.Catalog, s.stored)
			if err != nil {
				return err
			}
			s.extra = extra

			paths, err := runPaths(g, stateDir)
			if err != nil {
				return err
			}
			vars := launch.CAEnv(s.caFiles.CA, s.caFiles.Bundle)
			vars[envSession] = s.id
			var argv []string
			var cleanup func()
			var denyRead []string
			if runtime.GOOS == "linux" {
				denyRead = launch.LinuxSecretSockets(os.Getenv)
			}
			switch kind {
			case "claude", "srt":
				h, so, err := s.listen(listenSpec{via: map[string]string{"claude": "sandbox", "srt": "srt"}[kind], mode: mode, http: "127.0.0.1:0", socks: "127.0.0.1:0"})
				if err != nil {
					return err
				}
				if kind == "claude" {
					// Claude Code itself, its MCP servers and hooks run outside
					// the sandbox and could connect directly, so this listener
					// tunnels other hosts; catalog APIs are still decided.
					agent, _, err := s.listen(listenSpec{via: "agent", mode: "open", privateTunnels: true, http: "127.0.0.1:0"})
					if err != nil {
						return err
					}
					for k, v := range launch.ProxyEnv(agent) {
						vars[k] = v
					}
					vars[envAgentPort] = strconv.Itoa(launch.Port(agent))
					pinned := map[string]string{}
					for k, v := range vars {
						pinned[k] = v
					}
					if paths.ConfigFile != "" {
						pinned["OPFENCE_CONFIG"] = paths.ConfigFile
					}
					settings, err := launch.ClaudeSettings(launch.ClaudeOptions{
						HTTPPort: launch.Port(h), SOCKSPort: launch.Port(so), GOOS: runtime.GOOS,
						Paths: paths, DenyRead: denyRead, HookArgs: g.hookArgs(paths.ConfigFile), Env: pinned,
					})
					if err != nil {
						return err
					}
					argv = append([]string{args[0], "--settings", string(settings)}, args[1:]...)
				} else {
					srtPath, err := exec.LookPath("srt")
					if err != nil {
						return errors.New("srt is not installed; install Anthropic's sandbox runtime with: npm install -g @anthropic-ai/sandbox-runtime")
					}
					cwd, err := os.Getwd()
					if err != nil {
						return err
					}
					settings, err := launch.SrtSettings(launch.SrtOptions{
						HTTPPort: launch.Port(h), SOCKSPort: launch.Port(so), GOOS: runtime.GOOS,
						Paths: paths, DenyRead: denyRead, AllowWrite: []string{cwd, os.TempDir()},
					})
					if err != nil {
						return err
					}
					file := filepath.Join(paths.CertDir, "srt-"+s.id+".json")
					if err := os.WriteFile(file, settings, 0o644); err != nil {
						return err
					}
					cleanup = func() { os.Remove(file) }
					argv = append([]string{srtPath, "--settings", file, "--"}, args...)
				}
			case "weak":
				h, _, err := s.listen(listenSpec{via: "weak", mode: "open", privateTunnels: true, http: "127.0.0.1:0"})
				if err != nil {
					return err
				}
				for k, v := range launch.ProxyEnv(h) {
					vars[k] = v
				}
				argv = args
			}
			if cleanup != nil {
				defer cleanup()
			}
			env = launch.SetEnv(env, vars, runtime.GOOS == "windows")

			effMode := mode
			if effMode == "" {
				effMode = s.eng.Policy.Mode
			}
			printRunBanner(stderr, s, kind, effMode, changes, logFile.Name())
			if kind == "claude" {
				claudeWarnings(stderr, args[0])
			}
			code, err := runChild(cmd.Context(), argv, env)
			if err != nil {
				return err
			}
			if code != 0 {
				return exitCodeError{code}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&useSrt, "srt", false, "run the command in Anthropic's sandbox runtime (srt)")
	cmd.Flags().BoolVar(&weak, "weak", false, "run without a sandbox (proxy variables only)")
	cmd.Flags().StringVar(&mode, "mode", "", "strict or open for the sandbox (default from your policy, strict)")
	cmd.Flags().StringVar(&auditPath, "audit", "", "audit log file (default ~/.local/state/opfence/audit.jsonl)")
	return cmd
}

// runKind decides how COMMAND runs: claude (Claude Code's own sandbox), srt
// or weak.
func runKind(args []string, useSrt, weak bool, goos string) (string, error) {
	name := strings.TrimSuffix(filepath.Base(args[0]), ".exe")
	switch {
	case useSrt && weak:
		return "", errors.New("choose one of --srt and --weak")
	case useSrt:
		if goos == "windows" {
			return "", errors.New("the sandbox runtime does not run on Windows; use --weak")
		}
		return "srt", nil
	case weak:
		return "weak", nil
	case name == "claude":
		if goos == "windows" {
			return "", errors.New("the sandbox Claude Code uses does not run on native Windows; use WSL2, or opfence run --weak -- claude (no sandbox: Claude could bypass Opfence)")
		}
		for _, a := range args[1:] {
			if a == "--settings" || strings.HasPrefix(a, "--settings=") {
				return "", errors.New("opfence run passes its own --settings to Claude Code; put your settings in ~/.claude/settings.json instead")
			}
		}
		return "claude", nil
	}
	return "", fmt.Errorf(`%s is not Claude Code, so Opfence cannot set up its sandbox. Use
  opfence run --srt -- %s ...    to run it in Anthropic's sandbox runtime, or
  opfence run --weak -- %s ...   to run it without a sandbox (it could bypass Opfence)`, name, name, name)
}

// runPaths are the files the sandbox is kept away from.
func runPaths(g *globalOptions, stateDir string) (launch.Paths, error) {
	certDir, err := launch.CertDir()
	if err != nil {
		return launch.Paths{}, err
	}
	cfg := g.userConfig
	if cfg == "" {
		cfg = policy.UserConfigPath()
	}
	if cfg != "" {
		if cfg, err = filepath.Abs(cfg); err != nil {
			return launch.Paths{}, err
		}
	}
	exe, err := os.Executable()
	if err == nil {
		if r, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			exe = r
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return launch.Paths{}, err
	}
	return launch.Paths{StateDir: stateDir, ConfigFile: cfg, CertDir: certDir, Executable: exe, ProjectDir: cwd}, nil
}

// hookArgs passes the catalog and policy files on to the hook, so it decides
// with the same rules as the proxy. The user config is always passed by its
// absolute path: left to the hook, it would be found through environment
// variables a project's Claude Code settings can set.
func (g *globalOptions) hookArgs(userConfig string) []string {
	var out []string
	for _, f := range []struct{ flag, path string }{{"--catalog", g.catalogDir}, {"--user-config", userConfig}, {"--policy", g.policyFile}} {
		if f.path == "" {
			continue
		}
		if p, err := filepath.Abs(f.path); err == nil {
			out = append(out, f.flag, p)
		}
	}
	return out
}

func openRunLog(path string) (*os.File, func(string, ...any), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, err
	}
	var mu sync.Mutex
	return f, func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
	}, nil
}

func printRunBanner(w io.Writer, s *session, kind, mode string, changes []launch.EnvChange, logPath string) {
	how := map[string]string{
		"claude": "Claude Code's sandbox",
		"srt":    "the sandbox runtime",
		"weak":   "no sandbox (weak mode: the program could bypass Opfence)",
	}[kind]
	fmt.Fprintf(w, "Opfence session %s: %s mode, %s.\n", s.id, mode, how)
	fmt.Fprintf(w, "  Approvals: %s\n", s.approvals)
	fmt.Fprintf(w, "  Credentials: %d; audit log %s; problems go to %s\n", s.credentials(), s.audit.Path(), logPath)
	if s.upstream != nil {
		fmt.Fprintf(w, "  Upstream proxy: %s (from HTTPS_PROXY; NO_PROXY hosts are reached directly)\n", s.upstream.URL.Redacted())
	}
	for _, c := range changes {
		switch c.Action {
		case "placeholder":
			fmt.Fprintf(w, "  %s: placeholder for your stored %s key\n", c.Var, c.Provider)
		case "session":
			fmt.Fprintf(w, "  %s: placeholder for this session (the real %s key stays with Opfence)\n", c.Var, c.Provider)
		}
	}
}

// claudeWarnings reports Claude Code versions and settings that weaken the
// session. They are warnings: the user may know better.
func claudeWarnings(w io.Writer, claude string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, claude, "--version").Output(); err == nil {
		if v, ok := launch.ParseVersion(string(out)); ok && launch.Older(v, launch.MinClaudeVersion) {
			fmt.Fprintf(w, "  warning: Claude Code %s is older than %s; update it so a repository's settings cannot loosen the sandbox\n",
				launch.FormatVersion(v), launch.FormatVersion(launch.MinClaudeVersion))
		}
	}
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	for _, m := range launch.ClaudeSettingsWarnings(launch.UserSettingsPath(os.Getenv, home), launch.ManagedSettingsPath(runtime.GOOS), launch.ProjectSettingsFiles(cwd)...) {
		fmt.Fprintln(w, "  warning:", m)
	}
}

// runChild runs argv in the foreground and returns its exit code. Ctrl-C
// reaches the child from the terminal directly (it may want to handle it,
// as Claude Code does), so Opfence ignores it; other termination signals are
// passed on.
func runChild(ctx context.Context, argv []string, env []string) (int, error) {
	c := exec.Command(argv[0], argv[1:]...)
	c.Env = env
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := c.Start(); err != nil {
		return 0, fmt.Errorf("starting %s: %w", argv[0], err)
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-sigs:
				if sig != os.Interrupt {
					_ = c.Process.Signal(sig)
				}
			case <-ctx.Done():
				_ = c.Process.Signal(syscall.SIGTERM)
				return
			case <-done:
				return
			}
		}
	}()
	err := c.Wait()
	close(done)
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ee.ExitCode() < 0 {
			return 1, nil // killed by a signal
		}
		return ee.ExitCode(), nil
	}
	return 0, err
}

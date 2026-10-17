package approve

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Desktop shows a native dialog: osascript on macOS, zenity or kdialog on
// Linux desktops. Text reaches the dialog as an argument, never as script
// source, so a crafted card cannot run commands.
type Desktop struct {
	tool string // osascript, zenity or kdialog
	// run executes the dialog; tests replace it. It returns stdout and the
	// exit code (-1 when the program could not run or was killed).
	run func(ctx context.Context, name string, args ...string) (string, int)
}

// ScopeOffer is the time-limited grant dialogs offer for ask decisions.
const ScopeOffer = 10 * time.Minute

// NewDesktop returns the desktop channel, or nil when no dialog tool is
// available (no display, or none of the tools installed).
func NewDesktop() *Desktop {
	tool := ""
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("osascript"); err == nil {
			tool = "osascript"
		}
	case "linux":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return nil
		}
		for _, t := range []string{"zenity", "kdialog"} {
			if _, err := exec.LookPath(t); err == nil {
				tool = t
				break
			}
		}
	}
	if tool == "" {
		return nil
	}
	return &Desktop{tool: tool, run: runCommand}
}

func runCommand(ctx context.Context, name string, args ...string) (string, int) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err == nil {
		return string(out), 0
	}
	if ee, ok := err.(*exec.ExitError); ok && ctx.Err() == nil {
		return string(out), ee.ExitCode()
	}
	return string(out), -1
}

// Name implements Channel.
func (*Desktop) Name() string { return "desktop" }

// Show implements Channel. A wrong confirmation text shows the dialog again
// until the request is answered or expires.
func (d *Desktop) Show(ctx context.Context, v View, b *Broker) {
	note := ""
	for ctx.Err() == nil {
		secs := int(time.Until(v.Expires).Seconds())
		if secs < 1 {
			return
		}
		a, ok := d.ask(ctx, v, note, secs)
		if !ok || ctx.Err() != nil {
			return
		}
		a.ID, a.Channel = v.ID, "desktop"
		err := b.Answer(a)
		if err == nil || err == ErrUnknown {
			return
		}
		note = "That did not match. "
	}
}

// dialogText is the message every dialog shows.
func dialogText(v View, note string) string {
	var s strings.Builder
	s.WriteString("Opfence: an agent wants to\n\n")
	for _, c := range v.Cards {
		s.WriteString(c + "\n")
	}
	fmt.Fprintf(&s, "\n%s · %s · %s %s%s\nRequest %s", strings.Join(uniq(v.Classes), ", "), v.Environment, v.Method, v.Host, v.Path, v.Hash)
	if n := ViaNote(v.Via); n != "" {
		s.WriteString("\n" + n)
	}
	if v.ConfirmText != "" {
		fmt.Fprintf(&s, "\n\n%sType %s to confirm.", note, v.ConfirmText)
	}
	return s.String()
}

func uniq(xs []string) []string {
	var out []string
	for _, x := range xs {
		if len(out) == 0 || !contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

const scopeLabel = "Approve for 10 minutes"

// ask runs one dialog; ok is false when it was closed without an answer.
func (d *Desktop) ask(ctx context.Context, v View, note string, secs int) (Answer, bool) {
	text := dialogText(v, note)
	confirm := v.ConfirmText != ""
	switch d.tool {
	case "osascript":
		var script []string
		switch {
		case confirm:
			script = []string{`on run argv`, `display dialog (item 1 of argv) with title "Opfence" default answer "" buttons {"Deny", "Confirm"} default button "Deny" cancel button "Deny" with icon caution giving up after (item 2 of argv as integer)`, `end run`}
		case v.Scopable:
			script = []string{`on run argv`, `display dialog (item 1 of argv) with title "Opfence" buttons {"Deny", "` + scopeLabel + `", "Approve"} default button "Deny" cancel button "Deny" with icon caution giving up after (item 2 of argv as integer)`, `end run`}
		default:
			script = []string{`on run argv`, `display dialog (item 1 of argv) with title "Opfence" buttons {"Deny", "Approve"} default button "Deny" cancel button "Deny" with icon caution giving up after (item 2 of argv as integer)`, `end run`}
		}
		var args []string
		for _, l := range script {
			args = append(args, "-e", l)
		}
		out, code := d.run(ctx, "osascript", append(args, "--", text, fmt.Sprint(secs))...)
		switch {
		case code == 1:
			return Answer{Approve: false}, true // the Deny (cancel) button
		case code != 0 || strings.Contains(out, "gave up:true"):
			return Answer{}, false
		case confirm:
			typed := ""
			if i := strings.Index(out, "text returned:"); i >= 0 {
				typed = strings.TrimRight(out[i+len("text returned:"):], "\n")
			}
			return Answer{Approve: strings.Contains(out, "button returned:Confirm"), Typed: typed}, true
		case strings.Contains(out, "button returned:"+scopeLabel):
			return Answer{Approve: true, Scope: ScopeOffer}, true
		default:
			return Answer{Approve: strings.Contains(out, "button returned:Approve")}, true
		}
	case "zenity":
		text = pangoEscape(text)
		if confirm {
			out, code := d.run(ctx, "zenity", "--entry", "--title=Opfence", "--text="+text, "--ok-label=Confirm", "--cancel-label=Deny", fmt.Sprintf("--timeout=%d", secs))
			switch code {
			case 0:
				return Answer{Approve: true, Typed: strings.TrimRight(out, "\n")}, true
			case 1:
				return Answer{}, true
			}
			return Answer{}, false
		}
		args := []string{"--question", "--title=Opfence", "--text=" + text, "--ok-label=Approve", "--cancel-label=Deny", "--default-cancel", fmt.Sprintf("--timeout=%d", secs)}
		if v.Scopable {
			args = append(args, "--extra-button="+scopeLabel)
		}
		out, code := d.run(ctx, "zenity", args...)
		switch {
		case code == 0:
			return Answer{Approve: true}, true
		case code == 1 && strings.TrimSpace(out) == scopeLabel:
			return Answer{Approve: true, Scope: ScopeOffer}, true
		case code == 1:
			return Answer{}, true
		}
		return Answer{}, false
	case "kdialog":
		if confirm {
			out, code := d.run(ctx, "kdialog", "--title", "Opfence", "--inputbox", text)
			switch code {
			case 0:
				return Answer{Approve: true, Typed: strings.TrimRight(out, "\n")}, true
			case 1:
				return Answer{}, true
			}
			return Answer{}, false
		}
		_, code := d.run(ctx, "kdialog", "--title", "Opfence", "--yes-label", "Approve", "--no-label", "Deny", "--warningyesno", text)
		switch code {
		case 0:
			return Answer{Approve: true}, true
		case 1:
			return Answer{}, true
		}
	}
	return Answer{}, false
}

// pangoEscape escapes text for zenity, which reads --text as Pango markup.
func pangoEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

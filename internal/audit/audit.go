// Package audit is the runner's append-only, hash-chained audit log
// (docs/ARCHITECTURE.md §8.6). Each line is one JSON entry whose prev field
// is the SHA-256 of the line before it, so editing, inserting or deleting a
// line breaks the chain. Truncating lines from the end cannot be detected
// from the file alone.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one audit line. It never holds bodies, query strings or secrets.
type Entry struct {
	Time    time.Time `json:"time"`
	Session string    `json:"session"`
	// Via names the listener: sandbox, agent, srt or weak (empty for
	// opfence proxy).
	Via string `json:"via,omitempty"`
	// Event is request, tunnel or refused.
	Event  string `json:"event"`
	Host   string `json:"host"`
	Port   string `json:"port,omitempty"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"` // without the query string
	// Operations has one item per decoded operation.
	Operations []Operation `json:"operations,omitempty"`
	Decision   string      `json:"decision,omitempty"`
	// Outcome is forwarded, blocked, approved, tunneled, refused or error.
	Outcome  string `json:"outcome"`
	Reason   string `json:"reason,omitempty"`
	Approver string `json:"approver,omitempty"`
	// Credentials names the secrets injected (provider/name), never values.
	Credentials []string `json:"credentials,omitempty"`
	// Minted names the credentials a response created, which Opfence now
	// holds for the session (provider/name), never values.
	Minted []string `json:"minted,omitempty"`
	Hash   string   `json:"hash,omitempty"` // request hash approvals bind to
	Status int      `json:"status,omitempty"`
	Prev   string   `json:"prev"`
}

// Operation is the verdict on one operation of a request.
type Operation struct {
	Rule        string `json:"rule,omitempty"`
	Class       string `json:"class"`
	Environment string `json:"environment"`
	Decision    string `json:"decision"`
	Card        string `json:"card"`
}

// Log appends entries to one file. It is safe for concurrent use, and an
// advisory file lock keeps the chain intact when several Opfence processes
// share the file.
type Log struct {
	path string
	mu   sync.Mutex
}

// DefaultPath is $XDG_STATE_HOME/opfence/audit.jsonl, falling back to
// ~/.local/state/opfence/audit.jsonl.
func DefaultPath() (string, error) {
	dir, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "audit.jsonl"), nil
}

// StateDir is Opfence's state folder.
func StateDir() (string, error) {
	if d := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(d) {
		return filepath.Join(d, "opfence"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "opfence"), nil
}

// Open prepares the log file, creating it (0600, in a 0700 folder) if needed.
func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Log{path: path}, f.Close()
}

// Path returns the log file's path.
func (l *Log) Path() string { return l.path }

// Record appends e, setting its Prev from the current last line.
func (l *Log) Record(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := lock(f); err != nil {
		return err
	}
	defer unlock(f)
	last, err := lastLine(f)
	if err != nil {
		return err
	}
	e.Prev = ""
	if last != nil {
		e.Prev = hashLine(last)
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Time = e.Time.UTC()
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = f.Write(append(line, '\n'))
	return err
}

func hashLine(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

// lastLine returns the last complete line of f without its newline, or nil
// for an empty file.
func lastLine(f *os.File) ([]byte, error) {
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil || size == 0 {
		return nil, err
	}
	const chunk = 4096
	var tail []byte
	for off := size; off > 0; {
		n := int64(chunk)
		if off < n {
			n = off
		}
		off -= n
		buf := make([]byte, n)
		if _, err := f.ReadAt(buf, off); err != nil {
			return nil, err
		}
		tail = append(buf, tail...)
		body := bytes.TrimSuffix(tail, []byte("\n"))
		if i := bytes.LastIndexByte(body, '\n'); i >= 0 {
			return body[i+1:], nil
		}
		if off == 0 {
			return body, nil
		}
	}
	return nil, nil
}

// MaxLine bounds one audit line when reading the log back.
const MaxLine = 1 << 20

// Read decodes every entry, in order.
func Read(r io.Reader) ([]Entry, error) {
	var out []Entry
	err := scan(r, func(n int, line []byte) error {
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
		out = append(out, e)
		return nil
	})
	return out, err
}

// ErrBroken reports a break in the hash chain.
var ErrBroken = errors.New("audit log chain is broken")

// Verify checks the chain and returns the number of entries. The first
// entry must have an empty prev, so deleting lines from the start is
// detected too.
func Verify(r io.Reader) (int, error) {
	prev, count := "", 0
	err := scan(r, func(n int, line []byte) error {
		var e struct {
			Prev *string `json:"prev"`
		}
		if err := json.Unmarshal(line, &e); err != nil || e.Prev == nil {
			return fmt.Errorf("%w at line %d: not an audit entry", ErrBroken, n)
		}
		if *e.Prev != prev {
			return fmt.Errorf("%w at line %d: it does not follow line %d (edited, inserted or deleted lines)", ErrBroken, n, n-1)
		}
		prev, count = hashLine(line), n
		return nil
	})
	return count, err
}

func scan(r io.Reader, fn func(n int, line []byte) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), MaxLine)
	n := 0
	for sc.Scan() {
		n++
		if err := fn(n, sc.Bytes()); err != nil {
			return err
		}
	}
	return sc.Err()
}

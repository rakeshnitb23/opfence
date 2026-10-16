package approve

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"time"
)

// The control socket is a 0600 Unix socket in Opfence's state folder that
// `opfence approve` talks to with one JSON object per line. The sandbox is
// denied that folder (stage 9), so the agent cannot answer its own requests.

type controlRequest struct {
	Op     string  `json:"op"` // list, answer or watch
	Answer *Answer `json:"answer,omitempty"`
}

type controlResponse struct {
	Pending []View `json:"pending,omitempty"`
	OK      bool   `json:"ok,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Control is the control-socket channel. It shows nothing itself: clients
// list and watch pending requests over the socket.
type Control struct{ l net.Listener }

// Name implements Channel.
func (*Control) Name() string { return "cli" }

// Show implements Channel; requests reach clients through List and Watch.
func (*Control) Show(context.Context, View, *Broker) {}

// ListenControl opens the control socket at path. A stale socket left by a
// crashed process is replaced; a live one means another proxy is running.
func ListenControl(path string) (*Control, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("another Opfence proxy is already using %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return &Control{l: l}, nil
}

// Serve answers clients until the listener is closed.
func (c *Control) Serve(b *Broker) error {
	for {
		conn, err := c.l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go serveControlConn(conn, b)
	}
}

// Close stops the listener and removes the socket.
func (c *Control) Close() error { return c.l.Close() }

func serveControlConn(conn net.Conn, b *Broker) {
	defer conn.Close()
	dec := json.NewDecoder(bufio.NewReader(conn))
	enc := json.NewEncoder(conn)
	for {
		var req controlRequest
		if err := dec.Decode(&req); err != nil {
			return
		}
		switch req.Op {
		case "list":
			_ = enc.Encode(controlResponse{Pending: b.List(), OK: true})
		case "answer":
			if req.Answer == nil {
				_ = enc.Encode(controlResponse{Error: "no answer"})
				continue
			}
			a := *req.Answer
			a.Channel = "cli"
			if err := b.Answer(a); err != nil {
				_ = enc.Encode(controlResponse{Error: err.Error()})
			} else {
				_ = enc.Encode(controlResponse{OK: true})
			}
		case "watch":
			ch, cancel := b.Watch()
			defer cancel()
			if enc.Encode(controlResponse{Pending: b.List(), OK: true}) != nil {
				return
			}
			// The client sends nothing more; a read error means it left.
			gone := make(chan struct{})
			go func() { _, _ = conn.Read(make([]byte, 1)); close(gone) }()
			for {
				select {
				case v := <-ch:
					if enc.Encode(controlResponse{Pending: []View{v}, OK: true}) != nil {
						return
					}
				case <-gone:
					return
				}
			}
		default:
			_ = enc.Encode(controlResponse{Error: "unknown op " + req.Op})
		}
	}
}

// Client talks to a running proxy's control socket.
type Client struct {
	conn net.Conn
	dec  *json.Decoder
	enc  *json.Encoder
}

// Dial connects to the control socket.
func Dial(path string) (*Client, error) {
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("no Opfence proxy is running (control socket %s): %w", path, err)
	}
	return &Client{conn: conn, dec: json.NewDecoder(bufio.NewReader(conn)), enc: json.NewEncoder(conn)}, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) call(req controlRequest) (controlResponse, error) {
	var resp controlResponse
	if err := c.enc.Encode(req); err != nil {
		return resp, err
	}
	if err := c.dec.Decode(&resp); err != nil {
		return resp, err
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// List returns the pending requests.
func (c *Client) List() ([]View, error) {
	resp, err := c.call(controlRequest{Op: "list"})
	return resp.Pending, err
}

// Answer sends an answer.
func (c *Client) Answer(a Answer) error {
	_, err := c.call(controlRequest{Op: "answer", Answer: &a})
	return err
}

// Watch calls fn with the pending requests now and with each new one, until
// fn returns false or the connection ends. Use a separate Client for
// answers while watching.
func (c *Client) Watch(fn func(View) bool) error {
	if err := c.enc.Encode(controlRequest{Op: "watch"}); err != nil {
		return err
	}
	for {
		var resp controlResponse
		if err := c.dec.Decode(&resp); err != nil {
			return err
		}
		for _, v := range resp.Pending {
			if !fn(v) {
				return nil
			}
		}
	}
}

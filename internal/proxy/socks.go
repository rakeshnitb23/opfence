package proxy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

// SOCKS5 (RFC 1928), CONNECT only, no authentication: the listener is on
// loopback for one user's agent, like Claude Code's own sandbox proxy.
const (
	socksVersion       = 5
	socksCmdConnect    = 1
	socksAtypIPv4      = 1
	socksAtypDomain    = 3
	socksAtypIPv6      = 4
	socksSucceeded     = 0
	socksNotAllowed    = 2
	socksCmdNotSupport = 7
	socksAtypNotSupp   = 8
)

func (s *Server) serveSOCKSConn(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(helloTimeout))
	br := bufio.NewReader(c)
	host, port, err := socksHandshake(br, c)
	if err != nil {
		_ = c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	reply := func(code byte) error {
		_, err := c.Write([]byte{socksVersion, code, 0, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
		return err
	}
	pc := &prefixConn{Conn: c, r: io.MultiReader(br, c)}
	s.routeTunnel(pc, host, port, handshake{
		accept: func() error { return reply(socksSucceeded) },
		refuse: func(string) error { return reply(socksNotAllowed) },
	})
}

// socksHandshake reads the greeting and the request, answering the method
// selection itself, and returns the requested destination.
func socksHandshake(br *bufio.Reader, w io.Writer) (host, port string, err error) {
	var head [2]byte
	if _, err = io.ReadFull(br, head[:]); err != nil {
		return "", "", err
	}
	if head[0] != socksVersion {
		return "", "", errors.New("not SOCKS5")
	}
	methods := make([]byte, head[1])
	if _, err = io.ReadFull(br, methods); err != nil {
		return "", "", err
	}
	noAuth := false
	for _, m := range methods {
		noAuth = noAuth || m == 0
	}
	if !noAuth {
		_, _ = w.Write([]byte{socksVersion, 0xff})
		return "", "", errors.New("client offers no supported method")
	}
	if _, err = w.Write([]byte{socksVersion, 0}); err != nil {
		return "", "", err
	}
	var req [4]byte
	if _, err = io.ReadFull(br, req[:]); err != nil {
		return "", "", err
	}
	fail := func(code byte, msg string) (string, string, error) {
		_, _ = w.Write([]byte{socksVersion, code, 0, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
		return "", "", errors.New(msg)
	}
	if req[0] != socksVersion {
		return "", "", errors.New("not SOCKS5")
	}
	if req[1] != socksCmdConnect {
		return fail(socksCmdNotSupport, "only CONNECT is supported")
	}
	switch req[3] {
	case socksAtypIPv4, socksAtypIPv6:
		n := 4
		if req[3] == socksAtypIPv6 {
			n = 16
		}
		ip := make([]byte, n)
		if _, err = io.ReadFull(br, ip); err != nil {
			return "", "", err
		}
		host = net.IP(ip).String()
	case socksAtypDomain:
		l, err := br.ReadByte()
		if err != nil {
			return "", "", err
		}
		name := make([]byte, l)
		if _, err = io.ReadFull(br, name); err != nil {
			return "", "", err
		}
		host, _ = splitTarget(string(name))
		if host == "" {
			return fail(socksAtypNotSupp, "empty host name")
		}
	default:
		return fail(socksAtypNotSupp, "unsupported address type")
	}
	var p [2]byte
	if _, err = io.ReadFull(br, p[:]); err != nil {
		return "", "", err
	}
	return host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:]))), nil
}

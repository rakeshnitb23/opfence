package proxy

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func FuzzSOCKSHandshake(f *testing.F) {
	f.Add([]byte{5, 1, 0, 5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 187})
	f.Add([]byte{5, 1, 0, 5, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80})
	f.Add([]byte{5, 1, 2})
	f.Fuzz(func(t *testing.T, data []byte) {
		host, port, err := socksHandshake(bufio.NewReader(bytes.NewReader(data)), io.Discard)
		if err == nil && (port == "" || host == "") {
			t.Fatalf("accepted %q:%q from %v", host, port, data)
		}
	})
}

func FuzzPeekServerName(f *testing.F) {
	f.Add([]byte{0x16, 3, 1, 0, 5, 1, 0, 0, 1, 0})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		a, b := net.Pipe()
		go func() { _, _ = a.Write(data); a.Close() }()
		_ = b.SetDeadline(time.Now().Add(time.Second))
		sni, peeked, err := peekServerName(b)
		if err == nil && !bytes.HasPrefix(data, peeked) {
			t.Fatalf("peeked bytes %v are not a prefix of the input (sni %q)", peeked, sni)
		}
		b.Close()
	})
}

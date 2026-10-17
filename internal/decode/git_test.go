package decode

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/request"
)

var gitHints = Hints{Git: true}

func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

const (
	zeroID = "0000000000000000000000000000000000000000"
	idA    = "4f2a9c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39"
	idB    = "9c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a394f2a"
)

func gitReq(method, target string, body []byte) *request.Request {
	path, query, _ := strings.Cut(target, "?")
	r := &request.Request{Method: method, Host: "github.com", Path: path, Header: http.Header{}, Body: body}
	r.Query, _ = url.ParseQuery(query)
	return r
}

func TestGitDecode(t *testing.T) {
	type want struct{ service, action, ref, err string }
	push := func(lines ...string) []byte {
		var b strings.Builder
		for i, l := range lines {
			if i == 0 {
				l += "\x00 report-status side-band-64k quiet object-format=sha1 agent=git/2.47.0"
			}
			b.WriteString(pkt(l + "\n"))
		}
		b.WriteString("0000PACK\x00\x00\x00\x02")
		return []byte(b.String())
	}
	cases := []struct {
		name   string
		r      *request.Request
		expect []want
	}{
		{"fetch refs", gitReq("GET", "/acme/shop.git/info/refs?service=git-upload-pack", nil), []want{{GitUploadPack, GitFetch, "", ""}}},
		{"dumb refs", gitReq("GET", "/acme/shop/info/refs", nil), []want{{GitUploadPack, GitFetch, "", ""}}},
		{"fetch", gitReq("POST", "/acme/shop.git/git-upload-pack", []byte(pkt("command=fetch\n")+"0000")), []want{{GitUploadPack, GitFetch, "", ""}}},
		{"push refs", gitReq("GET", "/acme/shop.git/info/refs?service=git-receive-pack", nil), []want{{GitReceivePack, GitListRefs, "", ""}}},
		{"probe", gitReq("POST", "/acme/shop.git/git-receive-pack", []byte("0000")), []want{{GitReceivePack, GitListRefs, "", ""}}},
		{"push three", gitReq("POST", "/acme/shop.git/git-receive-pack", push(
			zeroID+" "+idA+" refs/heads/new", idA+" "+idB+" refs/heads/main", idA+" "+zeroID+" refs/tags/old")),
			[]want{{GitReceivePack, GitCreate, "refs/heads/new", ""}, {GitReceivePack, GitUpdate, "refs/heads/main", ""}, {GitReceivePack, GitDelete, "refs/tags/old", ""}}},
		{"shallow", gitReq("POST", "/acme/shop/git-receive-pack", []byte(pkt("shallow "+idA+"\n")+pkt(idA+" "+idB+" refs/heads/x\n")+"0000")),
			[]want{{GitReceivePack, GitUpdate, "refs/heads/x", ""}}},
		{"sha256", gitReq("POST", "/acme/shop/git-receive-pack", []byte(pkt(strings.Repeat("a", 64)+" "+strings.Repeat("b", 64)+" refs/heads/x\n")+"0000")),
			[]want{{GitReceivePack, GitUpdate, "refs/heads/x", ""}}},
		{"push GET", gitReq("GET", "/acme/shop/git-receive-pack", nil), []want{{"", "", "", "must be a POST"}}},
		{"refs POST", gitReq("POST", "/acme/shop/info/refs?service=git-receive-pack", nil), []want{{"", "", "", "must be a GET"}}},
		{"bad service", gitReq("GET", "/acme/shop/info/refs?service=git-upload-archive", nil), []want{{"", "", "", "unknown git service"}}},
		{"no flush", gitReq("POST", "/a/b/git-receive-pack", []byte(pkt(idA+" "+idB+" refs/heads/x\n"))), []want{{GitReceivePack, "", "", "before their flush"}}},
		{"short pkt", gitReq("POST", "/a/b/git-receive-pack", []byte("0066"+idA)), []want{{GitReceivePack, "", "", "before their flush"}}},
		{"bad length", gitReq("POST", "/a/b/git-receive-pack", []byte("zz00")), []want{{GitReceivePack, "", "", "malformed pkt-line"}}},
		{"delim", gitReq("POST", "/a/b/git-receive-pack", []byte("0001")), []want{{GitReceivePack, "", "", "unexpected pkt-line length"}}},
		{"bad id", gitReq("POST", "/a/b/git-receive-pack", []byte(pkt("xyz "+idB+" refs/heads/x\n")+"0000")), []want{{GitReceivePack, "", "", "malformed object id"}}},
		{"two zeros", gitReq("POST", "/a/b/git-receive-pack", []byte(pkt(zeroID+" "+zeroID+" refs/heads/x\n")+"0000")), []want{{GitReceivePack, "", "", "two zero ids"}}},
		{"bad ref", gitReq("POST", "/a/b/git-receive-pack", []byte(pkt(idA+" "+idB+" HEAD\n")+"0000")), []want{{GitReceivePack, "", "", "invalid ref name"}}},
		{"dotdot ref", gitReq("POST", "/a/b/git-receive-pack", []byte(pkt(idA+" "+idB+" refs/heads/../x\n")+"0000")), []want{{GitReceivePack, "", "", "invalid ref name"}}},
		{"signed", gitReq("POST", "/a/b/git-receive-pack", []byte(pkt("push-cert\x00report-status\n")+"0000")), []want{{GitReceivePack, "", "", "signed pushes"}}},
		{"lfs download", gitReq("POST", "/a/b.git/info/lfs/objects/batch", []byte(`{"operation":"download","objects":[]}`)), []want{{GitLFS, LFSDownload, "", ""}}},
		{"lfs upload", gitReq("POST", "/a/b.git/info/lfs/objects/batch", []byte(`{"operation":"upload","objects":[]}`)), []want{{GitLFS, LFSUpload, "", ""}}},
		{"lfs bad op", gitReq("POST", "/a/b.git/info/lfs/objects/batch", []byte(`{"operation":"delete"}`)), []want{{GitLFS, "", "", "unknown LFS batch operation"}}},
		{"lfs locks", gitReq("GET", "/a/b.git/info/lfs/locks", nil), []want{{GitLFS, LFSListLocks, "", ""}}},
		{"lfs verify", gitReq("POST", "/a/b.git/info/lfs/locks/verify", []byte(`{}`)), []want{{GitLFS, LFSListLocks, "", ""}}},
		{"lfs lock", gitReq("POST", "/a/b.git/info/lfs/locks", []byte(`{"path":"a.psd"}`)), []want{{GitLFS, LFSLock, "", ""}}},
		{"lfs unlock", gitReq("POST", "/a/b.git/info/lfs/locks/7/unlock", []byte(`{}`)), []want{{GitLFS, LFSUnlock, "", ""}}},
		{"lfs other", gitReq("DELETE", "/a/b.git/info/lfs/locks/7", nil), []want{{GitLFS, "", "", "unknown Git LFS request"}}},
	}
	for _, c := range cases {
		ops := Decode(c.r, gitHints)
		if len(ops) != len(c.expect) {
			t.Errorf("%s: %d ops, want %d: %+v", c.name, len(ops), len(c.expect), ops)
			continue
		}
		for i, w := range c.expect {
			o := ops[i]
			ref, _ := o.Args["ref"].(string)
			if o.Protocol != Git || o.Service != w.service || o.Action != w.action || ref != w.ref || !strings.Contains(o.Error, w.err) || (w.err == "") != (o.Error == "") {
				t.Errorf("%s[%d]: %+v, want %+v", c.name, i, o, w)
			}
			if o.Args["owner"] == nil || o.Args["repo"] == nil || strings.HasSuffix(o.Args["repo"].(string), ".git") {
				t.Errorf("%s[%d]: args %v", c.name, i, o.Args)
			}
		}
	}
}

func TestGitPaths(t *testing.T) {
	// Only repository paths on a git host are git; everything else is REST.
	for path, want := range map[string]bool{
		"/a/b/git-receive-pack":       true,
		"/a/b.git/info/refs":          true,
		"/a/b/info/lfs/objects/batch": true,
		"/a/b/git-receive-pack/x":     false,
		"/a/git-receive-pack":         false,
		"/a/b/c/git-receive-pack":     false,
		"/a/b/info/refs/x":            false,
		"/repos/a/b/git/refs":         false,
		"/a/b/git%2Dreceive-pack":     true,
		"/a/b/./git-receive-pack":     true,
	} {
		if got := isGitPath(path); got != want {
			t.Errorf("isGitPath(%q) = %v", path, got)
		}
	}
	r := gitReq("POST", "/a/b/git-receive-pack", []byte("0000"))
	if ops := Decode(r, Hints{}); ops[0].Protocol != REST {
		t.Errorf("git decoded on a host without the git hint: %+v", ops[0])
	}
}

// A push whose pack is larger than MaxBody is decoded from the body's first
// bytes; a compressed one that large is not.
func TestGitPushLargerThanMaxBody(t *testing.T) {
	body := []byte(pkt(idA+" "+idB+" refs/heads/main\n") + "0000PACK" + strings.Repeat("x", request.MaxBody))
	r, _, err := request.ParseFixture([]byte("POST /a/b/git-receive-pack HTTP/1.1\nHost: github.com\n\n" + string(body)))
	if err != nil {
		t.Fatal(err)
	}
	if r.BodyErr == nil || len(r.Prefix) != request.MaxBody {
		t.Fatalf("body err %v, prefix %d", r.BodyErr, len(r.Prefix))
	}
	if ops := Decode(r, gitHints); len(ops) != 1 || ops[0].Action != GitUpdate || ops[0].Error != "" {
		t.Fatalf("%+v", ops)
	}
	r.Header.Set("Content-Encoding", "gzip")
	if ops := Decode(r, gitHints); ops[0].Error == "" {
		t.Fatal("compressed oversized push decoded")
	}
	// Commands that do not end within MaxBody fail closed.
	many := bytes.Repeat([]byte(pkt(idA+" "+idB+" refs/heads/main\n")), request.MaxBody/100)
	r = gitReq("POST", "/a/b/git-receive-pack", nil)
	r.BodyErr, r.Prefix = request.ErrBodyTooLarge, many[:request.MaxBody]
	if ops := Decode(r, gitHints); ops[0].Error == "" {
		t.Fatal("truncated commands decoded")
	}
}

func FuzzGitReceivePack(f *testing.F) {
	f.Add([]byte(pkt(zeroID+" "+idA+" refs/heads/x\x00report-status\n") + "0000PACK"))
	f.Add([]byte(pkt("shallow "+idA+"\n") + pkt(idA+" "+zeroID+" refs/tags/v1\n") + "0000"))
	f.Add([]byte("0000"))
	f.Fuzz(func(t *testing.T, body []byte) {
		ops := Decode(gitReq("POST", "/a/b/git-receive-pack", body), gitHints)
		checkOps(t, ops)
		for _, o := range ops {
			if o.Error != "" {
				continue
			}
			ref, _ := o.Args["ref"].(string)
			switch o.Action {
			case GitListRefs:
			case GitCreate, GitUpdate, GitDelete:
				if !strings.HasPrefix(ref, "refs/") || strings.Contains(ref, "..") {
					t.Fatalf("bad ref accepted: %q", ref)
				}
			default:
				t.Fatalf("unexpected action %+v", o)
			}
		}
	})
}

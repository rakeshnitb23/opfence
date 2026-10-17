package inject

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/secrets"
)

// MaxSignedBody is the largest body SigV4 reads into memory to hash when
// the client sent no X-Amz-Content-Sha256 header.
const MaxSignedBody = 16 << 20

const (
	sigV4Alg      = "AWS4-HMAC-SHA256"
	sigV4AAlg     = "AWS4-ECDSA-P256-SHA256"
	amzDateFormat = "20060102T150405Z"
	// unsignedTrailer is a streaming upload whose chunks carry no
	// signatures, so only the seed signature needs redoing. AWS CLI v2 and
	// the current SDKs use it for S3 uploads.
	unsignedTrailer = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
)

var (
	signer   = v4.NewSigner()
	s3Signer = v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
)

// hopHeaders are dropped by the reverse proxy, so they are never signed.
var hopHeaders = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-connection": true, "te": true,
	"trailer": true, "transfer-encoding": true, "upgrade": true,
	"proxy-authorization": true, "proxy-authenticate": true,
}

// AWSRequest is an outgoing request to an AWS host, as it will be sent.
type AWSRequest struct {
	Method, Host  string
	Path, RawPath string // decoded and escaped path
	RawQuery      string
	Header        http.Header // updated in place when the request is re-signed
	ContentLength int64       // -1 when unknown
	Body          []byte      // the body read so far, still encoded
	BodyComplete  bool        // Body is the whole body
	Rest          io.Reader   // the rest of the body when it is not
}

// SigV4 re-signs a request that the client signed with a placeholder
// access key ID, using the real key, secret and session token Opfence holds
// for it (docs/ARCHITECTURE.md §8.4). The client's signature covers the
// placeholder, so the request is signed again over the same method, path,
// query and signed headers, with the same date, region and service.
//
// A request signed with a key Opfence does not hold passes unchanged, as
// does one whose placeholder belongs to another provider (reported in
// Foreign; AWS rejects it). An error means the request carries a placeholder
// Opfence cannot re-sign it for, and must be blocked with the error's text.
// When SigV4 had to read the rest of the body to hash it, it returns the
// whole body, which the caller must forward in place of Body and Rest.
func SigV4(prov *catalog.Provider, r AWSRequest, set *secrets.Set) (Result, []byte, error) {
	var res Result
	if prov == nil || !prov.SigV4 || set.Len() == 0 {
		return res, nil, nil
	}
	auth := r.Header.Get("Authorization")
	if auth == "" {
		q, _ := url.ParseQuery(r.RawQuery)
		if cred := q.Get("X-Amz-Credential"); cred != "" {
			if s := set.ByPlaceholder(strings.SplitN(cred, "/", 2)[0]); s != nil && s.Provider == prov.ID {
				return res, nil, refuse("it is a presigned URL, which Opfence cannot re-sign")
			}
		}
		return res, nil, nil
	}
	alg, cred, signedHeaders, ok := parseAuthorization(auth)
	if !ok {
		return res, nil, nil
	}
	id := set.ByPlaceholder(strings.SplitN(cred, "/", 2)[0])
	if id == nil {
		return res, nil, nil // signed with a key Opfence does not hold
	}
	if id.Provider != prov.ID {
		res.Foreign = append(res.Foreign, id.Provider+"/"+id.Name)
		return res, nil, nil
	}
	if alg == sigV4AAlg {
		return res, nil, refuse("it is signed with SigV4A (multi-Region), which Opfence cannot re-sign")
	}
	scope := strings.Split(cred, "/")
	if len(scope) != 5 || scope[4] != "aws4_request" {
		return res, nil, refuse("its credential scope is malformed")
	}
	region, service := scope[2], scope[3]
	secret, err := secretFor(id, set)
	if err != nil {
		return res, nil, err
	}
	creds := aws.Credentials{AccessKeyID: id.Value, SecretAccessKey: secret.Value}
	res.Injected = append(res.Injected, id.Provider+"/"+id.Name, secret.Provider+"/"+secret.Name)
	if tok := r.Header.Get("X-Amz-Security-Token"); tok != "" {
		creds.SessionToken = tok
		if s := set.ByPlaceholder(tok); s != nil {
			if s.Provider != prov.ID {
				return res, nil, refuse("its session token is a placeholder for " + s.Provider)
			}
			creds.SessionToken = s.Value
			res.Injected = append(res.Injected, s.Provider+"/"+s.Name)
		}
	}

	var full []byte
	payload := strings.TrimSpace(r.Header.Get("X-Amz-Content-Sha256"))
	switch {
	case strings.HasPrefix(payload, "STREAMING-") && payload != unsignedTrailer:
		return res, nil, refuse("it is a streaming upload with signed chunks (" + payload + "), which Opfence cannot re-sign")
	case payload == "":
		body := r.Body
		if !r.BodyComplete {
			if r.Rest == nil {
				return res, nil, refuse("its body could not be read")
			}
			rest, err := io.ReadAll(io.LimitReader(r.Rest, MaxSignedBody+1-int64(len(r.Body))))
			if err != nil {
				return res, nil, refuse("its body could not be read: " + err.Error())
			}
			full = append(append(make([]byte, 0, len(r.Body)+len(rest)), r.Body...), rest...)
			if len(full) > MaxSignedBody {
				return res, nil, refuse(fmt.Sprintf("its body is over %d MiB and has no X-Amz-Content-Sha256 header", MaxSignedBody>>20))
			}
			body = full
		}
		sum := sha256.Sum256(body)
		payload = hex.EncodeToString(sum[:])
	}

	when := time.Now().UTC()
	if d := r.Header.Get("X-Amz-Date"); d != "" {
		if when, err = time.Parse(amzDateFormat, d); err != nil {
			return res, full, refuse("its X-Amz-Date header is malformed")
		}
	}

	// Sign a copy holding only the headers the client signed, so the new
	// signature covers what the client meant to sign and nothing the proxy
	// adds or drops.
	out := &http.Request{
		Method: r.Method,
		URL:    &url.URL{Scheme: "https", Host: r.Host, Path: r.Path, RawPath: r.RawPath, RawQuery: r.RawQuery},
		Host:   r.Host,
		Header: http.Header{},
	}
	for _, name := range strings.Split(signedHeaders, ";") {
		switch name = strings.ToLower(strings.TrimSpace(name)); {
		case name == "content-length":
			if r.ContentLength > 0 {
				out.ContentLength = r.ContentLength
			}
		case name == "host", name == "authorization", hopHeaders[name]:
		default:
			if vals := r.Header.Values(name); len(vals) > 0 {
				out.Header[http.CanonicalHeaderKey(name)] = append([]string(nil), vals...)
			}
		}
	}
	sg := signer
	if strings.HasPrefix(service, "s3") {
		sg = s3Signer
	}
	if err := sg.SignHTTP(context.Background(), creds, out, payload, service, region, when); err != nil {
		return res, full, refuse(err.Error())
	}
	for _, k := range []string{"Authorization", "X-Amz-Date", "X-Amz-Security-Token"} {
		if v := out.Header.Get(k); v != "" {
			r.Header.Set(k, v)
		}
	}
	return res, full, nil
}

func refuse(why string) error {
	return fmt.Errorf("this AWS request was signed with a key Opfence holds, but Opfence cannot re-sign it: %s", why)
}

// parseAuthorization splits a SigV4 Authorization header.
func parseAuthorization(v string) (alg, cred, signedHeaders string, ok bool) {
	alg, rest, _ := strings.Cut(v, " ")
	if alg != sigV4Alg && alg != sigV4AAlg {
		return "", "", "", false
	}
	for _, part := range strings.Split(rest, ",") {
		k, val, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "Credential":
			cred = val
		case "SignedHeaders":
			signedHeaders = val
		}
	}
	return alg, cred, signedHeaders, cred != "" && signedHeaders != ""
}

// secretFor finds the secret access key that goes with an access key ID:
// the AWS secret found in the same place that is neither a key ID nor a
// session token. When there are several (two profiles in one file), the
// one whose name matches the key ID's wins.
func secretFor(id *secrets.Secret, set *secrets.Set) (*secrets.Secret, error) {
	if id.Group == "" {
		return nil, refuse("Opfence does not know which secret key goes with " + id.Name + "; run opfence init again")
	}
	var found []*secrets.Secret
	for _, s := range set.All() {
		if s == id || s.Provider != id.Provider || s.Group != id.Group || isKeyID(s.Value) || strings.Contains(strings.ToUpper(s.Name), "TOKEN") {
			continue
		}
		found = append(found, s)
	}
	if len(found) == 1 {
		return found[0], nil
	}
	want := strings.Replace(strings.ToUpper(id.Name), "ACCESS_KEY_ID", "SECRET_ACCESS_KEY", 1)
	for _, s := range found {
		if strings.ToUpper(s.Name) == want {
			return s, nil
		}
	}
	if len(found) == 0 {
		return nil, refuse("Opfence holds no secret access key found with " + id.Name)
	}
	return nil, refuse("several secret access keys were found with " + id.Name + " and none is named to match it")
}

func isKeyID(v string) bool {
	return len(v) == 20 && (strings.HasPrefix(v, "AKIA") || strings.HasPrefix(v, "ASIA"))
}

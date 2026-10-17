package inject

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/inject/sigv4test"
	"github.com/rakeshnitb23/opfence/internal/secrets"
)

var awsProv = &catalog.Provider{ID: "aws", SigV4: true}

// awsKeys returns a key ID, secret key and session token held in one group,
// with placeholders, assembled at run time so scanners skip them.
func awsKeys(t *testing.T, group string) (id, secret, token *secrets.Secret) {
	t.Helper()
	mk := func(name, value string, prefixes ...string) *secrets.Secret {
		ph, err := secrets.NewPlaceholder(value, prefixes)
		if err != nil {
			t.Fatal(err)
		}
		return &secrets.Secret{Provider: "aws", Name: name, Value: value, Placeholder: ph, Group: group}
	}
	return mk("AWS_ACCESS_KEY_ID", "ASIA"+"IOSFODNN7EXAMPLE", "AKIA", "ASIA"),
		mk("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/"+"bPxRfiCYEXAMPLEKEY"),
		mk("AWS_SESSION_TOKEN", "IQoJb3JpZ2luX2VjEBYaCXVzLWVhc3QtMSJHMEUCIQ"+"DexampleSessionTokenValue+/==")
}

type signReq struct {
	method, url, body string
	header            map[string]string
	service, region   string
	creds             aws.Credentials
	payload           string // X-Amz-Content-Sha256 to send; "" sends none and signs the body's hash
}

// clientSign signs a request as an AWS SDK would, and returns it as the
// proxy sees it.
func clientSign(t *testing.T, s signReq) AWSRequest {
	t.Helper()
	req, err := http.NewRequest(s.method, s.url, strings.NewReader(s.body))
	if err != nil {
		t.Fatal(err)
	}
	if s.body == "" {
		req.Body, req.ContentLength = http.NoBody, 0
	}
	for k, v := range s.header {
		req.Header.Set(k, v)
	}
	hash := s.payload
	if hash == "" {
		sum := sha256.Sum256([]byte(s.body))
		hash = hex.EncodeToString(sum[:])
	} else {
		req.Header.Set("X-Amz-Content-Sha256", hash)
	}
	sg := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = strings.HasPrefix(s.service, "s3") })
	if err := sg.SignHTTP(context.Background(), s.creds, req, hash, s.service, s.region, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	return AWSRequest{
		Method: req.Method, Host: req.URL.Host, Path: req.URL.Path, RawPath: req.URL.EscapedPath(), RawQuery: req.URL.RawQuery,
		Header: req.Header, ContentLength: req.ContentLength, Body: []byte(s.body), BodyComplete: true,
	}
}

// verify checks r's signature with the real credentials.
func verify(t *testing.T, r AWSRequest, body []byte, creds sigv4test.Creds) {
	t.Helper()
	if body == nil {
		body = r.Body
	}
	sr := &http.Request{
		Method: r.Method, Host: r.Host, Header: r.Header, ContentLength: r.ContentLength,
		URL:  &url.URL{Path: r.Path, RawPath: r.RawPath, RawQuery: r.RawQuery},
		Body: io.NopCloser(bytes.NewReader(body)),
	}
	if _, err := sigv4test.Verify(sr, creds); err != nil {
		t.Fatal(err)
	}
}

func TestSigV4Resign(t *testing.T) {
	id, sec, tok := awsKeys(t, "env")
	set := secrets.NewSet([]*secrets.Secret{id, sec, tok, railway})
	ph := aws.Credentials{AccessKeyID: id.Placeholder, SecretAccessKey: sec.Placeholder, SessionToken: tok.Placeholder}
	real := sigv4test.Creds{AccessKeyID: id.Value, SecretAccessKey: sec.Value, SessionToken: tok.Value}

	cases := []signReq{
		{method: "POST", url: "https://dynamodb.us-east-1.amazonaws.com/", body: `{"TableName":"orders"}`, service: "dynamodb", region: "us-east-1",
			header: map[string]string{"X-Amz-Target": "DynamoDB_20120810.DescribeTable", "Content-Type": "application/x-amz-json-1.0"}},
		{method: "POST", url: "https://sts.amazonaws.com/", body: "Action=GetCallerIdentity&Version=2011-06-15", service: "sts", region: "us-east-1",
			header: map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}},
		{method: "GET", url: "https://my-bucket.s3.eu-west-1.amazonaws.com/reports/q3%20final.csv?versionId=a%2Bb&x-id=GetObject", service: "s3", region: "eu-west-1",
			payload: "UNSIGNED-PAYLOAD"},
		{method: "PUT", url: "https://my-bucket.s3.eu-west-1.amazonaws.com/k?x-id=PutObject", body: "5\r\nhello\r\n0\r\nx-amz-checksum-crc32:NhCmhg==\r\n\r\n", service: "s3", region: "eu-west-1",
			payload: unsignedTrailer, header: map[string]string{"Content-Encoding": "aws-chunked", "X-Amz-Trailer": "x-amz-checksum-crc32", "X-Amz-Decoded-Content-Length": "5"}},
		{method: "GET", url: "https://ec2.us-west-2.amazonaws.com/?Action=DescribeInstances&Filter.1.Name=tag%3AName&Filter.1.Value.1=web%20*", service: "ec2", region: "us-west-2"},
	}
	for _, c := range cases {
		c.creds = ph
		r := clientSign(t, c)
		before := &http.Request{Method: r.Method, Host: r.Host, Header: r.Header.Clone(), ContentLength: r.ContentLength,
			URL: &url.URL{Path: r.Path, RawPath: r.RawPath, RawQuery: r.RawQuery}, Body: io.NopCloser(bytes.NewReader(r.Body))}
		if _, err := sigv4test.Verify(before, real); err == nil {
			t.Fatal("the placeholder signature verified with the real keys")
		}
		res, body, err := SigV4(awsProv, r, set)
		if err != nil {
			t.Fatalf("%s: %v", c.url, err)
		}
		if body != nil || len(res.Injected) != 3 || len(res.Foreign) != 0 {
			t.Fatalf("%s: %+v %q", c.url, res, body)
		}
		verify(t, r, nil, real)
	}
}

func TestSigV4ReadsTheBodyToHashIt(t *testing.T) {
	id, sec, _ := awsKeys(t, "/p/.env")
	set := secrets.NewSet([]*secrets.Secret{id, sec})
	real := sigv4test.Creds{AccessKeyID: id.Value, SecretAccessKey: sec.Value}
	full := `{"FunctionName":"f","Payload":"` + strings.Repeat("x", 100<<10) + `"}`
	r := clientSign(t, signReq{method: "POST", url: "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/f/invocations", body: full,
		service: "lambda", region: "us-east-1", creds: aws.Credentials{AccessKeyID: id.Placeholder, SecretAccessKey: sec.Placeholder}})
	r.Body, r.BodyComplete, r.Rest = []byte(full[:1000]), false, strings.NewReader(full[1000:])
	_, body, err := SigV4(awsProv, r, set)
	if err != nil || string(body) != full {
		t.Fatalf("%v, body %d bytes", err, len(body))
	}
	verify(t, r, body, real)

	// Too large to hold without a hash header: refused.
	r = clientSign(t, signReq{method: "POST", url: "https://lambda.us-east-1.amazonaws.com/x", body: "{}", service: "lambda", region: "us-east-1",
		creds: aws.Credentials{AccessKeyID: id.Placeholder, SecretAccessKey: sec.Placeholder}})
	r.BodyComplete, r.Rest = false, io.LimitReader(zeros{}, MaxSignedBody)
	if _, _, err := SigV4(awsProv, r, set); err == nil || !strings.Contains(err.Error(), "16 MiB") {
		t.Fatalf("large body: %v", err)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestSigV4PassesAndRefuses(t *testing.T) {
	id, sec, tok := awsKeys(t, "env")
	set := secrets.NewSet([]*secrets.Secret{id, sec, tok, railway})
	ph := aws.Credentials{AccessKeyID: id.Placeholder, SecretAccessKey: sec.Placeholder}
	get := signReq{method: "GET", url: "https://ec2.us-east-1.amazonaws.com/?Action=DescribeVpcs", service: "ec2", region: "us-east-1", creds: ph}

	// Signed with a real key Opfence does not hold: unchanged.
	other := get
	other.creds = aws.Credentials{AccessKeyID: "AKIA" + "OTHERKEY00000000", SecretAccessKey: strings.Repeat("s", 40)}
	r := clientSign(t, other)
	before := r.Header.Get("Authorization")
	if res, _, err := SigV4(awsProv, r, set); err != nil || r.Header.Get("Authorization") != before || len(res.Injected) != 0 {
		t.Fatalf("real key changed: %v %+v", err, res)
	}

	// Another provider's placeholder: left for AWS to reject.
	foreign := get
	foreign.creds = aws.Credentials{AccessKeyID: railway.Placeholder, SecretAccessKey: "x"}
	r = clientSign(t, foreign)
	if res, _, err := SigV4(awsProv, r, set); err != nil || len(res.Foreign) != 1 || len(res.Injected) != 0 {
		t.Fatalf("foreign: %v %+v", err, res)
	}

	// A header the client signed but the proxy dropped is left out of the
	// new signature; hop-by-hop headers are never signed.
	dropped := get
	dropped.header = map[string]string{"Accept-Encoding": "gzip", "X-Custom": "1"}
	r = clientSign(t, dropped)
	r.Header.Del("Accept-Encoding")
	if _, _, err := SigV4(awsProv, r, set); err != nil {
		t.Fatal(err)
	}
	if a := r.Header.Get("Authorization"); strings.Contains(a, "accept-encoding") || !strings.Contains(a, "x-custom") {
		t.Fatalf("signed headers: %s", a)
	}
	verify(t, r, nil, sigv4test.Creds{AccessKeyID: id.Value, SecretAccessKey: sec.Value})
	r.Header.Set("X-Custom", "2")
	tampered := &http.Request{Method: r.Method, Host: r.Host, Header: r.Header, URL: &url.URL{Path: r.Path, RawQuery: r.RawQuery}, Body: http.NoBody}
	if _, err := sigv4test.Verify(tampered, sigv4test.Creds{AccessKeyID: id.Value, SecretAccessKey: sec.Value}); err == nil || !strings.Contains(err.Error(), "signature does not match") {
		t.Fatalf("tampered request: %v", err)
	}

	refusals := map[string]func(*AWSRequest){
		"signed chunks": func(r *AWSRequest) { r.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD") },
		"SigV4A": func(r *AWSRequest) {
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), sigV4Alg, sigV4AAlg, 1))
		},
		"presigned URL": func(r *AWSRequest) {
			r.Header.Del("Authorization")
			r.RawQuery = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=" + id.Placeholder + "%2F20261017%2Fus-east-1%2Fs3%2Faws4_request"
		},
		"placeholder for railway": func(r *AWSRequest) { r.Header.Set("X-Amz-Security-Token", railway.Placeholder) },
		"malformed":               func(r *AWSRequest) { r.Header.Set("X-Amz-Date", "yesterday") },
		// Hosts anyone can run under amazonaws.com never get a real signature.
		"an API Gateway API":            func(r *AWSRequest) { r.Host = "abc123.execute-api.us-east-1.amazonaws.com" },
		"a load balancer":               func(r *AWSRequest) { r.Host = "my-lb-1234.us-east-1.elb.amazonaws.com" },
		"an EC2 instance's public name": func(r *AWSRequest) { r.Host = "ec2-203-0-113-5.compute-1.amazonaws.com" },
		"a VPC endpoint":                func(r *AWSRequest) { r.Host = "vpce-0abc-xyz.s3.us-east-1.vpce.amazonaws.com" },
	}
	// AWS's own APIs with similar names are re-signed.
	for _, host := range []string{"ec2-instance-connect.us-east-1.amazonaws.com", "elasticloadbalancing.us-east-1.amazonaws.com", "compute-optimizer.us-east-1.amazonaws.com"} {
		r := clientSign(t, get)
		r.Host = host
		if _, _, err := SigV4(awsProv, r, set); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
	for want, mutate := range refusals {
		r := clientSign(t, get)
		mutate(&r)
		if _, _, err := SigV4(awsProv, r, set); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", want, err)
		}
	}

	// No secret key in the key ID's group.
	lone := secrets.NewSet([]*secrets.Secret{id, {Provider: "aws", Name: "AWS_SECRET_ACCESS_KEY", Value: sec.Value, Placeholder: sec.Placeholder, Group: "/elsewhere/.env"}})
	if _, _, err := SigV4(awsProv, clientSign(t, get), lone); err == nil || !strings.Contains(err.Error(), "no secret access key") {
		t.Errorf("lone key ID: %v", err)
	}
}

func TestSigV4PairsKeysByName(t *testing.T) {
	id, sec, _ := awsKeys(t, "/p/.env")
	id2, sec2, _ := awsKeys(t, "/p/.env")
	id2.Name, sec2.Name = "PROD_AWS_ACCESS_KEY_ID", "PROD_AWS_SECRET_ACCESS_KEY"
	id2.Value, sec2.Value = "AKIA"+"PRODKEY000000000", strings.Repeat("P", 40)
	set := secrets.NewSet([]*secrets.Secret{id, sec, id2, sec2})
	r := clientSign(t, signReq{method: "GET", url: "https://iam.amazonaws.com/?Action=ListUsers", service: "iam", region: "us-east-1",
		creds: aws.Credentials{AccessKeyID: id2.Placeholder, SecretAccessKey: sec2.Placeholder}})
	if _, _, err := SigV4(awsProv, r, set); err != nil {
		t.Fatal(err)
	}
	verify(t, r, nil, sigv4test.Creds{AccessKeyID: id2.Value, SecretAccessKey: sec2.Value})

	sec2.Name = "SOMETHING_ELSE"
	r = clientSign(t, signReq{method: "GET", url: "https://iam.amazonaws.com/?Action=ListUsers", service: "iam", region: "us-east-1",
		creds: aws.Credentials{AccessKeyID: id2.Placeholder, SecretAccessKey: sec2.Placeholder}})
	if _, _, err := SigV4(awsProv, r, set); err == nil || !strings.Contains(err.Error(), "several secret access keys") {
		t.Fatalf("ambiguous: %v", err)
	}
}

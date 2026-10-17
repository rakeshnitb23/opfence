package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/rakeshnitb23/opfence/internal/inject/sigv4test"
	"github.com/rakeshnitb23/opfence/internal/secrets"
)

// The stage 10 exit criterion for AWS: a client holding only placeholders
// signs a request, and the fake AWS, which knows only the real keys,
// accepts the signature; the response never shows the real key ID.
func TestAWSPlaceholdersAreResigned(t *testing.T) {
	mk := func(name, value string) *secrets.Secret {
		ph, err := secrets.NewPlaceholder(value, []string{"AKIA", "ASIA"})
		if err != nil {
			t.Fatal(err)
		}
		return &secrets.Secret{Provider: "aws", Name: name, Value: value, Placeholder: ph, Group: "env"}
	}
	id := mk("AWS_ACCESS_KEY_ID", "ASIA"+"IOSFODNN7EXAMPLE")
	sec := mk("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/"+"bPxRfiCYEXAMPLEKEY")
	tok := mk("AWS_SESSION_TOKEN", "IQoJb3JpZ2luX2VjEBYaCXVzLWVhc3QtMSJHMEUCIQ"+"DexampleSessionTokenValue")
	real := sigv4test.Creds{AccessKeyID: id.Value, SecretAccessKey: sec.Value, SessionToken: tok.Value}

	e := newEnv(t, opts{secrets: secrets.NewSet([]*secrets.Secret{id, sec, tok}), respond: func(w http.ResponseWriter, r *http.Request) {
		if _, err := sigv4test.Verify(r, real); err != nil {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"__type":"SignatureDoesNotMatch","message":%q}`, err.Error())
			return
		}
		fmt.Fprintf(w, `{"Table":{"TableName":"orders"},"caller":%q}`, id.Value)
	}})
	c := e.client(true)
	do := func(method, u, body, service, payload string, hdr ...string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(method, u, strings.NewReader(body))
		if body == "" {
			req.Body, req.ContentLength = http.NoBody, 0
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		if payload == "" {
			sum := sha256.Sum256([]byte(body))
			payload = hex.EncodeToString(sum[:])
		} else {
			req.Header.Set("X-Amz-Content-Sha256", payload)
		}
		sg := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = service == "s3" })
		creds := aws.Credentials{AccessKeyID: id.Placeholder, SecretAccessKey: sec.Placeholder, SessionToken: tok.Placeholder}
		if err := sg.SignHTTP(context.Background(), creds, req, payload, service, "us-east-1", time.Now()); err != nil {
			t.Fatal(err)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}

	resp, body := do("POST", "https://dynamodb.us-east-1.amazonaws.com/", `{"TableName":"orders"}`, "dynamodb", "",
		"X-Amz-Target", "DynamoDB_20120810.DescribeTable", "Content-Type", "application/x-amz-json-1.0")
	if resp.StatusCode != 200 || strings.Contains(body, id.Value) || !strings.Contains(body, id.Placeholder) {
		t.Fatalf("dynamodb: %d %s", resp.StatusCode, body)
	}
	if resp, body := do("GET", "https://my-bucket.s3.us-east-1.amazonaws.com/reports/q3%20final.csv", "", "s3", "UNSIGNED-PAYLOAD"); resp.StatusCode != 200 {
		t.Fatalf("s3: %d %s", resp.StatusCode, body)
	}
	es := e.entries()
	if got := strings.Join(es[0].Credentials, ","); got != "aws/AWS_ACCESS_KEY_ID,aws/AWS_SECRET_ACCESS_KEY,aws/AWS_SESSION_TOKEN" {
		t.Fatalf("audit credentials %q", got)
	}

	// A request Opfence cannot re-sign is blocked before it leaves.
	e.srv.cfg.Approver = &approveAll{}
	hits := e.hits.Load()
	resp, body = do("PUT", "https://my-bucket.s3.us-east-1.amazonaws.com/k", "x", "s3", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "cannot re-sign") || e.hits.Load() != hits {
		t.Fatalf("streaming upload: %d %s", resp.StatusCode, body)
	}
}

package decode

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/rakeshnitb23/opfence/internal/request"
)

// SigV4Scope is the credential scope of a SigV4 or SigV4A signature.
type SigV4Scope struct {
	AccessKey string
	Region    string // empty for SigV4A
	Service   string
}

// ParseSigV4 extracts the credential scope from a request's Authorization
// header or presigned query parameters. It reports false for an unsigned
// request.
func ParseSigV4(r *request.Request) (SigV4Scope, bool) {
	if auth := r.Header.Get("Authorization"); auth != "" {
		alg, rest, _ := strings.Cut(auth, " ")
		if alg == "AWS4-HMAC-SHA256" || alg == "AWS4-ECDSA-P256-SHA256" {
			for _, part := range strings.Split(rest, ",") {
				k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
				if k == "Credential" {
					return parseScope(v)
				}
			}
		}
		return SigV4Scope{}, false
	}
	if alg := r.Query.Get("X-Amz-Algorithm"); alg == "AWS4-HMAC-SHA256" || alg == "AWS4-ECDSA-P256-SHA256" {
		return parseScope(r.Query.Get("X-Amz-Credential"))
	}
	return SigV4Scope{}, false
}

// parseScope parses AKID/date/region/service/aws4_request (SigV4) or
// AKID/date/service/aws4_request (SigV4A).
func parseScope(cred string) (SigV4Scope, bool) {
	parts := strings.Split(cred, "/")
	switch {
	case len(parts) == 5 && parts[4] == "aws4_request":
		return SigV4Scope{AccessKey: parts[0], Region: parts[2], Service: parts[3]}, parts[0] != "" && parts[3] != ""
	case len(parts) == 4 && parts[3] == "aws4_request":
		return SigV4Scope{AccessKey: parts[0], Service: parts[2]}, parts[0] != "" && parts[2] != ""
	}
	return SigV4Scope{}, false
}

// awsQueryServices are signing names of services that use the AWS Query
// protocol (an Action parameter on POST / or GET /).
var awsQueryServices = map[string]bool{
	"ec2": true, "iam": true, "sts": true, "rds": true, "sns": true, "sqs": true,
	"cloudformation": true, "elasticloadbalancing": true, "autoscaling": true,
	"monitoring": true, "elasticache": true, "redshift": true, "ses": true,
	"sdb": true, "elasticbeanstalk": true, "importexport": true,
}

func decodeAWS(r *request.Request) []Operation {
	op := Operation{Protocol: AWS, Method: r.Method, Path: r.Path, Args: map[string]any{}}
	scope, ok := ParseSigV4(r)
	if !ok {
		op.Error = "request to an AWS host is not SigV4-signed"
		return []Operation{op}
	}
	op.Service = strings.ToLower(scope.Service)

	// S3 is identified by method, bucket, key and sub-resource only. It
	// ignores unknown query parameters and headers, so an Action parameter
	// or X-Amz-Target header must never be trusted for it.
	if op.Service == "s3" {
		s3Operation(r, &op)
		return []Operation{op}
	}

	rootPath := false
	if segs, ok := request.NormalizePath(r.Path); ok && len(segs) == 0 {
		rootPath = true
	}

	// JSON protocol: POST / with the action in X-Amz-Target
	// ("DynamoDB_20120810.DeleteTable"). REST services ignore that header,
	// so it only counts on POST /.
	if target := r.Header.Get("X-Amz-Target"); target != "" && r.Method == "POST" && rootPath {
		op.Action = target[strings.LastIndexByte(target, '.')+1:]
		if r.BodyErr != nil {
			op.Error = r.BodyErr.Error()
			return []Operation{op}
		}
		if len(r.Body) > 0 {
			v, err := parseJSON(r.Body)
			if err != nil {
				op.Error = err.Error()
				return []Operation{op}
			}
			m, ok := v.(map[string]any)
			if !ok {
				op.Error = "AWS JSON body is not an object"
				return []Operation{op}
			}
			op.Args = m
		}
		return []Operation{op}
	}

	// Query protocol: Action in the form body or the query string of a
	// request to /, for services known to speak it. Elsewhere an Action
	// parameter could be junk the service ignores.
	if rootPath && awsQueryServices[op.Service] {
		params := url.Values{}
		for k, v := range r.Query {
			params[k] = append(params[k], v...)
		}
		if r.Method == "POST" && r.ContentType() == "application/x-www-form-urlencoded" {
			if r.BodyErr != nil {
				op.Error = r.BodyErr.Error()
				return []Operation{op}
			}
			form, err := url.ParseQuery(string(r.Body))
			if err != nil {
				op.Error = "invalid form body: " + err.Error()
				return []Operation{op}
			}
			for k, v := range form {
				params[k] = append(params[k], v...)
			}
		}
		acts := params["Action"]
		if len(acts) != 1 || acts[0] == "" {
			op.Error = "Query protocol request needs exactly one Action"
			return []Operation{op}
		}
		op.Action = acts[0]
		flat := map[string]any{}
		for k, v := range valuesToMap(params) {
			if !strings.HasPrefix(k, "X-Amz-") {
				flat[k] = v
			}
		}
		args, err := nestQueryParams(flat)
		if err != nil {
			op.Error = err.Error()
			return []Operation{op}
		}
		op.Args = args
		return []Operation{op}
	}

	// REST-JSON and REST-XML services (Lambda, API Gateway and others) carry
	// the action in the method and path; catalog rules match those with
	// aws: {service, method, path}.
	op.Args["query"] = valuesToMap(r.Query)
	if r.BodyErr != nil {
		op.BodyErr = r.BodyErr.Error()
	} else if len(r.Body) > 0 && (r.ContentType() == "application/json" || strings.HasSuffix(r.ContentType(), "+json")) {
		if v, err := parseJSON(r.Body); err == nil {
			op.Args["body"] = v
		} else {
			op.BodyErr = err.Error()
		}
	}
	return []Operation{op}
}

// nestQueryParams turns Query-protocol parameter names into structure:
// "InstanceId.1" and "InstanceId.2" become the list InstanceId, and
// "Tags.member.1.Key" becomes Tags[0].Key, so rules and cards can name
// InstanceId or Tags.Key. A name that is both a value and a prefix of
// another name ("A=1&A.1=2") is ambiguous and fails the request.
func nestQueryParams(flat map[string]any) (map[string]any, error) {
	keys := make([]string, 0, len(flat))
	for k := range flat {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	root := map[string]any{}
	for _, k := range keys {
		parts := strings.Split(k, ".")
		for _, p := range parts {
			if p == "" {
				parts = []string{k} // malformed: keep the name as it is
				break
			}
		}
		var segs []string
		for i, p := range parts {
			if p == "member" && i+1 < len(parts) && isIndex(parts[i+1]) {
				continue
			}
			segs = append(segs, p)
		}
		cur := root
		for i, p := range segs {
			last := i == len(segs)-1
			existing, ok := cur[p]
			switch {
			case last && ok:
				return nil, fmt.Errorf("conflicting Query parameter %q", k)
			case last:
				cur[p] = flat[k]
			case !ok:
				next := map[string]any{}
				cur[p] = next
				cur = next
			default:
				next, isMap := existing.(map[string]any)
				if !isMap {
					return nil, fmt.Errorf("conflicting Query parameter %q", k)
				}
				cur = next
			}
		}
	}
	for k, v := range root {
		root[k] = listify(v) // the top level stays a map even if every name is a number
	}
	return root, nil
}

func isIndex(s string) bool {
	if s == "" || len(s) > 6 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// listify turns maps whose keys are all indexes into lists ordered by index.
func listify(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	allIndex := len(m) > 0
	for k, x := range m {
		m[k] = listify(x)
		if !isIndex(k) {
			allIndex = false
		}
	}
	if !allIndex {
		return m
	}
	idx := make([]string, 0, len(m))
	for k := range m {
		idx = append(idx, k)
	}
	sort.Slice(idx, func(i, j int) bool {
		a, _ := strconv.Atoi(idx[i])
		b, _ := strconv.Atoi(idx[j])
		return a < b
	})
	list := make([]any, len(idx))
	for i, k := range idx {
		list[i] = m[k]
	}
	return list
}

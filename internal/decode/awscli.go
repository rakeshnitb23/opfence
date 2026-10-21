package decode

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/request"
)

// awscliData is awscli's command table, written by tools/awscligen from the
// awscli the AWS API MCP server parses commands with.
//
//go:embed awscli.json.gz
var awscliData []byte

type awscliTable struct {
	AWSCLI   string                   `json:"awscli"`
	Services map[string]awscliService `json:"services"`
}

type awscliService struct {
	Signing  string                    `json:"signing"`
	Protocol string                    `json:"protocol"`
	Version  string                    `json:"version"`
	Target   string                    `json:"target"`
	JSON     string                    `json:"json"`
	Ops      map[string]*string        `json:"ops"` // CLI name → API name, nil for customizations
	Detail   map[string]awscliOpDetail `json:"detail"`
}

type awscliOpDetail struct {
	Method string               `json:"method"`
	URI    string               `json:"uri"`
	Args   map[string]awscliArg `json:"args"`
}

type awscliArg struct {
	Member       string `json:"m"`
	Type         string `json:"t"`
	Location     string `json:"l"`
	LocationName string `json:"ln"`
	QueryName    string `json:"qn"`
	Flattened    bool   `json:"fl"`
	MemberType   string `json:"mt"`
	Negative     bool   `json:"neg"`
	Unread       bool   `json:"u"`
	Optional     bool   `json:"opt"`
	Flag         bool   `json:"flag"`
}

var awscli = sync.OnceValues(func() (*awscliTable, error) {
	zr, err := gzip.NewReader(bytes.NewReader(awscliData))
	if err != nil {
		return nil, err
	}
	var t awscliTable
	if err := json.NewDecoder(zr).Decode(&t); err != nil {
		return nil, err
	}
	return &t, nil
})

// AWSCLIVersion is the awscli version the command table was generated from.
func AWSCLIVersion() string {
	t, err := awscli()
	if err != nil {
		return ""
	}
	return t.AWSCLI
}

// CLIStep is one thing an AWS CLI command does: an API operation decoded as
// the proxy would decode its request, or, for an awscli customization that
// is not an API call, a class.
type CLIStep struct {
	Op     *Operation
	Class  classes.Class
	Reason string
}

// Words the AWS API MCP server refuses in a command (core/parser/lexer.py).
var awscliRefused = map[string]bool{
	"&&": true, "||": true, "=": true, "*=": true, "/=": true, "%=": true, "+=": true, "-=": true,
	"<<=": true, ">>=": true, "&=": true, "^=": true, "|=": true,
}

var uriParamRe = regexp.MustCompile(`\{[^{}]+\}`)

// Global options awscli takes anywhere in a command, and whether they take
// a value.
var awscliGlobals = map[string]bool{
	"debug": false, "endpoint-url": true, "no-verify-ssl": false, "no-paginate": false, "output": true,
	"query": true, "profile": true, "region": true, "version": false, "color": true, "no-sign-request": false,
	"ca-bundle": true, "cli-read-timeout": true, "cli-connect-timeout": true, "v2-debug": false,
}

// AWSCLI reads one AWS CLI command line ("aws rds delete-db-instance ...")
// and returns what it does. Arguments Opfence cannot read (--cli-input-json,
// file:// values, malformed shorthand) add an unknown step, so a rule whose
// conditions they could have met is never decided more loosely.
func AWSCLI(command string) ([]CLIStep, error) {
	t, err := awscli()
	if err != nil {
		return nil, fmt.Errorf("AWS CLI table: %w", err)
	}
	words, err := ShellWords(command)
	if err != nil {
		return nil, err
	}
	if len(words) == 0 || words[0] != "aws" {
		return nil, errors.New("not an aws command")
	}
	var rest []string
	for i := 1; i < len(words); i++ {
		w := words[i]
		if awscliRefused[w] {
			// The server refuses commands with shell operators.
			return []CLIStep{{Class: classes.Unknown, Reason: "the command contains " + w}}, nil
		}
		name, _, hasVal := strings.Cut(strings.TrimPrefix(w, "--"), "=")
		if takes, global := awscliGlobals[name]; strings.HasPrefix(w, "--") && global {
			if takes && !hasVal {
				i++
			}
			continue
		}
		rest = append(rest, w)
	}
	if len(rest) == 0 || rest[0] == "help" {
		return []CLIStep{{Class: classes.Read, Reason: "help"}}, nil
	}
	svcName := rest[0]
	if svcName == "s3" {
		return awscliS3(rest[1:])
	}
	svc, ok := t.Services[svcName]
	if !ok {
		return []CLIStep{{Class: classes.Unknown, Reason: "aws " + svcName + " is not an AWS CLI service"}}, nil
	}
	if len(rest) < 2 || rest[1] == "help" {
		return []CLIStep{{Class: classes.Read, Reason: "help"}}, nil
	}
	opName := rest[1]
	api, known := svc.Ops[opName]
	switch {
	case !known:
		return []CLIStep{{Class: classes.Unknown, Reason: "aws " + svcName + " " + opName + " is not an AWS CLI command"}}, nil
	case api == nil:
		return []CLIStep{awscliCustomization(svcName, opName)}, nil
	}
	detail, detailed := svc.Detail[opName]
	if !detailed {
		// A service catalog/aws has no rules for: the action is enough for
		// its defaults.
		return []CLIStep{{Op: &Operation{Protocol: AWS, Service: svc.Signing, Action: *api, Args: map[string]any{}}}}, nil
	}
	params, unread := awscliParams(detail, rest[2:])
	op, err := awscliOperation(svc, *api, detail, params)
	if err != nil {
		return []CLIStep{{Class: classes.Unknown, Reason: err.Error()}}, nil
	}
	steps := []CLIStep{{Op: op}}
	if unread != "" {
		steps = append(steps, CLIStep{Class: classes.Unknown, Reason: unread})
	}
	return steps, nil
}

// awscliParams reads an operation's arguments into API members. It returns
// a reason when some could not be read.
func awscliParams(d awscliOpDetail, words []string) (map[string]any, string) {
	params := map[string]any{}
	unread := ""
	for i := 0; i < len(words); i++ {
		w := words[i]
		if !strings.HasPrefix(w, "--") {
			continue // a positional argument (an outfile)
		}
		name, inline, hasInline := strings.Cut(w[2:], "=")
		a, ok := d.Args[name]
		if !ok {
			unread = "argument --" + name + " is not one Opfence knows"
			continue
		}
		next := func() (string, bool) {
			if hasInline {
				return inline, true
			}
			if i+1 < len(words) {
				i++
				return words[i], true
			}
			return "", false
		}
		switch {
		case a.Unread && a.Optional:
			if !hasInline && i+1 < len(words) && !strings.HasPrefix(words[i+1], "--") {
				i++
			}
			unread = "--" + name + " is not read"
		case a.Unread && a.Flag:
			unread = "--" + name + " is not read"
		case a.Unread:
			next()
			unread = "--" + name + " supplies parameters Opfence cannot see"
		case a.Type == "boolean":
			params[a.key()] = !a.Negative
		case a.Type == "list":
			var vals []string
			if hasInline {
				vals = append(vals, inline)
			}
			for !hasInline && i+1 < len(words) && !strings.HasPrefix(words[i+1], "--") {
				i++
				vals = append(vals, words[i])
			}
			v, err := awscliList(a, vals)
			if err != nil {
				unread = "--" + name + ": " + err.Error()
				continue
			}
			params[a.key()] = v
		default:
			s, ok := next()
			if !ok {
				unread = "--" + name + " has no value"
				continue
			}
			v, err := awscliValue(a.Type, s)
			if err != nil {
				unread = "--" + name + ": " + err.Error()
				continue
			}
			params[a.key()] = v
		}
	}
	return params, unread
}

// key is where a parameter goes in the decoded request: the member name,
// tagged with its wire location for REST protocols.
func (a awscliArg) key() string { return a.Member }

// awscliValue reads one value: JSON or shorthand for structures and maps,
// the text for everything else. file:// values are refused, because the
// file is not Opfence's to read.
func awscliValue(typ, s string) (any, error) {
	if strings.HasPrefix(s, "file://") || (strings.HasPrefix(s, "fileb://") && typ != "blob") {
		return nil, errors.New("value read from a file")
	}
	switch typ {
	case "structure", "map":
		if t := strings.TrimSpace(s); strings.HasPrefix(t, "{") {
			var v any
			dec := json.NewDecoder(strings.NewReader(t))
			dec.UseNumber()
			if err := dec.Decode(&v); err != nil {
				return nil, errors.New("not valid JSON")
			}
			return jsonStrings(v), nil
		}
		return awscliShorthand(s)
	}
	return s, nil
}

func awscliList(a awscliArg, vals []string) (any, error) {
	if len(vals) == 1 {
		if t := strings.TrimSpace(vals[0]); strings.HasPrefix(t, "[") {
			var v any
			dec := json.NewDecoder(strings.NewReader(t))
			dec.UseNumber()
			if err := dec.Decode(&v); err != nil {
				return nil, errors.New("not valid JSON")
			}
			return jsonStrings(v), nil
		}
	}
	out := make([]any, 0, len(vals))
	for _, v := range vals {
		if a.MemberType == "structure" || a.MemberType == "map" {
			m, err := awscliValue(a.MemberType, v)
			if err != nil {
				return nil, err
			}
			out = append(out, m)
			continue
		}
		if strings.HasPrefix(v, "file://") {
			return nil, errors.New("value read from a file")
		}
		if strings.Contains(v, ",") && a.MemberType != "structure" {
			for _, p := range strings.Split(v, ",") {
				out = append(out, p)
			}
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

// awscliShorthand reads awscli's flat shorthand, Key=Value,Key2=Value2.
// Nested shorthand (brackets, braces) is refused rather than misread.
func awscliShorthand(s string) (map[string]any, error) {
	if strings.ContainsAny(s, "[]{}") {
		return nil, errors.New("nested shorthand is not read")
	}
	out := map[string]any{}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, errors.New("shorthand without key=value")
		}
		if _, dup := out[k]; dup {
			return nil, errors.New("shorthand repeats " + k)
		}
		out[k] = strings.TrimSpace(v)
	}
	return out, nil
}

// jsonStrings turns JSON numbers and booleans into the strings a decoded
// request would carry, so conditions compare alike.
func jsonStrings(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = jsonStrings(e)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = jsonStrings(e)
		}
		return x
	}
	return v
}

// awscliOperation builds the request the SDK would send for an operation
// and decodes it as the proxy decodes requests, so its arguments have the
// shape catalog/aws's rules expect.
func awscliOperation(svc awscliService, api string, d awscliOpDetail, params map[string]any) (*Operation, error) {
	r := &request.Request{Method: d.Method, Host: svc.Signing + ".amazonaws.com", Header: http.Header{}, Query: url.Values{}}
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=OPFENCECLI/20000101/us-east-1/"+svc.Signing+"/aws4_request, SignedHeaders=host, Signature=0")
	byMember := map[string]awscliArg{}
	for _, a := range d.Args {
		if a.Member != "" {
			byMember[a.Member] = a
		}
	}
	switch svc.Protocol {
	case "json":
		r.Method, r.Path = "POST", "/"
		r.Header.Set("X-Amz-Target", svc.Target+"."+api)
		r.Header.Set("Content-Type", "application/x-amz-json-"+svc.JSON)
		body, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		r.Body = body
	case "query", "ec2":
		r.Method, r.Path = "POST", "/"
		form := url.Values{"Action": {api}, "Version": {svc.Version}}
		names := sortedKeys(params)
		for _, m := range names {
			a := byMember[m]
			name := m
			switch {
			case svc.Protocol == "ec2" && a.QueryName != "":
				name = a.QueryName
			case svc.Protocol == "ec2" && a.LocationName != "":
				name = upperFirst(a.LocationName)
			case a.LocationName != "":
				name = a.LocationName
			}
			queryFlatten(form, name, params[m], svc.Protocol == "ec2" || a.Flattened)
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Body = []byte(form.Encode())
	case "rest-json", "rest-xml":
		uri, rawQuery, _ := strings.Cut(d.URI, "?")
		// URI templates name members by their wire name (Route 53's {Id} is
		// HostedZoneId).
		uriValues := map[string]any{}
		for m, v := range params {
			if a := byMember[m]; a.Location == "uri" {
				if a.LocationName != "" {
					uriValues[a.LocationName] = v
				} else {
					uriValues[m] = v
				}
			}
		}
		var missing string
		path := uriParamRe.ReplaceAllStringFunc(uri, func(m string) string {
			name := strings.Trim(m, "{}")
			greedy := strings.HasSuffix(name, "+")
			name = strings.TrimSuffix(name, "+")
			v, ok := uriValues[name].(string)
			if !ok {
				missing = name
				return "x"
			}
			if greedy {
				return escapePathKeepSlash(v)
			}
			return url.PathEscape(v)
		})
		if missing != "" {
			return nil, fmt.Errorf("the request needs the %s parameter", missing)
		}
		r.Path = path
		if rawQuery != "" {
			q, err := url.ParseQuery(rawQuery)
			if err == nil {
				for k, v := range q {
					r.Query[k] = v
				}
			}
		}
		body := map[string]any{}
		for _, m := range sortedKeys(params) {
			a := byMember[m]
			name := a.LocationName
			if name == "" {
				name = m
			}
			switch a.Location {
			case "uri":
			case "querystring":
				for _, v := range scalarList(params[m]) {
					r.Query.Add(name, v)
				}
			case "header", "headers":
				for _, v := range scalarList(params[m]) {
					r.Header.Add(name, v)
				}
			default:
				body[m] = params[m]
			}
		}
		if svc.Protocol == "rest-json" && len(body) > 0 {
			b, err := json.Marshal(body)
			if err != nil {
				return nil, err
			}
			r.Body = b
			r.Header.Set("Content-Type", "application/json")
		}
	default:
		return &Operation{Protocol: AWS, Service: svc.Signing, Action: api, Args: params}, nil
	}
	ops := decodeAWS(r)
	if len(ops) != 1 {
		return nil, errors.New("the request decodes to more than one operation")
	}
	op := ops[0]
	if op.Error != "" {
		return nil, errors.New(op.Error)
	}
	if op.Action == "" {
		op.Action = api // REST services: the proxy matches method and path, the CLI knows the name
	}
	return &op, nil
}

// queryFlatten writes a value in Query-protocol form: lists as
// Name.member.N (Name.N when flattened or in the EC2 protocol), structures as
// Name.Field.
func queryFlatten(form url.Values, name string, v any, flat bool) {
	switch x := v.(type) {
	case map[string]any:
		for _, k := range sortedKeys(x) {
			queryFlatten(form, name+"."+k, x[k], flat)
		}
	case []any:
		for i, e := range x {
			n := name + ".member." + strconv.Itoa(i+1)
			if flat {
				n = name + "." + strconv.Itoa(i+1)
			}
			queryFlatten(form, n, e, flat)
		}
	case bool:
		form.Set(name, strconv.FormatBool(x))
	case json.Number:
		form.Set(name, x.String())
	case nil:
	default:
		form.Set(name, fmt.Sprint(x))
	}
}

func scalarList(v any) []string {
	switch x := v.(type) {
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, fmt.Sprint(e))
		}
		return out
	case bool:
		return []string{strconv.FormatBool(x)}
	}
	return []string{fmt.Sprint(v)}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func escapePathKeepSlash(s string) string {
	parts := strings.Split(s, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// awscliCustomization classifies awscli commands that are not one API call,
// from the list the AWS API MCP server allows (core/parser/parser.py).
func awscliCustomization(svc, op string) CLIStep {
	reason := "aws " + svc + " " + op
	switch svc + " " + op {
	case "ecr get-login", "ecr get-login-password", "ecr-public get-login-password", "eks get-token",
		"rds generate-db-auth-token", "codeartifact login", "codecommit credential-helper", "cloudfront sign":
		return CLIStep{Class: classes.Credential, Reason: reason + " returns a credential"}
	case "datapipeline list-runs", "configservice get-status", "cloudtrail validate-logs", "emr describe-cluster",
		"gamelift get-game-session-log", "eks update-kubeconfig":
		return CLIStep{Class: classes.Read, Reason: reason + " only reads the account"}
	case "dlm create-default-role", "datapipeline create-default-roles", "emr create-default-roles",
		"emr-containers update-role-trust-policy":
		return CLIStep{Class: classes.Access, Reason: reason + " creates or changes IAM roles"}
	}
	if op == "wait" {
		return CLIStep{Class: classes.Read, Reason: reason + " polls until a resource reaches a state"}
	}
	return CLIStep{Class: classes.Unknown, Reason: reason + " is an awscli command Opfence does not classify"}
}

// awscliS3 maps the high-level aws s3 commands onto the API operations they
// make, as catalog/aws's S3 rules name them.
func awscliS3(args []string) ([]CLIStep, error) {
	if len(args) == 0 || args[0] == "help" {
		return []CLIStep{{Class: classes.Read, Reason: "help"}}, nil
	}
	cmd := args[0]
	var paths []string
	flags := map[string]string{}
	for i := 1; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			paths = append(paths, a)
			continue
		}
		name, val, has := strings.Cut(a[2:], "=")
		if !has && s3ValueFlags[name] && i+1 < len(args) {
			i++
			val = args[i]
		}
		flags[name] = val
	}
	_, recursive := flags["recursive"]
	s3op := func(action string, bucket, key string, headers map[string]string) CLIStep {
		h := map[string]any{}
		for k, v := range headers {
			if v != "" {
				h[k] = v
			}
		}
		a := map[string]any{"Bucket": bucket, "headers": h}
		if key != "" {
			a["Key"] = key
		}
		return CLIStep{Op: &Operation{Protocol: AWS, Service: "s3", Action: action, Args: a}}
	}
	acl := map[string]string{"x-amz-acl": flags["acl"]}
	for _, g := range strings.Split(flags["grants"], " ") {
		perm, who, ok := strings.Cut(g, "=")
		if !ok {
			continue
		}
		switch perm {
		case "read":
			acl["x-amz-grant-read"] = who
		case "full":
			acl["x-amz-grant-full-control"] = who
		case "readacl":
			acl["x-amz-grant-read-acp"] = who
		case "writeacl":
			acl["x-amz-grant-write-acp"] = who
		}
	}
	isS3 := func(p string) (bucket, key string, ok bool) {
		rest, found := strings.CutPrefix(p, "s3://")
		if !found {
			return "", "", false
		}
		bucket, key, _ = strings.Cut(rest, "/")
		return bucket, key, bucket != ""
	}
	switch cmd {
	case "ls":
		return []CLIStep{{Class: classes.Read, Reason: "aws s3 ls lists buckets or objects"}}, nil
	case "presign":
		return []CLIStep{{Class: classes.Credential, Reason: "aws s3 presign makes a URL that grants access"}}, nil
	case "mb", "rb", "website", "rm":
		if len(paths) != 1 {
			return nil, fmt.Errorf("aws s3 %s takes one s3:// path", cmd)
		}
		b, k, ok := isS3(paths[0])
		if !ok {
			return nil, fmt.Errorf("aws s3 %s needs an s3:// path", cmd)
		}
		switch cmd {
		case "mb":
			return []CLIStep{s3op("CreateBucket", b, "", nil)}, nil
		case "website":
			return []CLIStep{s3op("PutBucketWebsite", b, "", nil)}, nil
		case "rb":
			steps := []CLIStep{s3op("DeleteBucket", b, "", nil)}
			if _, force := flags["force"]; force {
				steps = append(steps, s3op("DeleteObjects", b, "", nil))
			}
			return steps, nil
		default: // rm
			if recursive || k == "" {
				return []CLIStep{s3op("DeleteObjects", b, "", nil)}, nil
			}
			return []CLIStep{s3op("DeleteObject", b, k, nil)}, nil
		}
	case "cp", "mv", "sync":
		if len(paths) != 2 {
			return nil, fmt.Errorf("aws s3 %s takes a source and a destination", cmd)
		}
		sb, sk, srcS3 := isS3(paths[0])
		db, dk, dstS3 := isS3(paths[1])
		var steps []CLIStep
		switch {
		case dstS3 && srcS3:
			steps = append(steps, s3op("CopyObject", db, dk, acl))
		case dstS3:
			steps = append(steps, s3op("PutObject", db, dk, acl))
		case srcS3:
			steps = append(steps, CLIStep{Class: classes.Read, Reason: "aws s3 " + cmd + " downloads from S3"})
		default:
			return nil, fmt.Errorf("aws s3 %s needs an s3:// path", cmd)
		}
		if cmd == "mv" && srcS3 {
			if recursive || sk == "" {
				steps = append(steps, s3op("DeleteObjects", sb, "", nil))
			} else {
				steps = append(steps, s3op("DeleteObject", sb, sk, nil))
			}
		}
		if _, del := flags["delete"]; cmd == "sync" && del && dstS3 {
			steps = append(steps, s3op("DeleteObjects", db, "", nil))
		}
		return steps, nil
	}
	return []CLIStep{{Class: classes.Unknown, Reason: "aws s3 " + cmd + " is not an aws s3 command Opfence classifies"}}, nil
}

// aws s3 options that take a value (awscli customizations/s3/subcommands.py).
var s3ValueFlags = map[string]bool{
	"acl": true, "grants": true, "include": true, "exclude": true, "sse": true, "sse-c": true, "sse-c-key": true,
	"sse-kms-key-id": true, "sse-c-copy-source": true, "sse-c-copy-source-key": true, "storage-class": true,
	"website-redirect": true, "content-type": true, "cache-control": true, "content-disposition": true,
	"content-encoding": true, "content-language": true, "expires": true, "source-region": true, "metadata": true,
	"metadata-directive": true, "expected-size": true, "request-payer": true, "expires-in": true,
	"index-document": true, "error-document": true, "page-size": true, "copy-props": true, "checksum-mode": true,
	"checksum-algorithm": true, "case-conflict": true,
}

// ShellWords splits a command line as Python's shlex.split does in POSIX
// mode, which is how the AWS API MCP server splits it: whitespace separates
// words, single quotes are literal, double quotes allow \" and \\, and a
// backslash outside quotes escapes the next character.
func ShellWords(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			inWord = true
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, errors.New("no closing quotation")
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
		case c == '"':
			inWord = true
			i++
			for ; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
					i++
				}
				cur.WriteByte(s[i])
			}
			if i >= len(s) {
				return nil, errors.New("no closing quotation")
			}
		case c == '\\':
			if i+1 >= len(s) {
				return nil, errors.New("no escaped character")
			}
			inWord = true
			i++
			cur.WriteByte(s[i])
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			inWord = true
			cur.WriteByte(c)
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out, nil
}

// AWSCLIOp describes an operation the AWS CLI can run, for checks that
// catalog rules are reachable from the CLI.
type AWSCLIOp struct {
	Action, Method, URI string
	// Keys are the top-level argument names the decoded request can carry;
	// Body and Headers the names under body and headers.
	Keys, Body, Headers map[string]bool
}

// AWSCLIOps lists the operations of the services the table has argument
// details for, by SigV4 signing name.
func AWSCLIOps(signing string) []AWSCLIOp {
	t, err := awscli()
	if err != nil {
		return nil
	}
	var out []AWSCLIOp
	for _, svc := range t.Services {
		if svc.Signing != signing {
			continue
		}
		for name, d := range svc.Detail {
			api := svc.Ops[name]
			if api == nil {
				continue
			}
			op := AWSCLIOp{Action: *api, Method: d.Method, URI: d.URI, Keys: map[string]bool{}, Body: map[string]bool{}, Headers: map[string]bool{}}
			for _, a := range d.Args {
				if a.Unread || a.Member == "" {
					continue
				}
				switch {
				case svc.Protocol == "json":
					op.Keys[a.Member] = true
				case svc.Protocol == "ec2":
					switch {
					case a.QueryName != "":
						op.Keys[a.QueryName] = true
					case a.LocationName != "":
						op.Keys[upperFirst(a.LocationName)] = true
					default:
						op.Keys[a.Member] = true
					}
				case svc.Protocol == "query":
					if a.LocationName != "" {
						op.Keys[a.LocationName] = true
					} else {
						op.Keys[a.Member] = true
					}
				default: // rest-json, rest-xml
					switch a.Location {
					case "header", "headers":
						op.Headers[strings.ToLower(a.LocationName)] = true
						op.Keys["headers"] = true
					case "querystring":
						op.Keys["query"] = true
						if signing == "s3" {
							op.Keys[a.LocationName] = true
						}
					case "uri":
						op.Keys[a.Member] = true
					default:
						op.Body[a.Member] = true
						op.Keys["body"] = true
						if signing == "s3" {
							op.Keys[a.Member] = true
						}
					}
				}
			}
			out = append(out, op)
		}
	}
	return out
}

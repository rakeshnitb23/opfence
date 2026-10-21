package catalog

import (
	"regexp"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/decode"
)

// Every catalog/aws rule can be reached by an AWS CLI command (through the
// AWS API MCP server's call_aws), and every argument its conditions and
// resource read can come from the command line. A rule the CLI path could
// not reach, or a condition it could not meet, would decide call_aws more
// loosely than the proxy decides the same request.
func TestAWSRulesReachableFromCLI(t *testing.T) {
	c, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	p := c.Provider("aws")
	if p == nil {
		t.Fatal("no aws provider")
	}
	sample := regexp.MustCompile(`\{[^{}]+\}`)
	ops := map[string][]decode.AWSCLIOp{}
	checked := 0
	for _, r := range p.Rules {
		m := r.Match.AWS
		if m == nil {
			continue
		}
		if _, ok := ops[m.Service]; !ok {
			ops[m.Service] = decode.AWSCLIOps(m.Service)
		}
		// Several CLI services can share a signing name and an action (rds,
		// neptune and docdb all sign as rds); an argument counts when any of
		// them supplies it.
		var found []decode.AWSCLIOp
		for _, op := range ops[m.Service] {
			switch {
			case m.Action != "" && op.Action == m.Action:
				found = append(found, op)
			case m.Action == "" && op.Method == m.Method && m.Template != nil:
				uri, _, _ := strings.Cut(op.URI, "?")
				if _, ok := m.Template.Match(sample.ReplaceAllString(uri, "x")); ok {
					found = append(found, op)
				}
			}
		}
		if len(found) == 0 {
			t.Errorf("%s: no AWS CLI operation runs %s %s%s %s", r.ID, m.Service, m.Action, m.Method, m.Path)
			continue
		}
		var args []string
		for _, w := range r.When {
			args = append(args, w.If.Arg)
		}
		if r.Resource != nil {
			args = append(args, r.Resource.Arg)
		}
		for _, a := range args {
			head, rest, _ := strings.Cut(a, ".")
			ok := m.Template != nil && strings.Contains(m.Path, "{"+head+"}") // a path parameter
			for _, op := range found {
				switch head {
				case "body":
					ok = ok || op.Body[strings.Split(rest, ".")[0]]
				case "headers":
					ok = ok || op.Headers[rest]
				default:
					ok = ok || op.Keys[head]
				}
			}
			if !ok {
				t.Errorf("%s: argument %s cannot come from the AWS CLI's %s arguments", r.ID, a, found[0].Action)
			}
		}
		checked++
	}
	if checked < 100 {
		t.Fatalf("checked %d rules", checked)
	}
}

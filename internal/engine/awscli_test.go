package engine

import (
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/catalog"
	"github.com/rakeshnitb23/opfence/internal/classes"
	"github.com/rakeshnitb23/opfence/internal/policy"
)

func callAWS(t *testing.T, user *policy.File, cmd any) Evaluation {
	t.Helper()
	c, err := catalog.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	e := New(c, policy.Resolve(user, nil))
	return e.EvaluateTool(c.Provider("aws-api-mcp"), "call_aws", map[string]any{"cli_command": cmd}).Evaluations[0]
}

func TestCallAWS(t *testing.T) {
	cases := []struct {
		cmd      any
		class    classes.Class
		decision classes.Decision
		resource string
		source   string
	}{
		{"aws s3api list-buckets", classes.Read, classes.Allow, "", "AWS s3 ListBuckets"},
		{"aws rds delete-db-instance --db-instance-identifier shop-db --skip-final-snapshot", classes.Irreversible, classes.Confirm, "shop-db", "aws.rds.delete-db-instance irreversible"},
		{"aws rds delete-db-instance --db-instance-identifier shop-db", classes.Delete, classes.Ask, "shop-db", "aws.rds.delete-db-instance delete"},
		{"aws secretsmanager get-secret-value --secret-id prod/db", classes.Credential, classes.Deny, "prod/db", "aws.secretsmanager"},
		// A list takes the strictest command, with its resource.
		{[]any{"aws s3api list-buckets", "aws dynamodb delete-table --table-name orders"}, classes.Irreversible, classes.Confirm, "orders", "AWS s3 ListBuckets"},
		// Unreadable parts keep the rule's own class.
		{"aws ec2 run-instances --cli-input-json file://x.json", classes.Irreversible, classes.Confirm, "", "rule class, for what Opfence cannot read"},
		{"not aws at all", classes.Irreversible, classes.Confirm, "", "unreadable command"},
		{[]any{"aws s3api list-buckets", 7.0}, classes.Irreversible, classes.Confirm, "", ""},
	}
	for _, c := range cases {
		ev := callAWS(t, nil, c.cmd)
		if ev.Class != c.class || ev.Decision != c.decision || ev.Resource != c.resource || !strings.Contains(ev.ClassSource, c.source) {
			t.Errorf("%v: %s %s resource %q (%s); want %s %s %q (%s)", c.cmd, ev.Class, ev.Decision, ev.Resource, ev.ClassSource, c.class, c.decision, c.resource, c.source)
		}
	}
}

// The aws provider's environments and rule overrides apply to commands run
// through call_aws, as they do to the same requests through the proxy.
func TestCallAWSPolicy(t *testing.T) {
	user := &policy.File{
		Environments: map[string]map[string]map[string][]string{
			policy.Development: {"aws": {"DBInstanceIdentifier": {"dev-db"}}},
		},
	}
	cmd := "aws rds delete-db-instance --db-instance-identifier dev-db --skip-final-snapshot"
	ev := callAWS(t, user, cmd)
	if ev.Environment != policy.Development || ev.Decision != classes.Ask {
		t.Fatalf("mapped dev database: %s %s (%s)", ev.Environment, ev.Decision, ev.EnvSource)
	}
	if ev := callAWS(t, user, strings.Replace(cmd, "dev-db", "prod-db", 1)); ev.Environment != policy.Production || ev.Decision != classes.Confirm {
		t.Fatalf("unmapped database: %s %s", ev.Environment, ev.Decision)
	}
	override := &policy.File{Rules: []policy.RuleOverride{{Rule: "aws.secretsmanager.*", Decision: classes.Ask}}}
	if ev := callAWS(t, override, "aws secretsmanager get-secret-value --secret-id x"); ev.Decision != classes.Ask {
		t.Fatalf("override on aws.secretsmanager.*: %s (%s)", ev.Decision, ev.DecisionSource)
	}
}

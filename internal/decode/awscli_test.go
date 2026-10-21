package decode

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

func TestShellWords(t *testing.T) {
	cases := []struct {
		in   string
		want []string
		bad  bool
	}{
		{"aws s3 ls", []string{"aws", "s3", "ls"}, false},
		{"  aws\ts3   ls  ", []string{"aws", "s3", "ls"}, false},
		{`aws ssm put-parameter --value 'a b "c"'`, []string{"aws", "ssm", "put-parameter", "--value", `a b "c"`}, false},
		{`aws x --v "a \"b\" \n c"`, []string{"aws", "x", "--v", `a "b" \n c`}, false},
		{`aws x --v a\ b`, []string{"aws", "x", "--v", "a b"}, false},
		{`aws x --v ''`, []string{"aws", "x", "--v", ""}, false},
		{`aws x --v 'a'"b"c`, []string{"aws", "x", "--v", "abc"}, false},
		{`aws x 'unterminated`, nil, true},
		{`aws x "unterminated`, nil, true},
		{`aws x \`, nil, true},
	}
	for _, c := range cases {
		got, err := ShellWords(c.in)
		if (err != nil) != c.bad || (!c.bad && !reflect.DeepEqual(got, c.want)) {
			t.Errorf("ShellWords(%q) = %q, %v; want %q (error %v)", c.in, got, err, c.want, c.bad)
		}
	}
}

// summary describes what AWSCLI returns: "svc Action" for operations, the
// class for direct steps.
func summary(t *testing.T, cmd string) []string {
	t.Helper()
	steps, err := AWSCLI(cmd)
	if err != nil {
		return []string{"error"}
	}
	var out []string
	for _, s := range steps {
		if s.Op != nil {
			out = append(out, s.Op.Service+" "+s.Op.Action)
		} else {
			out = append(out, string(s.Class))
		}
	}
	return out
}

func TestAWSCLIOperations(t *testing.T) {
	U, R, C, A := string(classes.Unknown), string(classes.Read), string(classes.Credential), string(classes.Access)
	cases := []struct {
		cmd  string
		want []string
	}{
		{"aws rds delete-db-instance --db-instance-identifier db --skip-final-snapshot", []string{"rds DeleteDBInstance"}},
		{"aws --region us-east-1 --profile p rds describe-db-instances", []string{"rds DescribeDBInstances"}},
		{"aws rds describe-db-instances --region=us-east-1 --output json --query 'DBInstances[].Endpoint'", []string{"rds DescribeDBInstances"}},
		{"aws rds describe-db-instances --region '*'", []string{"rds DescribeDBInstances"}},
		{"aws s3api delete-bucket --bucket b", []string{"s3 DeleteBucket"}},
		{"aws s3api get-object --bucket b --key k out.txt", []string{"s3 GetObject"}},
		{"aws lambda delete-function --function-name f", []string{"lambda DeleteFunction"}},
		{"aws route53 delete-hosted-zone --id Z1", []string{"route53 DeleteHostedZone"}},
		{"aws iam create-access-key --user-name bob", []string{"iam CreateAccessKey"}},
		{"aws dynamodb delete-table --table-name t", []string{"dynamodb DeleteTable"}},
		{"aws sqs delete-queue --queue-url https://q", []string{"sqs DeleteQueue"}},
		{"aws configservice describe-config-rules", []string{"config DescribeConfigRules"}},
		{"aws help", []string{R}},
		{"aws rds help", []string{R}},
		{"aws rds wait db-instance-available --db-instance-identifier db", []string{R}},
		{"aws ecr get-login-password", []string{C}},
		{"aws eks get-token --cluster-name c", []string{C}},
		{"aws rds generate-db-auth-token --hostname h --port 5432 --username u", []string{C}},
		{"aws emr create-default-roles", []string{A}},
		{"aws emr terminate-clusters --cluster-ids j-1", []string{U}},
		{"aws frobnicate do-it", []string{U}},
		{"aws rds frobnicate", []string{U}},
		{"aws rds describe-db-instances && aws s3 rb s3://b --force", []string{U}},
		{"aws configure set region x", []string{U}},
		{"ls -la", []string{"error"}},
		{"aws 'unterminated", []string{"error"}},
		// What cannot be read adds an unknown step.
		{"aws ec2 run-instances --cli-input-json file://x.json", []string{"ec2 RunInstances", U}},
		{"aws ec2 run-instances --image-id ami-1 --generate-cli-skeleton", []string{"ec2 RunInstances", U}},
		{"aws iam put-role-policy --role-name r --policy-name p --policy-document file://p.json", []string{"iam PutRolePolicy", U}},
		{"aws s3api delete-objects --bucket b --delete Objects=[{Key=a}]", []string{"s3 DeleteObjects", U}},
		{"aws rds delete-db-instance --db-instance-identifier db --frobnicate", []string{"rds DeleteDBInstance", U}},
		{"aws rds delete-db-instance --db-instance-identifier", []string{"rds DeleteDBInstance", U}},
		{"aws route53 delete-hosted-zone", []string{U}},
		// The high-level S3 commands.
		{"aws s3 ls", []string{R}},
		{"aws s3 ls s3://b --recursive", []string{R}},
		{"aws s3 presign s3://b/k --expires-in 600", []string{C}},
		{"aws s3 mb s3://b", []string{"s3 CreateBucket"}},
		{"aws s3 rb s3://b", []string{"s3 DeleteBucket"}},
		{"aws s3 rb s3://b --force", []string{"s3 DeleteBucket", "s3 DeleteObjects"}},
		{"aws s3 rm s3://b/k", []string{"s3 DeleteObject"}},
		{"aws s3 rm s3://b/prefix/ --recursive", []string{"s3 DeleteObjects"}},
		{"aws s3 rm s3://b", []string{"s3 DeleteObjects"}},
		{"aws s3 cp f.txt s3://b/f.txt", []string{"s3 PutObject"}},
		{"aws s3 cp s3://b/f.txt f.txt", []string{R}},
		{"aws s3 cp s3://a/f s3://b/f", []string{"s3 CopyObject"}},
		{"aws s3 mv s3://a/f s3://b/f", []string{"s3 CopyObject", "s3 DeleteObject"}},
		{"aws s3 mv s3://a/ s3://b/ --recursive", []string{"s3 CopyObject", "s3 DeleteObjects"}},
		{"aws s3 mv f s3://b/f", []string{"s3 PutObject"}},
		{"aws s3 sync . s3://b", []string{"s3 PutObject"}},
		{"aws s3 sync . s3://b --delete", []string{"s3 PutObject", "s3 DeleteObjects"}},
		{"aws s3 sync s3://b . --delete", []string{R}},
		{"aws s3 website s3://b --index-document index.html", []string{"s3 PutBucketWebsite"}},
		{"aws s3 cp a b", []string{"error"}},
		{"aws s3 frobnicate s3://b", []string{U}},
	}
	for _, c := range cases {
		if got := summary(t, c.cmd); !reflect.DeepEqual(got, c.want) {
			t.Errorf("AWSCLI(%q) = %q, want %q", c.cmd, got, c.want)
		}
	}
}

// The arguments come out in the shape the proxy's decoder gives the same
// request, which is what catalog/aws's conditions read.
func TestAWSCLIArgs(t *testing.T) {
	cases := []struct {
		cmd  string
		path string
		want any
	}{
		{"aws rds delete-db-instance --db-instance-identifier db --skip-final-snapshot", "SkipFinalSnapshot", "true"},
		{"aws rds delete-db-instance --db-instance-identifier db --no-skip-final-snapshot", "SkipFinalSnapshot", "false"},
		{"aws rds delete-db-instance --db-instance-identifier=db", "DBInstanceIdentifier", "db"},
		{"aws ssm get-parameter --name /x --with-decryption", "WithDecryption", true},
		{"aws ec2 terminate-instances --instance-ids i-1 i-2", "InstanceId", []any{"i-1", "i-2"}},
		{"aws ec2 terminate-instances --instance-ids i-1,i-2", "InstanceId", []any{"i-1", "i-2"}},
		{`aws ec2 terminate-instances --instance-ids '["i-1","i-2"]'`, "InstanceId", []any{"i-1", "i-2"}},
		{"aws dynamodb update-continuous-backups --table-name t --point-in-time-recovery-specification PointInTimeRecoveryEnabled=false",
			"PointInTimeRecoverySpecification", map[string]any{"PointInTimeRecoveryEnabled": "false"}},
		{`aws dynamodb update-continuous-backups --table-name t --point-in-time-recovery-specification '{"PointInTimeRecoveryEnabled": false}'`,
			"PointInTimeRecoverySpecification", map[string]any{"PointInTimeRecoveryEnabled": false}},
		{"aws s3api put-object --bucket b --key a/b.txt --acl public-read", "headers", map[string]any{"x-amz-acl": "public-read"}},
		{"aws s3api put-object --bucket b --key a/b.txt", "Key", "a/b.txt"},
		{"aws lambda create-function-url-config --function-name f --auth-type NONE", "body", map[string]any{"AuthType": "NONE"}},
		{"aws s3 cp f s3://b/k --acl public-read", "headers", map[string]any{"x-amz-acl": "public-read"}},
		{"aws s3 cp f s3://b/k --grants read=uri=http://acs.amazonaws.com/groups/global/AllUsers", "headers",
			map[string]any{"x-amz-grant-read": "uri=http://acs.amazonaws.com/groups/global/AllUsers"}},
	}
	for _, c := range cases {
		steps, err := AWSCLI(c.cmd)
		if err != nil || len(steps) == 0 || steps[0].Op == nil {
			t.Errorf("%s: %v %+v", c.cmd, err, steps)
			continue
		}
		got := steps[0].Op.Args[c.path]
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %s = %#v, want %#v", c.cmd, c.path, got, c.want)
		}
	}
	// Lambda's rules match method and path.
	steps, _ := AWSCLI("aws lambda create-function-url-config --function-name my-fn --qualifier live --auth-type NONE")
	if op := steps[0].Op; op.Method != "POST" || op.Path != "/2021-10-31/functions/my-fn/url" {
		t.Errorf("lambda request %s %s", op.Method, op.Path)
	}
}

// Every detailed operation's URI template names parameters an argument
// supplies, and every service has a signing name.
func TestAWSCLITable(t *testing.T) {
	tab, err := awscli()
	if err != nil {
		t.Fatal(err)
	}
	if AWSCLIVersion() == "" || len(tab.Services) < 400 {
		t.Fatalf("table from awscli %q has %d services", AWSCLIVersion(), len(tab.Services))
	}
	param := regexp.MustCompile(`\{([^{}+]+)\+?\}`)
	for name, svc := range tab.Services {
		if svc.Signing == "" || len(svc.Ops) == 0 {
			t.Errorf("%s: signing %q, %d operations", name, svc.Signing, len(svc.Ops))
		}
		for op, d := range svc.Detail {
			for _, m := range param.FindAllStringSubmatch(d.URI, -1) {
				found := false
				for _, a := range d.Args {
					if a.Location == "uri" && (a.LocationName == m[1] || (a.LocationName == "" && a.Member == m[1])) {
						found = true
					}
				}
				if !found {
					t.Errorf("%s %s: no argument supplies {%s} in %s", name, op, m[1], d.URI)
				}
			}
		}
	}
}

func FuzzAWSCLI(f *testing.F) {
	for _, s := range []string{"aws s3 ls", "aws rds delete-db-instance --db-instance-identifier db --skip-final-snapshot",
		"aws s3 sync . s3://b --delete", `aws dynamodb put-item --table-name t --item '{"a":{"S":"b"}}'`,
		"aws lambda invoke --function-name f out.json", "aws ec2 run-instances --tag-specifications ResourceType=instance,Tags=[{Key=a,Value=b}]"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		steps, err := AWSCLI(s)
		if err != nil {
			return
		}
		if len(steps) == 0 {
			t.Fatal("no steps")
		}
		for _, st := range steps {
			if st.Op == nil && !st.Class.Valid() {
				t.Fatalf("step without an operation or a class: %+v", st)
			}
			if st.Op != nil && (st.Op.Protocol != AWS || st.Op.Service == "" || strings.TrimSpace(st.Op.Action) == "") {
				t.Fatalf("operation %+v", st.Op)
			}
		}
	})
}

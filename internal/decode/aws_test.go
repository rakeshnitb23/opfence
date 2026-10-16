package decode

import (
	"reflect"
	"testing"
)

func TestNestQueryParams(t *testing.T) {
	got, err := nestQueryParams(map[string]any{
		"InstanceId.2": "i-2", "InstanceId.1": "i-1", "InstanceId.10": "i-10",
		"Tags.member.1.Key": "env", "Tags.member.1.Value": "prod",
		"ValuesToAdd.AttributeValue.1": "all", "Plain": "x", "1": "top", "a..b": "odd",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"InstanceId":  []any{"i-1", "i-2", "i-10"},
		"Tags":        []any{map[string]any{"Key": "env", "Value": "prod"}},
		"ValuesToAdd": map[string]any{"AttributeValue": []any{"all"}},
		"Plain":       "x", "1": "top", "a..b": "odd",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v", got)
	}
	for _, bad := range []map[string]any{{"A": "1", "A.1": "2"}, {"A.1": "1", "A.1.B": "2"}} {
		if _, err := nestQueryParams(bad); err == nil {
			t.Errorf("%v: want conflict error", bad)
		}
	}
}

package classes

import "testing"

func TestParseClass(t *testing.T) {
	for _, c := range All {
		got, err := ParseClass(string(c))
		if err != nil || got != c {
			t.Errorf("ParseClass(%q) = %q, %v", c, got, err)
		}
	}
	if _, err := ParseClass("destroy"); err == nil {
		t.Error("ParseClass accepted an unknown class")
	}
	if _, err := ParseClass(""); err == nil {
		t.Error("ParseClass accepted an empty class")
	}
}

func TestDecisionRoundTrip(t *testing.T) {
	for d := Allow; d <= Deny; d++ {
		b, err := d.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var back Decision
		if err := back.UnmarshalText(b); err != nil || back != d {
			t.Errorf("round trip %v: got %v, %v", d, back, err)
		}
	}
	if _, err := Decision(7).MarshalText(); err == nil {
		t.Error("marshalled an invalid decision")
	}
	var d Decision
	if err := d.UnmarshalText([]byte("maybe")); err == nil {
		t.Error("parsed an unknown decision")
	}
}

func TestStrictest(t *testing.T) {
	if got := Strictest(); got != Allow {
		t.Errorf("Strictest() = %v", got)
	}
	if got := Strictest(Ask, Allow, Confirm, Ask); got != Confirm {
		t.Errorf("got %v, want confirm", got)
	}
	if got := Strictest(Allow, Deny, Confirm); got != Deny {
		t.Errorf("got %v, want deny", got)
	}
}

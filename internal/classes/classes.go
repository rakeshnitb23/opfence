// Package classes defines Opfence's risk classes and decisions.
//
// Classes describe what an operation does; decisions describe what Opfence
// does about it. Classes have no order. Decisions are ordered from least to
// most strict, and combining several operations always takes the strictest
// decision.
package classes

import (
	"fmt"
	"strings"
)

// Class is the risk class of one operation.
type Class string

// The risk classes. See docs/ARCHITECTURE.md §3.1.
const (
	Read         Class = "read"         // no change to state
	Write        Class = "write"        // creates or changes state, recoverable
	Delete       Class = "delete"       // removes something that can be restored
	Irreversible Class = "irreversible" // data or resources gone for good
	Money        Class = "money"        // spends, refunds or moves money
	Credential   Class = "credential"   // creates, reveals or rotates secrets
	Access       Class = "access"       // changes who can see or do what
	Unknown      Class = "unknown"      // not classified, or the decoder could not be sure
)

// All lists every class in display order.
var All = []Class{Read, Write, Delete, Irreversible, Money, Credential, Access, Unknown}

// Valid reports whether c is a known class.
func (c Class) Valid() bool {
	for _, k := range All {
		if c == k {
			return true
		}
	}
	return false
}

// ParseClass parses a class name.
func ParseClass(s string) (Class, error) {
	c := Class(strings.TrimSpace(s))
	if !c.Valid() {
		return "", fmt.Errorf("unknown class %q (want one of %s)", s, joinClasses())
	}
	return c, nil
}

func joinClasses() string {
	names := make([]string, len(All))
	for i, c := range All {
		names[i] = string(c)
	}
	return strings.Join(names, ", ")
}

// Decision is what Opfence does with an operation.
type Decision int

// Decisions, from least to most strict.
const (
	Allow   Decision = iota // run it
	Ask                     // ask a human first
	Confirm                 // ask, and the human must type the resource name
	Deny                    // never run it
)

var decisionNames = [...]string{"allow", "ask", "confirm", "deny"}

func (d Decision) String() string {
	if d < Allow || d > Deny {
		return fmt.Sprintf("Decision(%d)", int(d))
	}
	return decisionNames[d]
}

// ParseDecision parses a decision name.
func ParseDecision(s string) (Decision, error) {
	s = strings.TrimSpace(s)
	for i, n := range decisionNames {
		if s == n {
			return Decision(i), nil
		}
	}
	return 0, fmt.Errorf("unknown decision %q (want allow, ask, confirm or deny)", s)
}

// MarshalText implements encoding.TextMarshaler.
func (d Decision) MarshalText() ([]byte, error) {
	if d < Allow || d > Deny {
		return nil, fmt.Errorf("invalid decision %d", int(d))
	}
	return []byte(d.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Decision) UnmarshalText(b []byte) error {
	v, err := ParseDecision(string(b))
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// Strictest returns the strictest of the given decisions, or Allow if none.
func Strictest(ds ...Decision) Decision {
	out := Allow
	for _, d := range ds {
		if d > out {
			out = d
		}
	}
	return out
}

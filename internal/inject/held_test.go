package inject

import (
	"errors"
	"strings"
	"testing"

	"github.com/rakeshnitb23/opfence/internal/catalog"
)

const envPath = "spec.template.spec.containers.env.value"

func heldService(t *testing.T, h *Held, object string) (body string, tokens []string) {
	t.Helper()
	resp := `{"metadata":{"name":"api","annotations":{"note":"x"}},"spec":{"template":{"spec":{"containers":[{"image":"gcr.io/p/api",` +
		`"env":[{"name":"DB_PASSWORD","value":"hunter2-\"quoted\"-<&>"},{"name":"PORT","value":"8080"},{"name":"EMPTY","value":""}]}]}}}}`
	out, res, err := Transform([]byte(resp), &catalog.Response{Hold: []string{envPath}}, Funcs{
		Hold: func(path, v string) (string, error) {
			tok, err := h.Hold("google-cloud-run", object, path, v)
			tokens = append(tokens, tok)
			return tok, err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Hits[envPath] != 3 || len(tokens) != 2 || strings.Contains(string(out), "hunter2") || strings.Contains(string(out), "8080") {
		t.Fatalf("held %d values, tokens %v: %s", res.Hits[envPath], tokens, out)
	}
	return string(out), tokens
}

func TestHeldRoundTrip(t *testing.T) {
	h := NewHeld()
	const obj = "/apis/serving.knative.dev/v1/namespaces/p/services/api"
	body, tokens := heldService(t, h, obj)
	// The same values read again get the same tokens.
	if again, tokens2 := heldService(t, h, obj); again != body || tokens2[0] != tokens[0] || h.Len() != 2 {
		t.Fatalf("second read: %v vs %v (%d held)", tokens2, tokens, h.Len())
	}
	if !strings.Contains(body, `"value":""`) {
		t.Errorf("an empty value should stay empty: %s", body)
	}

	// The client changes the image and writes the whole object back.
	write := strings.Replace(body, "gcr.io/p/api", "gcr.io/p/api:v2", 1)
	out, n, err := h.Restore("google-cloud-run", obj, []string{envPath}, []byte(write))
	if err != nil || n != 2 {
		t.Fatalf("restore: %d, %v", n, err)
	}
	want := `{"metadata":{"annotations":{"note":"x"},"name":"api"},"spec":{"template":{"spec":{"containers":[{"env":[{"name":"DB_PASSWORD","value":"hunter2-\"quoted\"-<&>"},` +
		`{"name":"PORT","value":"8080"},{"name":"EMPTY","value":""}],"image":"gcr.io/p/api:v2"}]}}}}`
	if string(out) != want {
		t.Fatalf("restored:\n%s\nwant\n%s", out, want)
	}
	// The values may move between variables of the same object: swapping
	// PORT's and DB_PASSWORD's tokens is still the same field.
	swapped := strings.Replace(strings.Replace(write, tokens[0], "TMP", 1), tokens[1], tokens[0], 1)
	swapped = strings.Replace(swapped, "TMP", tokens[1], 1)
	if _, n, err := h.Restore("google-cloud-run", obj, []string{envPath}, []byte(swapped)); err != nil || n != 2 {
		t.Fatalf("swapped: %d %v", n, err)
	}
	// A body without tokens is unchanged.
	if out, n, err := h.Restore("google-cloud-run", obj, []string{envPath}, []byte(`{"a":1}`)); err != nil || n != 0 || string(out) != `{"a":1}` {
		t.Fatalf("plain body: %s %d %v", out, n, err)
	}
}

func TestHeldRefusals(t *testing.T) {
	h := NewHeld()
	const obj = "/v2/projects/p/locations/l/services/api"
	body, tokens := heldService(t, h, obj)
	tok := tokens[0]
	cases := map[string]struct {
		provider, object string
		restore          []string
		body             string
	}{
		"another object":   {"google-cloud-run", "/v2/projects/p/locations/l/services/public-echo", []string{envPath}, body},
		"another provider": {"github", obj, []string{envPath}, body},
		"no restore path":  {"google-cloud-run", obj, nil, body},
		"other restore":    {"google-cloud-run", obj, []string{"spec.template.metadata.annotations"}, body},
		"moved to annotation": {"google-cloud-run", obj, []string{envPath, "metadata.annotations"},
			strings.Replace(body, `"note":"x"`, `"note":"`+tok+`"`, 1)},
		"moved outside":   {"google-cloud-run", obj, []string{envPath}, `{"description":"` + tok + `"}`},
		"inside a string": {"google-cloud-run", obj, []string{envPath}, strings.Replace(body, `"`+tok+`"`, `"x `+tok+`"`, 1)},
		"in a key":        {"google-cloud-run", obj, []string{envPath}, `{"` + tok + `":1}`},
		"escaped":         {"google-cloud-run", obj, []string{envPath}, strings.Replace(body, `"`+tok+`"`, `"\u006f`+tok[1:]+`"`, 1)},
		"unknown token":   {"google-cloud-run", obj, []string{envPath}, strings.Replace(body, tok, HeldPrefix+strings.Repeat("a", 26), 1)},
		"truncated token": {"google-cloud-run", obj, []string{envPath}, strings.Replace(body, tok, tok[:len(tok)-1], 1)},
		"not JSON":        {"google-cloud-run", obj, []string{envPath}, "value=" + tok},
		"two JSON values": {"google-cloud-run", obj, []string{envPath}, body + body},
	}
	for name, tc := range cases {
		out, _, err := h.Restore(tc.provider, tc.object, tc.restore, []byte(tc.body))
		if err == nil || !errors.Is(err, ErrHeld) || out != nil {
			t.Errorf("%s: %v, %s", name, err, out)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
}

func TestHeldLimit(t *testing.T) {
	h := NewHeld()
	for i := 0; i < MaxHeld; i++ {
		if _, err := h.Hold("p", "/o", "v", strings.Repeat("x", i%50)+string(rune('a'+i%26))+strings.Repeat("y", i/50)); err != nil {
			t.Fatal(err)
		}
	}
	if h.Len() != MaxHeld {
		t.Fatalf("%d held", h.Len())
	}
	if _, err := h.Hold("p", "/o", "v", "one more value"); err == nil {
		t.Fatal("held more than the limit")
	}
	tok, err := h.Hold("p", "/o", "v", "a") // already held: no new entry needed
	if err != nil || !strings.HasPrefix(tok, HeldPrefix) || len(tok) != heldTokenLen {
		t.Fatalf("%q %v", tok, err)
	}
}

func FuzzHeldRestore(f *testing.F) {
	h := NewHeld()
	tok, _ := h.Hold("p", "/o", "env.value", "secret-value")
	f.Add(`{"env":[{"value":"` + tok + `"}]}`)
	f.Add(`{"env":{"value":"` + tok + `","x":"` + tok + `"}}`)
	f.Fuzz(func(t *testing.T, body string) {
		out, n, err := h.Restore("p", "/o", []string{"env.value"}, []byte(body))
		if err != nil {
			return
		}
		// Whatever was swapped, no token is left and the value appears only
		// as often as tokens were swapped.
		if n > 0 && strings.Contains(string(out), tok) {
			t.Fatalf("token left in %s", out)
		}
		if strings.Count(string(out), "secret-value")-strings.Count(body, "secret-value") != n {
			t.Fatalf("swapped %d but the value count changed differently: %s -> %s", n, body, out)
		}
	})
}

// A ** step reaches the environment wherever an operation carries it, and
// a token held under a pattern may come back anywhere the pattern matches
// in the same object.
func TestHeldAnyDepth(t *testing.T) {
	const pat = "**.env.value"
	op := `{"name":"operations/1","done":true,"metadata":{"template":{"containers":[{"env":[{"name":"A","value":"a-secret"}]}]}},` +
		`"response":{"template":{"template":{"containers":[{"env":[{"name":"B","value":"b-secret"}]}]}}},"env":{"value":"top"},"note":{"value":"kept"}}`
	h := NewHeld()
	out, res, err := Transform([]byte(op), &catalog.Response{Hold: []string{pat}}, Funcs{
		Hold: func(path, v string) (string, error) { return h.Hold("run", "/v2/x", path, v) },
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"a-secret", "b-secret", `"top"`} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("%s left in %s", secret, out)
		}
	}
	if res.Hits[pat] != 3 || h.Len() != 3 || !strings.Contains(string(out), `"kept"`) || !strings.Contains(string(out), `"operations/1"`) {
		t.Fatalf("%d hits, %d held: %s", res.Hits[pat], h.Len(), out)
	}
	// Redact takes ** too.
	if out, _, err := Transform([]byte(op), &catalog.Response{Redact: []string{"**.env"}}, Funcs{}); err != nil ||
		strings.Contains(string(out), "secret") || strings.Contains(string(out), `"top"`) {
		t.Fatalf("redact: %s %v", out, err)
	}

	tok, _ := h.Hold("run", "/v2/x", pat, "a-secret")
	for _, body := range []string{
		`{"template":{"containers":[{"env":[{"name":"A","value":"` + tok + `"}]}]}}`,
		`{"env":{"value":"` + tok + `"}}`,
	} {
		if out, n, err := h.Restore("run", "/v2/x", []string{pat}, []byte(body)); err != nil || n != 1 || !strings.Contains(string(out), "a-secret") {
			t.Errorf("%s: %s %d %v", body, out, n, err)
		}
	}
	for _, body := range []string{
		`{"template":{"containers":[{"env":[{"name":"A","valueFrom":"` + tok + `"}]}]}}`,
		`{"annotations":{"value":"` + tok + `"}}`,
	} {
		if _, _, err := h.Restore("run", "/v2/x", []string{pat}, []byte(body)); err == nil {
			t.Errorf("%s: restored outside the pattern", body)
		}
	}
}

func TestPrefixMatch(t *testing.T) {
	cases := []struct {
		path, pat string
		want      bool
	}{
		{"a.b.c", "a.b", true}, {"a.b", "a.b.c", false}, {"x.env.value", "**.env.value", true},
		{"env.value", "**.env.value", true}, {"env.value.k", "**.env.value", true}, {"env.valueFrom", "**.env.value", false},
		{"a.env.b.value", "**.env.value", false}, {"a.x.b.c", "a.**.c", true}, {"a.c", "a.**.c", true}, {"a", "a.**.c", false},
	}
	for _, c := range cases {
		if got := under(strings.Split(c.path, "."), c.pat); got != c.want {
			t.Errorf("under(%s, %s) = %v", c.path, c.pat, got)
		}
	}
}

package approve

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rakeshnitb23/opfence/internal/classes"
)

// TestPhoneLive runs the phone channel against a real ntfy server, playing
// the phone itself: OPFENCE_NTFY_LIVE=https://ntfy.sh go test -run Live
// ./internal/approve. OPFENCE_NTFY_TOKEN sets an access token.
func TestPhoneLive(t *testing.T) {
	server := os.Getenv("OPFENCE_NTFY_LIVE")
	if server == "" {
		t.Skip("set OPFENCE_NTFY_LIVE to an ntfy server URL")
	}
	cfg := PhoneConfig{Server: server, Topic: NewTopic(), Reply: NewTopic(), Token: os.Getenv("OPFENCE_NTFY_TOKEN")}
	p := NewPhone(cfg, func(f string, a ...any) { t.Logf(f, a...) })
	b := NewBroker(30*time.Second, p)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Listen(ctx, b)

	// The "phone": a subscription to the push topic.
	events := make(chan map[string]any, 16)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cfg.WebURL()+"/json", nil)
	p.auth(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			var ev map[string]any
			if json.Unmarshal(sc.Bytes(), &ev) == nil && ev["event"] != "open" && ev["event"] != "keepalive" {
				events <- ev
			}
		}
	}()
	next := func() map[string]any {
		select {
		case ev := <-events:
			return ev
		case <-time.After(15 * time.Second):
			t.Fatal("no event on the push topic")
			return nil
		}
	}
	time.Sleep(time.Second) // let Listen connect

	res, _ := approveAsync(t, b, pendingFor("railway.service.delete", classes.Delete, classes.Ask, "svc-1", 1))
	ev := next()
	if ev["event"] != "message" || !strings.Contains(ev["message"].(string), "railway.service.delete") {
		t.Fatalf("push %v", ev)
	}
	var m phoneMessage
	raw, _ := json.Marshal(ev)
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	tap(t, m, "Approve")
	select {
	case a := <-res:
		if !a.Approved || a.Channel != "phone" {
			t.Fatalf("%+v", a)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the tap never reached the broker")
	}
	if ev := next(); ev["event"] != "message_delete" || ev["sequence_id"] != m2id(raw) {
		t.Fatalf("push not deleted: %v", ev)
	}

	// The round trip opfence phone setup checks.
	done := make(chan error, 1)
	go func() { done <- p.Test(ctx) }()
	ev = next()
	raw, _ = json.Marshal(ev)
	m = phoneMessage{}
	_ = json.Unmarshal(raw, &m)
	tap(t, m, "It works")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func m2id(raw []byte) string {
	var x struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(raw, &x)
	return x.ID
}

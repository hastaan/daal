package origin

import (
	"io"
	"net/http"
	"testing"
	"time"
)

func TestServeAndBlock(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetBody(ChannelSubscription, []byte("vless://abc@example/?type=tcp#test"))

	// Allow → 200 + body.
	resp, err := httpGet(s.URL(ChannelSubscription))
	if err != nil {
		t.Fatalf("allow get: %v", err)
	}
	if resp != "vless://abc@example/?type=tcp#test" {
		t.Fatalf("body=%q", resp)
	}

	// Drop → connection forcibly closed.
	s.Set(ChannelSubscription, StateDrop)
	if _, err := httpGet(s.URL(ChannelSubscription)); err == nil {
		t.Fatalf("expected error in drop state")
	}

	// Allow again.
	s.Set(ChannelSubscription, StateAllow)
	if _, err := httpGet(s.URL(ChannelSubscription)); err != nil {
		t.Fatalf("expected success after un-drop: %v", err)
	}
}

func httpGet(url string) (string, error) {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

package main

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestTelegramWebSettingsEncryptedAndTestMessage(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("TG_BOT_TOKEN", "")
	t.Setenv("TG_CHAT_ID", "")
	const token = "123456:private_bot_token_1234567890"
	calls := 0
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/bot"+token+"/sendMessage" {
			t.Error("incorrect Telegram request")
		}
		r.ParseForm()
		if r.Form.Get("chat_id") != "-100123456" || !strings.Contains(r.Form.Get("text"), "测试消息") {
			t.Error("incorrect chat or test message")
		}
		w.Write([]byte(`{"ok":true,"result":{"message_id":1}}`))
	}))
	defer upstream.Close()
	t.Setenv("TG_API_BASE_URL", upstream.URL)
	s := testServer(upstream.Client())
	dnsTestStore(t, s)
	h := newHandler(s)
	payload := `{"token":"` + token + `","chat_id":"-100123456","enabled":true}`
	if w := apiRequest(h, "POST", "/api/telegram/settings", payload); w.Code != 200 {
		t.Fatalf("save Telegram: %d %s", w.Code, w.Body.String())
	}
	raw, err := os.ReadFile(s.credentials.file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), token) {
		t.Fatal("Telegram token saved unencrypted")
	}
	w := apiRequest(h, "GET", "/api/telegram/settings", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), token) || !strings.Contains(w.Body.String(), "-100123456") {
		t.Fatal("Telegram status leaked token or lost chat ID")
	}
	if w := apiRequest(h, "POST", "/api/telegram/test", `{}`); w.Code != 200 {
		t.Fatalf("test Telegram: %d %s", w.Code, w.Body.String())
	}
	if calls != 1 {
		t.Fatal("test message not sent exactly once")
	}
	if w := apiRequest(h, "POST", "/api/telegram/settings", `{"token":"","chat_id":"-100123456","enabled":false}`); w.Code != 200 {
		t.Fatal("empty token should preserve existing token")
	}
	if w := apiRequest(h, "POST", "/api/telegram/test", `{}`); w.Code != 502 || calls != 1 {
		t.Fatal("disabled Telegram sent a message")
	}
	if w := apiRequest(h, "DELETE", "/api/telegram/settings", ""); w.Code != 200 {
		t.Fatal("remove Telegram settings failed")
	}
	if _, ok := s.credentials.token(telegramSettingsID); ok {
		t.Fatal("Telegram credentials not removed")
	}
}
func TestTelegramErrorsDoNotExposeToken(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "ci-admin")
	t.Setenv("TG_BOT_TOKEN", "private-telegram-token")
	t.Setenv("TG_CHAT_ID", "123")
	upstream := newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte(`{"ok":false,"description":"private-telegram-token"}`))
	}))
	defer upstream.Close()
	t.Setenv("TG_API_BASE_URL", upstream.URL)
	w := apiRequest(newHandler(testServer(upstream.Client())), "POST", "/api/telegram/test", `{}`)
	if w.Code != 502 || strings.Contains(w.Body.String(), "private-telegram-token") {
		t.Fatal("upstream Telegram error leaked bot token")
	}
}

package main

import (
	"errors"
	"strings"
	"testing"
)

func TestSafeProxyFailure(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"proxyconnect tcp: 407 Proxy Authentication Required", "代理认证失败"},
		{"context deadline exceeded", "连接超时"},
		{"dial tcp: connection refused", "连接被拒绝"},
		{"tls: certificate verification failed", "TLS"},
		{"lookup: no such host", "域名解析失败"},
		{"Get http://user:secret@example.com: unexpected EOF", "网络连接失败"},
	} {
		got := safeProxyFailure(errors.New(tc.input))
		if !strings.Contains(got, tc.want) || strings.Contains(got, "secret") {
			t.Fatalf("unsafe or incorrect classification: %s", got)
		}
	}
}

func TestProxySavePersistsEnabledTogether(t *testing.T) {
	store, err := initAccounts(t.TempDir()+"/credentials.enc", strings.Repeat("k", 40))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{credentials: store}
	if err := s.saveProxyConfig("account-a", "http://user:secret@proxy.example:8080"); err != nil {
		t.Fatal(err)
	}
	if !s.proxyEnabled("account-a") {
		t.Fatal("saved proxy not enabled")
	}
	if _, ok := s.proxyURL("account-b"); ok {
		t.Fatal("proxy leaked across accounts")
	}
	store.file = "/dev/null/invalid"
	if err := s.saveProxyConfig("account-a", "http://replacement.example:8080"); err == nil {
		t.Fatal("expected storage failure")
	}
	raw, _ := s.proxyURL("account-a")
	if raw != "http://user:secret@proxy.example:8080" {
		t.Fatal("failed save changed original configuration")
	}
}

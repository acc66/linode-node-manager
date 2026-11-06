package main

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestDomesticTCPRequiresUnambiguousResult(t *testing.T) {
	s := testServer(http.DefaultClient)
	dnsTestStore(t, s)
	if err := s.saveRootPassword("domestic-probe", 0, "probe", `{"host":"192.0.2.10","port":22,"user":"root","password":"test-password"}`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, output    string
		ok, unreachable bool
	}{
		{"open", "banner\nDOMESTIC_TCP_OPEN\n", true, false},
		{"closed", "DOMESTIC_TCP_CLOSED\n", false, true},
		{"missing marker", "bash: timeout: command not found", false, false},
		{"embedded marker", "unexpected: DOMESTIC_TCP_CLOSED", false, false},
		{"conflicting markers", "DOMESTIC_TCP_OPEN\nDOMESTIC_TCP_CLOSED\n", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s.sshRun = func(context.Context, string, string) (string, error) { return tc.output, nil }
			_, err := s.checkDomesticTCP(context.Background(), "192.0.2.20", 22)
			if (err == nil) != tc.ok || errors.Is(err, errDomesticTCPUnreachable) != tc.unreachable {
				t.Fatalf("unexpected classification: %v", err)
			}
		})
	}
}

func TestIPChangeRejectsOfflineTargetBeforeAPICalls(t *testing.T) {
	s := testServer(nil)
	if err := s.checkIPTarget(context.Background(), "legacy", Instance{ID: 7, Status: "offline"}); err == nil {
		t.Fatal("offline instance cannot verify a candidate IP before releasing the old IP")
	}
}

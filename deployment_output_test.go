package main

import (
	"strings"
	"testing"
)

func TestDeploymentOutputRedactsSplitSecrets(t *testing.T) {
	var updates []string
	writer := &deploymentOutput{secrets: []string{"private-secret", "root-private-secret-password"}, update: func(value string) { updates = append(updates, value) }}
	for _, chunk := range []string{"Starting root-private-", "secret-password backend ", "private-", "secret completed\n with more output"} {
		writer.Write([]byte(chunk))
	}
	result := writer.Result()
	if strings.Contains(result, "private-secret") || strings.Contains(result, "root-private-secret-password") || !strings.Contains(result, "[REDACTED]") {
		t.Fatalf("credential leaked in final result: %s", result)
	}
	for _, update := range updates {
		if strings.Contains(update, "private-secret") || strings.Contains(update, "root-private-") {
			t.Fatalf("credential leaked in streamed update: %s", update)
		}
	}
	if len(updates) == 0 {
		t.Fatal("no live updates published")
	}
}

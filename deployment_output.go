package main

import (
	"bytes"
	"os/exec"
	"sort"
	"strings"
	"sync"
)

type deploymentOutput struct {
	mu      sync.Mutex
	raw     bytes.Buffer
	secrets []string
	update  func(string)
}

func (w *deploymentOutput) redacted(raw string) string {
	ordered := append([]string(nil), w.secrets...)
	sort.Slice(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	for _, secret := range ordered {
		if secret != "" {
			raw = strings.ReplaceAll(raw, secret, "[REDACTED]")
		}
	}
	return raw
}
func (w *deploymentOutput) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.raw.Write(data)
	if w.update != nil {
		safe := w.redacted(w.raw.String())
		hold := 0
		for _, secret := range w.secrets {
			if len(secret) > hold {
				hold = len(secret)
			}
		}
		boundary := len(safe) - hold
		if boundary < 0 {
			boundary = 0
		}
		w.update(safe[:boundary])
	}
	return len(data), nil
}
func (w *deploymentOutput) Result() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.redacted(w.raw.String())
}
func runDeploymentCommand(cmd *exec.Cmd, secrets []string, update func(string)) (string, error) {
	output := &deploymentOutput{secrets: secrets, update: update}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	result := output.Result()
	if update != nil {
		update(result)
	}
	return result, err
}

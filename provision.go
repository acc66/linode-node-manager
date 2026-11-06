package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Catalog requests are read-only and use the selected account's credentials.
func (s *Server) catalog(w http.ResponseWriter, r *http.Request) {
	paths := map[string]string{"regions": "/regions", "types": "/linode/types", "images": "/images"}
	path, ok := paths[r.PathValue("kind")]
	if !ok {
		fail(w, 404, "Unknown catalog")
		return
	}
	account := r.URL.Query().Get("account_id")
	if account == "" {
		fail(w, 400, "Select a Linode account first")
		return
	}
	if _, err := s.accountToken(account); err != nil {
		fail(w, 400, "Unknown or unconfigured Linode account")
		return
	}
	items := []json.RawMessage{}
	for page := 1; page <= 100; page++ {
		b, status, err := s.linodeFor(r.Context(), account, "GET", fmt.Sprintf("%s?page_size=100&page=%d", path, page), nil)
		if err != nil {
			fail(w, 502, "Linode catalog unavailable")
			return
		}
		if status != 200 {
			fail(w, 502, fmt.Sprintf("Linode catalog HTTP %d; check API permissions", status))
			return
		}
		var data struct {
			Data  []json.RawMessage `json:"data"`
			Pages int               `json:"pages"`
		}
		if json.Unmarshal(b, &data) != nil {
			fail(w, 502, "Invalid Linode catalog response")
			return
		}
		items = append(items, data.Data...)
		if page >= data.Pages {
			send(w, 200, map[string]any{"data": items})
			return
		}
	}
	fail(w, 502, "Linode catalog exceeds pagination limit")
}
func linodeCreateError(body []byte, rootPass, apiToken string) string {
	var response struct {
		Errors []struct {
			Field  string `json:"field"`
			Reason string `json:"reason"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &response) != nil || len(response.Errors) == 0 {
		return "Linode API returned an error without a readable reason"
	}
	messages := make([]string, 0, len(response.Errors))
	for _, issue := range response.Errors {
		reason := strings.TrimSpace(issue.Reason)
		if rootPass != "" {
			reason = strings.ReplaceAll(reason, rootPass, "[redacted]")
		}
		if apiToken != "" {
			reason = strings.ReplaceAll(reason, apiToken, "[redacted]")
		}
		reason = strings.Map(func(r rune) rune {
			if r < 32 || r == 127 {
				return ' '
			}
			return r
		}, reason)
		if len(reason) > 300 {
			reason = reason[:300]
		}
		field := strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '[' || r == ']' {
				return r
			}
			return -1
		}, strings.TrimSpace(issue.Field))
		if reason == "" {
			continue
		}
		if field != "" {
			messages = append(messages, field+": "+reason)
		} else {
			messages = append(messages, reason)
		}
	}
	if len(messages) == 0 {
		return "Linode API returned an error without a readable reason"
	}
	if len(messages) > 5 {
		messages = messages[:5]
	}
	return strings.Join(messages, "; ")
}

func validLinodeLabel(label string) bool {
	if len(label) < 3 || len(label) > 64 || label[0] < 'A' || label[0] > 'Z' && label[0] < 'a' || label[0] > 'z' {
		return false
	}
	last := label[len(label)-1]
	if !(last >= 'A' && last <= 'Z' || last >= 'a' && last <= 'z' || last >= '0' && last <= '9') {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
		if i > 0 && (c == '-' && label[i-1] == '-' || c == '_' && label[i-1] == '_' || c == '.' && label[i-1] == '.') {
			return false
		}
	}
	return true
}

func (s *Server) createInstance(w http.ResponseWriter, r *http.Request) {
	account := r.URL.Query().Get("account_id")
	if account == "" {
		fail(w, 400, "Select a Linode account first")
		return
	}
	if _, err := s.accountToken(account); err != nil {
		fail(w, 400, "Unknown or unconfigured Linode account")
		return
	}
	var in struct {
		Label        string `json:"label"`
		Region       string `json:"region"`
		Type         string `json:"type"`
		Image        string `json:"image"`
		RootPass     string `json:"root_pass"`
		Confirm      bool   `json:"confirm"`
		OpenAllPorts *bool  `json:"open_all_ports"`
		AliyunCheck  bool   `json:"aliyun_check"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		fail(w, 400, "Invalid create request")
		return
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		fail(w, 400, "Expected one JSON object")
		return
	}
	in.Label = strings.TrimSpace(in.Label)
	if !in.Confirm {
		fail(w, 400, "Confirm creation and billing first")
		return
	}
	if !validLinodeLabel(in.Label) {
		fail(w, 400, "Linode 名称不能包含中文；必须以英文字母开头和字母/数字结尾，只能包含英文、数字、短横线、下划线和点，长度 3 至 64 位")
		return
	}
	if in.Region == "" || in.Type == "" || in.Image == "" {
		fail(w, 400, "请选择地区、套餐和系统镜像")
		return
	}
	if len(in.RootPass) < 12 || len(in.RootPass) > 128 {
		fail(w, 400, "Root password must be 12-128 characters; Linode also checks password strength")
		return
	}
	if s.credentials == nil {
		fail(w, 503, "Configure ACCOUNT_ENCRYPTION_KEY before creating instances so root passwords can be saved encrypted")
		return
	}
	if in.AliyunCheck && !s.chinaProbeConfigured("aliyun") {
		fail(w, 400, "请先在国内探测中配置阿里云 SSH 探测机")
		return
	}
	openAll := in.OpenAllPorts == nil || *in.OpenAllPorts
	data := map[string]any{"label": in.Label, "region": in.Region, "type": in.Type, "image": in.Image, "root_pass": in.RootPass, "booted": true}
	if openAll {
		if err := s.openNetworkConfig(r.Context(), account, data); err != nil {
			fail(w, 502, err.Error())
			return
		}
	}
	payload, _ := json.Marshal(data)
	b, status, err := s.linodeFor(r.Context(), account, "POST", "/linode/instances", bytes.NewReader(payload))
	if err != nil {
		fail(w, 502, "Creation result unknown. Refresh the instance list before retrying to avoid duplicate billing.")
		return
	}
	if status != 200 && status != 201 {
		// Expose only Linode's safe field/reason pair; never forward raw JSON.
		apiStatus := 502
		if status >= 400 && status < 500 {
			apiStatus = status
		}
		token, _ := s.accountToken(account)
		fail(w, apiStatus, fmt.Sprintf("Linode create HTTP %d: %s", status, linodeCreateError(b, in.RootPass, token)))
		return
	}
	var inst Instance
	if json.Unmarshal(b, &inst) != nil || inst.ID <= 0 {
		fail(w, 502, "Creation result unknown. Refresh the instance list before retrying.")
		return
	}
	inst.AccountID = account
	inst.OpenAllPorts = openAll
	warning := ""
	if err := s.saveRootPassword(account, inst.ID, inst.Label, in.RootPass); err != nil {
		warning = "Instance created, but saving its password failed. Keep the password you entered; do not create again."
	} else {
		inst.PasswordSaved = true
	}
	if openAll {
		if err := s.saveRootPassword("open-ports-"+account, inst.ID, inst.Label, "true"); err != nil {
			warning += " 服务器已创建并且云防火墙不绑定，但全端口配置状态未保存。"
		}
	}
	enabled, _ := r.Context().Value(proxyContextKey{}).(bool)
	bootJob := ""
	if inst.PasswordSaved {
		bootJob = s.queueBootTuningWithCheck(account, inst.ID, enabled, in.AliyunCheck)
	}
	send(w, 201, struct {
		Instance
		Warning string `json:"warning,omitempty"`
		BootJob string `json:"boot_job_id,omitempty"`
	}{inst, warning, bootJob})
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type TelegramSettings struct {
	Token   string `json:"token"`
	ChatID  string `json:"chat_id"`
	Enabled bool   `json:"enabled"`
}

const telegramSettingsID = "telegram-settings/0"

func (s *Server) telegramSettings() (TelegramSettings, string, error) {
	if s.credentials != nil {
		if raw, ok := s.credentials.token(telegramSettingsID); ok {
			var config TelegramSettings
			if json.Unmarshal([]byte(raw), &config) != nil {
				return config, "saved", errors.New("Telegram 配置损坏，请重新保存")
			}
			return config, "saved", nil
		}
	}
	token, chat := os.Getenv("TG_BOT_TOKEN"), os.Getenv("TG_CHAT_ID")
	return TelegramSettings{Token: token, ChatID: chat, Enabled: token != "" && chat != ""}, "env", nil
}
func validTelegramChat(chat string) bool {
	if strings.HasPrefix(chat, "@") && len(chat) > 1 {
		for _, c := range chat[1:] {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
				return false
			}
		}
		return true
	}
	n, err := strconv.ParseInt(chat, 10, 64)
	return err == nil && n != 0
}
func (s *Server) telegramSettingsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		config, source, err := s.telegramSettings()
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		send(w, 200, map[string]any{"configured": config.Token != "" && config.ChatID != "", "chat_id": config.ChatID, "enabled": config.Enabled, "source": source})
		return
	case "POST":
		var config TelegramSettings
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&config) != nil {
			fail(w, 400, "Telegram 配置格式无效")
			return
		}
		config.Token = strings.TrimSpace(config.Token)
		config.ChatID = strings.TrimSpace(config.ChatID)
		if config.Token == "" {
			old, _, err := s.telegramSettings()
			if err != nil {
				fail(w, 400, err.Error())
				return
			}
			config.Token = old.Token
		}
		pieces := strings.SplitN(config.Token, ":", 2)
		valid := false
		if len(pieces) == 2 && len(pieces[1]) >= 20 {
			if id, err := strconv.ParseInt(pieces[0], 10, 64); err == nil && id > 0 {
				valid = true
			}
			for _, c := range pieces[1] {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
					valid = false
				}
			}
		}
		if !valid || !validTelegramChat(config.ChatID) {
			fail(w, 400, "请填写有效的 Bot Token 与 Chat ID（支持群组负数 ID 或 @频道用户名）")
			return
		}
		raw, _ := json.Marshal(config)
		if err := s.saveRootPassword("telegram-settings", 0, "Telegram", string(raw)); err != nil {
			fail(w, 500, "无法加密保存 Telegram 配置")
			return
		}
		send(w, 200, map[string]bool{"saved": true})
		return
	case "DELETE":
		if s.credentials != nil {
			if _, ok := s.credentials.token(telegramSettingsID); ok {
				if err := s.credentials.remove(telegramSettingsID); err != nil {
					fail(w, 500, "无法移除 Telegram 配置")
					return
				}
			}
		}
		send(w, 200, map[string]bool{"deleted": true})
		return
	default:
		fail(w, 405, "Method not allowed")
	}
}
func (s *Server) sendTelegram(ctx context.Context, message string) error {
	config, _, err := s.telegramSettings()
	if err != nil {
		return err
	}
	if !config.Enabled || config.Token == "" || config.ChatID == "" {
		return errors.New("Telegram 提醒未启用或配置不完整")
	}
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(env("TG_API_BASE_URL", "https://api.telegram.org"), "/")+"/bot"+config.Token+"/sendMessage", strings.NewReader(url.Values{"chat_id": {config.ChatID}, "text": {message}}.Encode()))
	if err != nil {
		return errors.New("Telegram 请求参数无效")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := *s.client
	client.Jar = nil
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("Telegram 网络连接失败")
	}
	defer resp.Body.Close()
	var result struct {
		OK bool `json:"ok"`
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Telegram API HTTP %d，请检查 Token、Chat ID 和机器人权限", resp.StatusCode)
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result) != nil || !result.OK {
		return errors.New("Telegram 未确认发送成功，请检查机器人和聊天权限")
	}
	return nil
}
func (s *Server) telegramTestAPI(w http.ResponseWriter, r *http.Request) {
	if err := s.sendTelegram(r.Context(), "✅ Linode 节点管理：Telegram 测试消息发送成功。"); err != nil {
		fail(w, 502, err.Error())
		return
	}
	send(w, 200, map[string]string{"message": "测试消息已发送，请在 Telegram 查看"})
}

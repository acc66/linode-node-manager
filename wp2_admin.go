package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

const wp2SessionID = "wp2-session/0"

type wp2Session struct {
	Base    string         `json:"base"`
	Cookies []*http.Cookie `json:"cookies"`
}

var errWP2Expired = errors.New("wp2 登录已过期或没有管理员权限，请重新连接")

func wp2Base() (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(env("WP2_BASE_URL", ""), "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("请配置有效的 HTTPS WP2_BASE_URL")
	}
	return u, nil
}
func (s *Server) loadWP2Session() (*wp2Session, error) {
	if s.credentials == nil {
		return nil, nil
	}
	raw, ok := s.credentials.token(wp2SessionID)
	if !ok {
		return nil, nil
	}
	var session wp2Session
	if json.Unmarshal([]byte(raw), &session) != nil {
		return nil, errors.New("wp2 会话数据无效，请断开后重新连接")
	}
	base, err := wp2Base()
	if err != nil {
		return nil, err
	}
	if session.Base != base.String() {
		return nil, errors.New("wp2 地址已变更，请断开后重新连接")
	}
	return &session, nil
}
func (s *Server) wp2Client(session *wp2Session) *http.Client {
	client := *s.client
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(session.Base)
	jar.SetCookies(u, session.Cookies)
	client.Jar = jar
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &client
}
func wp2Form(ctx context.Context, client *http.Client, target string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return client.Do(req)
}
func (s *Server) adminWP2Nodes(ctx context.Context, session *wp2Session) ([]map[string]any, error) {
	client := s.wp2Client(session)
	nodes := []map[string]any{}
	for start := 0; start < 100000; start += 100 {
		form := url.Values{"draw": {"1"}, "start": {fmt.Sprint(start)}, "length": {"100"}, "search[value]": {""}, "order[0][column]": {"0"}, "order[0][dir]": {"asc"}, "columns[0][data]": {"id"}}
		resp, err := wp2Form(ctx, client, session.Base+"/admin/node/ajax", form)
		if err != nil {
			return nil, errors.New("无法连接 wp2 管理接口")
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			resp.Body.Close()
			return nil, errWP2Expired
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("wp2 管理接口 HTTP %d", resp.StatusCode)
		}
		var result struct {
			Data []struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
				Sort any    `json:"sort"`
				IP   string `json:"node_ip"`
			} `json:"data"`
			Total *int `json:"recordsFiltered"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&result)
		resp.Body.Close()
		if err != nil || result.Total == nil {
			return nil, errors.New("wp2 未返回管理节点列表，请重新连接并确认管理员权限")
		}
		for _, n := range result.Data {
			if n.ID <= 0 {
				return nil, errors.New("wp2 节点 ID 无效")
			}
			nodes = append(nodes, map[string]any{"id": n.ID, "name": n.Name, "sort": n.Sort, "node_ip": n.IP, "node_status": "unknown", "status_source": "wp2 admin listing; no heartbeat verification"})
		}
		if start+len(result.Data) >= *result.Total {
			return nodes, nil
		}
		if len(result.Data) == 0 {
			return nil, errors.New("wp2 节点分页数据不完整")
		}
	}
	return nil, errors.New("wp2 节点超过分页上限")
}
func (s *Server) wp2SessionAPI(w http.ResponseWriter, r *http.Request) {
	s.wp2Mu.Lock()
	defer s.wp2Mu.Unlock()
	switch r.Method {
	case "GET":
		session, err := s.loadWP2Session()
		if err != nil {
			send(w, 200, map[string]any{"connected": false, "message": err.Error()})
			return
		}
		send(w, 200, map[string]any{"connected": session != nil})
		return
	case "DELETE":
		if s.credentials != nil {
			if _, ok := s.credentials.token(wp2SessionID); ok {
				if err := s.credentials.remove(wp2SessionID); err != nil {
					fail(w, 500, "无法删除保存的 wp2 会话")
					return
				}
			}
		}
		send(w, 200, map[string]bool{"connected": false})
		return
	case "POST":
		if s.credentials == nil {
			fail(w, 503, "请配置 ACCOUNT_ENCRYPTION_KEY，以加密保存登录会话")
			return
		}
		base, err := wp2Base()
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		var in struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			Code     string `json:"code"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in) != nil || strings.TrimSpace(in.Email) == "" || in.Password == "" {
			fail(w, 400, "请输入 wp2 管理员邮箱和密码")
			return
		}
		session := &wp2Session{Base: base.String()}
		client := s.wp2Client(session)
		resp, err := wp2Form(r.Context(), client, session.Base+"/auth/login", url.Values{"email": {strings.TrimSpace(in.Email)}, "passwd": {in.Password}, "code": {in.Code}, "remember_me": {"1"}})
		if err != nil {
			fail(w, 502, "无法连接 wp2 登录接口")
			return
		}
		var result struct {
			Ret int    `json:"ret"`
			Msg string `json:"msg"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result)
		session.Cookies = resp.Cookies()
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			fail(w, 502, "wp2 登录响应异常")
			return
		}
		if result.Ret == 2 {
			fail(w, 409, "该账户启用了两步验证，请填写 6 位动态码后重试")
			return
		}
		if result.Ret != 1 {
			if strings.Contains(result.Msg, "验证") {
				fail(w, 409, "wp2 要求验证码验证，当前连接表单无法完成网页验证码；请在 wp2 完成验证后使用其他连接方式")
			} else {
				fail(w, 400, "wp2 登录失败，请检查邮箱、密码和动态码")
			}
			return
		}
		if len(session.Cookies) == 0 {
			fail(w, 502, "wp2 登录没有返回会话 Cookie")
			return
		}
		if _, err := s.adminWP2Nodes(r.Context(), session); err != nil {
			fail(w, 409, err.Error())
			return
		}
		raw, _ := json.Marshal(session)
		if err := s.saveRootPassword("wp2-session", 0, session.Base, string(raw)); err != nil {
			fail(w, 500, "无法加密保存 wp2 会话")
			return
		}
		send(w, 200, map[string]bool{"connected": true})
		return
	default:
		fail(w, 405, "Method not allowed")
	}
}

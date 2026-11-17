package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type proxyEgressBatchResult struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Address   string           `json:"address"`
	IP        string           `json:"ip,omitempty"`
	Available bool             `json:"available"`
	Conflicts []egressConflict `json:"conflicts,omitempty"`
	Error     string           `json:"error,omitempty"`
}

func (s *Server) proxyPoolEgressBatchAPI(w http.ResponseWriter, r *http.Request) {
	if s.credentials == nil {
		fail(w, http.StatusServiceUnavailable, "代理加密存储未配置")
		return
	}
	var in struct {
		AccountID string   `json:"account_id"`
		IDs       []string `json:"ids"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF {
		fail(w, http.StatusBadRequest, "批量出口检测请求无效")
		return
	}
	if in.AccountID == "" || len(in.IDs) == 0 || len(in.IDs) > 50 {
		fail(w, http.StatusBadRequest, "请选择账号和 1-50 个代理进行检测")
		return
	}
	if _, err := s.accountToken(in.AccountID); err != nil {
		fail(w, http.StatusBadRequest, "账号不存在")
		return
	}
	entries := s.proxyPool()
	byID := make(map[string]poolProxy, len(entries))
	for _, entry := range entries {
		byID[entry.ID] = entry
	}
	results := make([]proxyEgressBatchResult, len(in.IDs))
	seen := map[string]bool{}
	for i, id := range in.IDs {
		entry, ok := byID[id]
		if !ok || id == "" || seen[id] {
			fail(w, http.StatusBadRequest, "代理列表含无效或重复 ID，请刷新后重试")
			return
		}
		seen[id] = true
		results[i] = proxyEgressBatchResult{ID: entry.ID, Name: entry.Name}
	}

	jobs := make(chan int)
	workerCount := min(8, len(results))
	var wg sync.WaitGroup
	for worker := 0; worker < workerCount; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				entry := byID[in.IDs[index]]
				result := proxyEgressBatchResult{ID: entry.ID, Name: entry.Name}
				store := s.credentials
				store.mu.RLock()
				endpoint, endpointErr := proxyEndpointLocked(store, entry.URL)
				store.mu.RUnlock()
				if endpointErr != nil {
					result.Error = "代理地址无效，请检查配置"
					results[index] = result
					continue
				}
				result.Address = endpoint
				ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
				ip, err := s.lookupEgress(ctx, entry.URL)
				cancel()
				if err != nil {
					result.Error = "出口检测失败：" + safeProxyFailure(err)
					results[index] = result
					continue
				}
				parsed := net.ParseIP(strings.TrimSpace(ip))
				if parsed == nil || !parsed.IsGlobalUnicast() || parsed.IsPrivate() {
					result.Error = "未返回有效公网出口 IP"
					results[index] = result
					continue
				}
				result.IP = parsed.String()
				if current, exists := s.poolURL(entry.ID); !exists || current != entry.URL {
					result.Error = "检测期间代理资料已变化，请重试"
					results[index] = result
					continue
				}
				conflicts, conflictErr := s.egressConflicts(result.IP, in.AccountID)
				if conflictErr != nil {
					result.Error = conflictErr.Error()
				} else {
					result.Conflicts = conflicts
					result.Available = len(conflicts) == 0
				}
				results[index] = result
			}
		}()
	}
	for i := range results {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	send(w, http.StatusOK, map[string]any{"results": results})
}

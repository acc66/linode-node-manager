package main

import (
 "context"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "testing"
)

func TestEncryptedAccountStore(t *testing.T){
 path:=filepath.Join(t.TempDir(),"accounts.enc")
 key:=strings.Repeat("k",48)
 store,err:=initAccounts(path,key);if err!=nil{t.Fatal(err)}
 one,err:=store.add("香港账号",strings.Repeat("a",64));if err!=nil{t.Fatal(err)}
 two,err:=store.add("新加坡账号",strings.Repeat("b",64));if err!=nil{t.Fatal(err)}
 if one.ID==two.ID{t.Fatal("account IDs collided")}
 raw,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 if strings.Contains(string(raw),strings.Repeat("a",64))||strings.Contains(string(raw),"香港账号"){t.Fatal("account secrets or metadata stored in plaintext")}
 if st,err:=os.Stat(path);err!=nil||st.Mode().Perm()!=0600{t.Fatalf("store permissions %v %v",st,err)}
 reloaded,err:=initAccounts(path,key);if err!=nil{t.Fatal(err)}
 if got,ok:=reloaded.token(one.ID);!ok||got!=strings.Repeat("a",64){t.Fatal("reloaded first account token failed")}
 if got,ok:=reloaded.token(two.ID);!ok||got!=strings.Repeat("b",64){t.Fatal("reloaded second account token failed")}
 if _,err:=initAccounts(path,strings.Repeat("x",40));err==nil{t.Fatal("wrong encryption key must fail closed")}
 if err:=reloaded.remove(one.ID);err!=nil{t.Fatal(err)}
 if _,ok:=reloaded.token(one.ID);ok{t.Fatal("deleted account still exists")}
 final,err:=initAccounts(path,key);if err!=nil{t.Fatal(err)}
 if len(final.list())!=1{t.Fatalf("expected one persisted account, got %d",len(final.list()))}
}
func TestMultiAccountAPIsIsolation(t *testing.T){
 t.Setenv("ADMIN_TOKEN","ci-admin")
 t.Setenv("LINODE_TOKEN","")
 t.Setenv("WP2_BASE_URL","https://wp2.invalid")
 t.Setenv("WP2_API_TOKEN","fake-wp2-token")
 store,err:=initAccounts(filepath.Join(t.TempDir(),"accounts.enc"),strings.Repeat("k",40));if err!=nil{t.Fatal(err)}
 first,_:=store.add("account-a",strings.Repeat("a",64))
 second,_:=store.add("account-b",strings.Repeat("b",64))
 var mu sync.Mutex
 actions:=map[string][]string{}
 upstream:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  token:=strings.TrimPrefix(r.Header.Get("Authorization"),"Bearer ")
  if token!=strings.Repeat("a",64)&&token!=strings.Repeat("b",64){t.Errorf("wrong auth token")}
  mu.Lock();actions[token]=append(actions[token],r.Method+" "+r.URL.Path);mu.Unlock()
  w.Header().Set("Content-Type","application/json")
  if r.Method=="GET"&&r.URL.Path=="/v4/linode/instances"{_,_=w.Write([]byte(`{"pages":1,"data":[{"id":7,"label":"same-id","status":"running","ipv4":["8.8.8.8"]}]}`));return}
  if r.Method=="GET"&&r.URL.Path=="/v4/linode/instances/7"{_,_=w.Write([]byte(`{"id":7,"label":"same-id","status":"running","ipv4":["8.8.8.8"]}`));return}
  if r.Method=="POST"&&r.URL.Path=="/v4/linode/instances/7/reboot"{_,_=w.Write([]byte(`{"ok":true}`));return}
  http.Error(w,"not found",404)
 }))
 defer upstream.Close()
 t.Setenv("LINODE_API_BASE_URL",upstream.URL+"/v4")
 s:=testServer(upstream.Client());s.accounts=store;s.accountStatus=map[string]Snapshot{}
 h:=newHandler(s)
 listing:=apiRequest(h,"GET","/api/accounts","")
 if listing.Code!=200||strings.Contains(listing.Body.String(),strings.Repeat("a",64)){t.Fatalf("account listing exposed credential or failed: %d %s",listing.Code,listing.Body.String())}
 for _,a:=range []ManagedAccount{first,second}{
  w:=apiRequest(h,"GET","/api/instances?account_id="+a.ID,"")
  if w.Code!=200{t.Fatalf("listing status %d %s",w.Code,w.Body.String())}
  var data struct{Instances []Instance `json:"instances"`}
  if err:=json.Unmarshal(w.Body.Bytes(),&data);err!=nil||len(data.Instances)!=1||data.Instances[0].AccountID!=a.ID{t.Fatalf("wrong account mapping: %+v %v",data,err)}
  w=apiRequest(h,"POST","/api/instances/7/reboot?account_id="+a.ID,`{}`)
  if w.Code!=200{t.Fatalf("account reboot mock got %d: %s",w.Code,w.Body.String())}
 }
 combined:=apiRequest(h,"GET","/api/instances","")
 var both struct{Instances []Instance `json:"instances"`}
 if err:=json.Unmarshal(combined.Body.Bytes(),&both);err!=nil||len(both.Instances)!=2||both.Instances[0].AccountID==both.Instances[1].AccountID{t.Fatalf("combined accounts with overlapping instance IDs corrupted: %+v %v",both,err)}
 if w:=apiRequest(h,"POST","/api/instances/7/reboot?account_id=unknown",`{}`);w.Code!=502{t.Fatalf("unknown account must fail closed, HTTP %d",w.Code)}
 mu.Lock();defer mu.Unlock()
 for _,token:=range []string{strings.Repeat("a",64),strings.Repeat("b",64)}{
  seen:=false
  for _,call:=range actions[token]{if call=="POST /v4/linode/instances/7/reboot"{seen=true}}
  if !seen{t.Errorf("scoped mock reboot missing for token prefix %q",token[:4])}
 }
}
func TestMultiAccountMonitorKeyIsolation(t *testing.T){
 t.Setenv("LINODE_TOKEN","")
 t.Setenv("TG_BOT_TOKEN","")
 t.Setenv("TG_CHAT_ID","")
 store,err:=initAccounts(filepath.Join(t.TempDir(),"accounts.enc"),strings.Repeat("k",40));if err!=nil{t.Fatal(err)}
 a,_:=store.add("first",strings.Repeat("a",64))
 b,_:=store.add("second",strings.Repeat("b",64))
 upstream:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  _,_=w.Write([]byte(`{"pages":1,"data":[{"id":12,"label":"shared","status":"running","ipv4":["8.8.8.8"]}]}`))
 }))
 defer upstream.Close();t.Setenv("LINODE_API_BASE_URL",upstream.URL+"/v4")
 s:=testServer(upstream.Client());s.accounts=store;s.accountStatus=map[string]Snapshot{}
 s.sshRun=func(_ context.Context,_ string,_ string)(string,error){return `{"cpu":40,"memory":50,"disk":60,"uptime":12,"service":"active"}`,nil}
 s.pollAccounts(context.Background())
 if len(s.accountStatus)!=2||s.accountStatus[a.ID+"/12"].AccountID!=a.ID||s.accountStatus[b.ID+"/12"].AccountID!=b.ID{t.Fatalf("monitor snapshots conflated: %+v",s.accountStatus)}
}

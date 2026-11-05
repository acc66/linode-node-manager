package main

import (
 "encoding/json"
 "net/http"
 "path/filepath"
 "strings"
 "testing"
)
func TestCreateInstanceAccountAndConfirmation(t *testing.T){
 t.Setenv("ADMIN_TOKEN","ci-admin")
 t.Setenv("LINODE_TOKEN","legacy-token")
 store,err:=initAccounts(filepath.Join(t.TempDir(),"accounts.enc"),strings.Repeat("k",40));if err!=nil{t.Fatal(err)}
 account,err:=store.add("create-account",strings.Repeat("a",64));if err!=nil{t.Fatal(err)}
 calls:=0
 upstream:=newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  calls++
  if r.Method!="POST"||r.URL.Path!="/v4/linode/instances"||r.Header.Get("Authorization")!="Bearer "+strings.Repeat("a",64){t.Error("incorrect create routing or credentials")}
  var data map[string]any
  if json.NewDecoder(r.Body).Decode(&data)!=nil{t.Fatal("invalid payload")}
  if data["region"]!="us-east"||data["type"]!="g6-nanode-1"||data["image"]!="linode/debian12"||data["root_pass"]!="test-password-123!"||data["booted"]!=true||data["confirm"]!=nil{t.Errorf("unexpected creation payload fields")}
  w.WriteHeader(200);w.Write([]byte(`{"id":99,"label":"new-node","status":"provisioning","ipv4":[],"root_pass":"must-not-leak"}`))
 }))
 defer upstream.Close();t.Setenv("LINODE_API_BASE_URL",upstream.URL+"/v4")
 s:=testServer(upstream.Client());s.accounts=store;s.credentials,_=initAccounts(filepath.Join(t.TempDir(),"credentials.enc"),strings.Repeat("k",40));h:=newHandler(s)
 payload:=`{"label":"new-node","region":"us-east","type":"g6-nanode-1","image":"linode/debian12","root_pass":"test-password-123!","confirm":true}`
 for _,tc:=range []struct{query,body string}{
  {"",payload},{"?account_id=unknown",payload},
  {"?account_id="+account.ID,strings.Replace(payload,`"confirm":true`,`"confirm":false`,1)},
  {"?account_id="+account.ID,strings.Replace(payload,"test-password-123!","short",1)},
  {"?account_id="+account.ID,payload+` {}`},
 }{
  if w:=apiRequest(h,"POST","/api/instances"+tc.query,tc.body);w.Code!=400{t.Fatalf("invalid request: %d %s",w.Code,w.Body.String())}
 }
 if calls!=0{t.Fatal("invalid request reached upstream")}
 w:=apiRequest(h,"POST","/api/instances?account_id="+account.ID,payload)
 if w.Code!=201||!strings.Contains(w.Body.String(),`"account_id":"`+account.ID+`"`)||strings.Contains(w.Body.String(),"must-not-leak"){t.Fatalf("create result: %d %s",w.Code,w.Body.String())}
 if calls!=1{t.Fatalf("expected one creation, got %d",calls)}
}
func TestCatalogPagination(t *testing.T){
 t.Setenv("ADMIN_TOKEN","ci-admin");t.Setenv("LINODE_TOKEN","mock")
 upstream:=newMockUpstream(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.URL.Path!="/v4/regions"||r.Header.Get("Authorization")!="Bearer mock"{t.Error("incorrect catalog route")}
  if r.URL.Query().Get("page")=="1"{w.Write([]byte(`{"pages":2,"data":[{"id":"us-east"}]}`))}else{w.Write([]byte(`{"pages":2,"data":[{"id":"ap-south"}]}`))}
 }))
 defer upstream.Close();t.Setenv("LINODE_API_BASE_URL",upstream.URL+"/v4")
 h:=newHandler(testServer(upstream.Client()))
 w:=apiRequest(h,"GET","/api/catalog/regions?account_id=legacy","")
 if w.Code!=200||!strings.Contains(w.Body.String(),"us-east")||!strings.Contains(w.Body.String(),"ap-south"){t.Fatalf("catalog: %d %s",w.Code,w.Body.String())}
 if w:=apiRequest(h,"GET","/api/catalog/regions","");w.Code!=400{t.Fatalf("missing account: %d",w.Code)}
}

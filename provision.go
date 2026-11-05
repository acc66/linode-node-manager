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
func (s *Server) catalog(w http.ResponseWriter,r *http.Request){
 paths:=map[string]string{"regions":"/regions","types":"/linode/types","images":"/images"}
 path,ok:=paths[r.PathValue("kind")];if !ok{fail(w,404,"Unknown catalog");return}
 account:=r.URL.Query().Get("account_id")
 if account==""{fail(w,400,"Select a Linode account first");return}
 if _,err:=s.accountToken(account);err!=nil{fail(w,400,"Unknown or unconfigured Linode account");return}
 items:=[]json.RawMessage{}
 for page:=1;page<=100;page++{
  b,status,err:=s.linodeFor(r.Context(),account,"GET",fmt.Sprintf("%s?page_size=100&page=%d",path,page),nil)
  if err!=nil{fail(w,502,"Linode catalog unavailable");return}
  if status!=200{fail(w,502,fmt.Sprintf("Linode catalog HTTP %d; check API permissions",status));return}
  var data struct{Data []json.RawMessage `json:"data"`;Pages int `json:"pages"`}
  if json.Unmarshal(b,&data)!=nil{fail(w,502,"Invalid Linode catalog response");return}
  items=append(items,data.Data...);if page>=data.Pages{send(w,200,map[string]any{"data":items});return}
 }
 fail(w,502,"Linode catalog exceeds pagination limit")
}
func (s *Server) createInstance(w http.ResponseWriter,r *http.Request){
 account:=r.URL.Query().Get("account_id")
 if account==""{fail(w,400,"Select a Linode account first");return}
 if _,err:=s.accountToken(account);err!=nil{fail(w,400,"Unknown or unconfigured Linode account");return}
 var in struct{
  Label string `json:"label"`
  Region string `json:"region"`
  Type string `json:"type"`
  Image string `json:"image"`
  RootPass string `json:"root_pass"`
  Confirm bool `json:"confirm"`
  OpenAllPorts *bool `json:"open_all_ports"`
 }
 dec:=json.NewDecoder(http.MaxBytesReader(w,r.Body,16<<10));dec.DisallowUnknownFields()
 if err:=dec.Decode(&in);err!=nil{fail(w,400,"Invalid create request");return}
 if err:=dec.Decode(new(any));err!=io.EOF{fail(w,400,"Expected one JSON object");return}
 in.Label=strings.TrimSpace(in.Label)
 if !in.Confirm{fail(w,400,"Confirm creation and billing first");return}
 if len(in.Label)<3||len(in.Label)>64||in.Region==""||in.Type==""||in.Image==""{fail(w,400,"Label (3-64 characters), region, type and image are required");return}
 if len(in.RootPass)<12||len(in.RootPass)>128{fail(w,400,"Root password must be 12-128 characters; Linode also checks password strength");return}
 if s.credentials==nil{fail(w,503,"Configure ACCOUNT_ENCRYPTION_KEY before creating instances so root passwords can be saved encrypted");return}
 openAll:=in.OpenAllPorts==nil||*in.OpenAllPorts
 data:=map[string]any{"label":in.Label,"region":in.Region,"type":in.Type,"image":in.Image,"root_pass":in.RootPass,"booted":true}
 if openAll{if err:=s.openNetworkConfig(r.Context(),account,data);err!=nil{fail(w,502,err.Error());return}}
 payload,_:=json.Marshal(data)
 b,status,err:=s.linodeFor(r.Context(),account,"POST","/linode/instances",bytes.NewReader(payload))
 if err!=nil{fail(w,502,"Creation result unknown. Refresh the instance list before retrying to avoid duplicate billing.");return}
 if status!=200&&status!=201{
  // Never forward an upstream response that may echo the password.
  fail(w,502,fmt.Sprintf("Linode create HTTP %d. Check account quota, permissions, region capacity and password strength in Linode.",status));return
 }
 var inst Instance
 if json.Unmarshal(b,&inst)!=nil||inst.ID<=0{fail(w,502,"Creation result unknown. Refresh the instance list before retrying.");return}
 inst.AccountID=account
 inst.OpenAllPorts=openAll
 warning:=""
 if err:=s.saveRootPassword(account,inst.ID,inst.Label,in.RootPass);err!=nil{warning="Instance created, but saving its password failed. Keep the password you entered; do not create again."}else{inst.PasswordSaved=true}
 if openAll{if err:=s.saveRootPassword("open-ports-"+account,inst.ID,inst.Label,"true");err!=nil{warning+=" 服务器已创建并且云防火墙不绑定，但全端口配置状态未保存。"}}
 send(w,201,struct{Instance;Warning string `json:"warning,omitempty"`}{inst,warning})
}

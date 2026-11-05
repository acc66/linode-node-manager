package main

import (
 "fmt"
 "net/http"
 "strconv"
 "strings"
)

// Reuse the AES-GCM store in a separate file; IDs include account and instance.
func (s *Server) saveRootPassword(account string,id int,label,password string)error{
 if s.credentials==nil{return fmt.Errorf("encrypted credential storage is not configured")}
 store:=s.credentials;key:=account+"/"+strconv.Itoa(id)
 store.mu.Lock();defer store.mu.Unlock()
 old,exists:=store.accounts[key]
 store.accounts[key]=storedAccount{ID:key,Name:label,Token:password}
 if err:=store.saveLocked();err!=nil{if exists{store.accounts[key]=old}else{delete(store.accounts,key)};return err}
 return nil
}
func (s *Server) passwordSaved(account string,id int)bool{
 if s.credentials==nil{return false};_,ok:=s.credentials.token(account+"/"+strconv.Itoa(id));return ok
}
func (s *Server) instancePassword(w http.ResponseWriter,r *http.Request){
 account:=r.URL.Query().Get("account_id");id,err:=strconv.Atoi(r.PathValue("id"))
 if account==""||err!=nil||id<=0{fail(w,400,"Select an account and valid instance");return}
 if _,err:=s.accountToken(account);err!=nil{fail(w,400,"Unknown account");return}
 if s.credentials==nil{fail(w,503,"Encrypted password storage unavailable");return}
 password,ok:=s.credentials.token(account+"/"+strconv.Itoa(id));if !ok{fail(w,404,"No password saved. Linode cannot return existing root passwords.");return}
 send(w,200,map[string]string{"root_pass":password})
}
func (s *Server) deleteInstance(w http.ResponseWriter,r *http.Request){
 account:=r.URL.Query().Get("account_id");id,err:=strconv.Atoi(r.PathValue("id"))
 if account==""||err!=nil||id<=0{fail(w,400,"Select an account and valid instance");return}
 if r.URL.Query().Get("confirm_id")!=strconv.Itoa(id){fail(w,400,"Confirm the instance ID before permanent deletion");return}
 if _,err:=s.accountToken(account);err!=nil{fail(w,400,"Unknown account");return}
 _,status,err:=s.linodeFor(r.Context(),account,"DELETE","/linode/instances/"+strconv.Itoa(id),nil)
 if err!=nil{fail(w,502,"Deletion result unknown. Refresh the instance list before retrying.");return}
 if status!=200&&status!=204{fail(w,502,fmt.Sprintf("Linode delete HTTP %d; check permissions and instance state",status));return}
 warning:=""
 if s.credentials!=nil&&s.passwordSaved(account,id){if err:=s.credentials.remove(account+"/"+strconv.Itoa(id));err!=nil{warning="Instance deleted, but saved password cleanup failed"}}
 s.mu.Lock();delete(s.accountStatus,account+"/"+strconv.Itoa(id));if account=="legacy"{delete(s.status,id)};s.mu.Unlock()
 send(w,200,map[string]any{"deleted":true,"id":id,"warning":strings.TrimSpace(warning)})
}

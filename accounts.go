package main

import (
 "context"
 "crypto/aes"
 "crypto/cipher"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "net/http"
 "io"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "sync"
)

type ManagedAccount struct {
 ID string `json:"id"`
 Name string `json:"name"`
 Token string `json:"-"`
}
type storedAccount struct{
 ID string `json:"id"`
 Name string `json:"name"`
 Token string `json:"token"`
}
type accountStore struct {
 mu sync.RWMutex
 key [32]byte
 file string
 accounts map[string]storedAccount
}
func initAccounts(file,key string)(*accountStore,error){
 if len(key)<32{return nil,errors.New("ACCOUNT_ENCRYPTION_KEY must be at least 32 characters")}
 s:=&accountStore{key:sha256.Sum256([]byte(key)),file:file,accounts:map[string]storedAccount{}}
 b,err:=os.ReadFile(file)
 if errors.Is(err,os.ErrNotExist){return s,nil}
 if err!=nil{return nil,fmt.Errorf("read account store: %w",err)}
 if len(b)<13{return nil,errors.New("encrypted account store is invalid")}
 block,err:=aes.NewCipher(s.key[:]);if err!=nil{return nil,err}
 gcm,err:=cipher.NewGCM(block);if err!=nil{return nil,err}
 n:=gcm.NonceSize();if len(b)<=n{return nil,errors.New("encrypted account store is invalid")}
 plain,err:=gcm.Open(nil,b[:n],b[n:],nil)
 if err!=nil{return nil,errors.New("account store decryption failed; verify ACCOUNT_ENCRYPTION_KEY")}
 var data []storedAccount
 if err=json.Unmarshal(plain,&data);err!=nil{return nil,errors.New("account store has invalid data")}
 for _,a:=range data{
  if a.ID==""||a.Token==""||a.Name==""{return nil,errors.New("account store contains incomplete record")}
  s.accounts[a.ID]=a
 }
 return s,nil
}
func (s *accountStore) saveLocked()error{
 entries:=make([]storedAccount,0,len(s.accounts))
 for _,a:=range s.accounts{entries=append(entries,a)}
 sort.Slice(entries,func(i,j int)bool{return entries[i].ID<entries[j].ID})
 plain,err:=json.Marshal(entries);if err!=nil{return err}
 block,err:=aes.NewCipher(s.key[:]);if err!=nil{return err}
 gcm,err:=cipher.NewGCM(block);if err!=nil{return err}
 nonce:=make([]byte,gcm.NonceSize());if _,err=rand.Read(nonce);err!=nil{return err}
 encrypted:=gcm.Seal(nonce,nonce,plain,nil)
 if err=os.MkdirAll(filepath.Dir(s.file),0700);err!=nil{return err}
 f,err:=os.CreateTemp(filepath.Dir(s.file),".accounts-*");if err!=nil{return err}
 defer os.Remove(f.Name())
 if err=f.Chmod(0600);err!=nil{f.Close();return err}
 if _,err=f.Write(encrypted);err!=nil{f.Close();return err}
 if err=f.Sync();err!=nil{f.Close();return err}
 if err=f.Close();err!=nil{return err}
 return os.Rename(f.Name(),s.file)
}
func (s *accountStore) list()[]ManagedAccount{
 s.mu.RLock();defer s.mu.RUnlock()
 out:=make([]ManagedAccount,0,len(s.accounts))
 for _,a:=range s.accounts{out=append(out,ManagedAccount{ID:a.ID,Name:a.Name})}
 sort.Slice(out,func(i,j int)bool{return out[i].Name<out[j].Name})
 return out
}
func (s *accountStore) token(id string)(string,bool){
 s.mu.RLock();defer s.mu.RUnlock()
 a,ok:=s.accounts[id];return a.Token,ok
}
func (s *accountStore) add(name,token string)(ManagedAccount,error){
 name=strings.TrimSpace(name)
 if len(name)<1||len(name)>80||len(token)<20||len(token)>512{return ManagedAccount{},errors.New("account name (1-80) or API token (20-512) is invalid")}
 idb:=make([]byte,16)
 if _,err:=rand.Read(idb);err!=nil{return ManagedAccount{},err}
 a:=storedAccount{ID:hex.EncodeToString(idb),Name:name,Token:token}
 s.mu.Lock();defer s.mu.Unlock()
 for _,v:=range s.accounts{if v.Name==a.Name{return ManagedAccount{},errors.New("account name already exists")}}
 s.accounts[a.ID]=a
 if err:=s.saveLocked();err!=nil{delete(s.accounts,a.ID);return ManagedAccount{},err}
 return ManagedAccount{ID:a.ID,Name:a.Name},nil
}
func (s *accountStore) remove(id string)error{
 s.mu.Lock();defer s.mu.Unlock()
 old,ok:=s.accounts[id];if !ok{return os.ErrNotExist}
 delete(s.accounts,id)
 if err:=s.saveLocked();err!=nil{s.accounts[id]=old;return err}
 return nil
}
func (s *Server) accountToken(id string)(string,error){
 if id==""||id=="legacy"{
  t:=os.Getenv("LINODE_TOKEN")
  if t==""{return "",errors.New("legacy LINODE_TOKEN not configured")}
  return t,nil
 }
 if s.accounts==nil{return "",errors.New("account store not configured")}
 t,ok:=s.accounts.token(id);if !ok{return "",errors.New("unknown account")}
 return t,nil
}
func (s *Server) linodeFor(ctx context.Context,accountID,method,path string,payload io.Reader)([]byte,int,error){
 token,err:=s.accountToken(accountID);if err!=nil{return nil,503,err}
 base:=env("LINODE_API_BASE_URL","https://api.linode.com/v4")
 return s.request(ctx,method,strings.TrimRight(base,"/")+path,token,payload)
}
func (s *Server) accountsAPI(w http.ResponseWriter,r *http.Request){
 if s.accounts==nil{fail(w,503,"Configure ACCOUNT_ENCRYPTION_KEY (32+ chars) to use multiple accounts");return}
 switch r.Method{
 case http.MethodGet:
  out:=s.accounts.list()
  if os.Getenv("LINODE_TOKEN")!=""{out=append([]ManagedAccount{{ID:"legacy",Name:"默认账号 (.env)"}},out...)}
  send(w,200,map[string]any{"accounts":out})
 case http.MethodPost:
  var in struct{Name string `json:"name"`;Token string `json:"token"`}
  if err:=json.NewDecoder(http.MaxBytesReader(w,r.Body,16<<10)).Decode(&in);err!=nil{fail(w,400,"Invalid account payload");return}
  a,err:=s.accounts.add(in.Name,in.Token)
  if err!=nil{fail(w,400,err.Error());return}
  send(w,201,a)
 default:
  fail(w,405,"Method not allowed")
 }
}
func (s *Server) deleteAccount(w http.ResponseWriter,r *http.Request){
 if s.accounts==nil{fail(w,503,"Account storage unavailable");return}
 id:=r.PathValue("id")
 if id=="legacy"{fail(w,400,"Default account is managed in .env");return}
 err:=s.accounts.remove(id)
 if errors.Is(err,os.ErrNotExist){fail(w,404,"Account not found");return}
 if err!=nil{fail(w,500,"Failed to save account changes");return}
 // Do not modify or shut down any Linode instance when an account is removed.
 s.mu.Lock()
 for k:=range s.accountStatus{if strings.HasPrefix(k,id+"/"){delete(s.accountStatus,k)}}
 s.mu.Unlock()
 send(w,200,map[string]bool{"deleted":true})
}

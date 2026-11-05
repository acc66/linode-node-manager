package main

import (
 "context"
 "crypto/subtle"
 "crypto/sha256"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "log"
 "net"
 "net/http"
 "net/url"
 "os"
 "os/exec"
 "strconv"
 "strings"
 "sync"
 "time"
)

type Server struct {
 wp2Mu sync.Mutex
 client *http.Client
 mu sync.RWMutex
 status map[int]Snapshot
 accountStatus map[string]Snapshot
 credentials *accountStore
 accounts *accountStore
 jobs map[string]Job
 sshRun func(context.Context,string,string)(string,error)
}
type Snapshot struct {
 AccountID string `json:"account_id,omitempty"`
 ID int `json:"id"`
 Label string `json:"label"`
 State string `json:"status"`
 CPU float64 `json:"cpu"`
 Memory float64 `json:"memory"`
 Disk float64 `json:"disk"`
 Uptime float64 `json:"uptime"`
 Service string `json:"service"`
 Failures int `json:"failures"`
 Alert string `json:"alert_state"`
 Updated string `json:"updated_at"`
}
type Job struct {
 InstanceID int `json:"instance_id,omitempty"`
 TargetID int `json:"target_id,omitempty"`
 AccountID string `json:"account_id,omitempty"`
 ID string `json:"job_id"`
 Status string `json:"status"`
 Log string `json:"log"`
}
type Instance struct {
 AccountID string `json:"account_id,omitempty"`
 ID int `json:"id"`
 Label string `json:"label"`
 Status string `json:"status"`
 IPv4 []string `json:"ipv4"`
 IPv6 string `json:"ipv6"`
 Region string `json:"region"`
 Type string `json:"type"`
 PasswordSaved bool `json:"password_saved"`
}
func env(k,d string)string {if v:=os.Getenv(k);v!="" {return v};return d}
func number(k string,d int)int {v,e:=strconv.Atoi(os.Getenv(k));if e!=nil{return d};return v}
func send(w http.ResponseWriter,status int,v any){w.Header().Set("Content-Type","application/json");w.WriteHeader(status);_ =json.NewEncoder(w).Encode(v)}
func fail(w http.ResponseWriter,status int,e string){send(w,status,map[string]string{"error":e})}
func safeEqual(a,b string)bool{
 x,y:=sha256.Sum256([]byte(a)),sha256.Sum256([]byte(b))
 return subtle.ConstantTimeCompare(x[:],y[:])==1
}
func (s *Server) auth(next http.HandlerFunc)http.HandlerFunc{return func(w http.ResponseWriter,r *http.Request){
 w.Header().Set("Cache-Control","no-store")
 w.Header().Set("X-Content-Type-Options","nosniff")
 w.Header().Set("Referrer-Policy","no-referrer")
 w.Header().Set("X-Frame-Options","DENY")
 w.Header().Set("Content-Security-Policy","default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
 bearer:=os.Getenv("ADMIN_TOKEN")
 user:=os.Getenv("ADMIN_USERNAME")
 pass:=os.Getenv("ADMIN_PASSWORD")
 authorized:=false
 isBearer:=false
 if v:=r.Header.Get("Authorization");bearer!=""&&strings.HasPrefix(v,"Bearer "){
  authorized=safeEqual(v,"Bearer "+bearer);isBearer=authorized
 }else if u,p,ok:=r.BasicAuth();ok&&user!=""&&len(pass)>=12{
  authorized=safeEqual(u,user)&&safeEqual(p,pass)
 }
 if !authorized{
  w.Header().Set("WWW-Authenticate",`Basic realm="Linode Manager", charset="UTF-8"`)
  fail(w,401,"Unauthorized");return
 }
 if (r.Method=="POST"||r.Method=="DELETE"||r.Method=="PUT"||r.Method=="PATCH")&&!isBearer{
  if r.Header.Get("Sec-Fetch-Site")=="cross-site"{fail(w,403,"Cross-site request rejected");return}
  if origin:=r.Header.Get("Origin");origin!=""{
   u,err:=url.Parse(origin);if err!=nil||u.Host!=r.Host||u.Scheme!="https"&&!(u.Scheme=="http"&&(r.Host=="127.0.0.1:8000"||r.Host=="localhost:8000")){
    fail(w,403,"Cross-origin request rejected");return
   }
  }
  if r.Header.Get("Content-Type")!="application/json"{fail(w,415,"JSON content type required");return}
 }
 next(w,r.WithContext(useProxyContext(r.Context(),r.URL.Query().Get("use_proxy")=="true")))
}}
func (s *Server) request(ctx context.Context,method,endpoint,token string,payload io.Reader)([]byte,int,error){
 req,e:=http.NewRequestWithContext(ctx,method,endpoint,payload);if e!=nil{return nil,0,e}
 req.Header.Set("Authorization","Bearer "+token)
 if payload!=nil{req.Header.Set("Content-Type","application/json")}
 resp,e:=s.client.Do(req);if e!=nil{return nil,0,e};defer resp.Body.Close()
 b,e:=io.ReadAll(io.LimitReader(resp.Body,4<<20));return b,resp.StatusCode,e
}
func (s *Server) linode(ctx context.Context,method,path string,payload io.Reader)([]byte,int,error){return s.linodeFor(ctx,"",method,path,payload)}
func (s *Server) instances(ctx context.Context)([]Instance,error){return s.instancesFor(ctx,"")}
func (s *Server) instancesFor(ctx context.Context,accountID string)([]Instance,error){
 out:=[]Instance{}
 for page:=1;page<=100;page++{
  b,status,e:=s.linodeFor(ctx,accountID,"GET",fmt.Sprintf("/linode/instances?page=%d&page_size=100",page),nil)
  if e!=nil{return nil,e};if status!=200{return nil,fmt.Errorf("Linode HTTP %d",status)}
  var data struct{Data []Instance `json:"data"`;Pages int `json:"pages"`}
  if e=json.Unmarshal(b,&data);e!=nil{return nil,e}
  for _,inst:=range data.Data{inst.AccountID=accountID;if inst.AccountID==""{inst.AccountID="legacy"};inst.PasswordSaved=s.passwordSaved(inst.AccountID,inst.ID);out=append(out,inst)};if page>=data.Pages{break}
 }
 return out,nil
}
func (s *Server) wpNodes(w http.ResponseWriter,r *http.Request){
 s.wp2Mu.Lock();defer s.wp2Mu.Unlock()
 session,err:=s.loadWP2Session();if err!=nil{fail(w,409,err.Error());return}
 if session!=nil{
  nodes,err:=s.adminWP2Nodes(r.Context(),session);if err!=nil{fail(w,409,err.Error());return}
  send(w,200,map[string]any{"nodes":nodes,"source":"wp2-admin"});return
 }

 base:=env("WP2_BASE_URL","");token:=os.Getenv("WP2_API_TOKEN")
 path:=env("WP2_NODES_PATH","/mod_mu/nodes")
 u,e:=url.Parse(base);if e!=nil||u.Scheme!="https"||u.Host==""||u.User!=nil||u.RawQuery!=""||u.Fragment!=""{fail(w,503,"Configure HTTPS WP2_BASE_URL");return}
 if token==""{fail(w,503,"Configure WP2_API_TOKEN");return}
 if path!="/mod_mu/nodes" {fail(w,400,"Unsupported node-list path");return}
 target:=strings.TrimRight(base,"/")+path+"?key="+url.QueryEscape(token)+"&view=manager"
 req,e:=http.NewRequestWithContext(r.Context(),"GET",target,nil);if e!=nil{fail(w,500,"Invalid request");return}
 resp,e:=s.client.Do(req);if e!=nil{fail(w,502,"wp2 unavailable");return};defer resp.Body.Close()
 if resp.StatusCode!=200{fail(w,502,fmt.Sprintf("wp2 HTTP %d",resp.StatusCode));return}
 var data struct{Ret int `json:"ret"`;Data json.RawMessage `json:"data"`;ManagerView bool `json:"manager_view"`}
 if e=json.NewDecoder(io.LimitReader(resp.Body,4<<20)).Decode(&data);e!=nil||data.Ret!=1{fail(w,502,"wp2 returned invalid or rejected response");return}
 var nodes []map[string]any
 if len(data.Data)==0||strings.TrimSpace(string(data.Data))=="null"{fail(w,502,"wp2 returned null node data, not a node list; check WebAPI and source IP permissions");return}
 if e=json.Unmarshal(data.Data,&nodes);e!=nil{fail(w,502,"wp2 nodes response malformed");return}
 // Never forward credentials or full node configuration to the browser.
 safe:=make([]map[string]any,0,len(nodes))
 for _,n:=range nodes{
  // wp2 /mod_mu/nodes is a node configuration listing, not a live heartbeat feed.
  safe=append(safe,map[string]any{"id":n["id"],"name":n["name"],"sort":n["sort"],"node_status":"unknown","status_source":"wp2 node listing; no heartbeat"})
 }
 warning:="";if len(safe)==0{warning="wp2 返回空节点列表。旧接口仅支持 sort=0/10/12/13 且要求有 node_ip；请部署 wp2 管理视图补丁。"}
 if len(safe)==0&&data.ManagerView{warning="wp2 管理视图返回空列表，请检查当前 wp2 连接的数据库是否有节点记录。"}
 send(w,200,map[string]any{"nodes":safe,"warning":warning,"manager_view":data.ManagerView})
}
func ssh(ctx context.Context,ip,script string)(string,error){
 key:=env("SSH_PRIVATE_KEY_PATH","/run/secrets/linode_ssh_key")
 known:=env("SSH_KNOWN_HOSTS_PATH","/run/secrets/known_hosts")
 if _,e:=os.Stat(key);e!=nil{return "",errors.New("SSH private key not configured")}
 if _,e:=os.Stat(known);e!=nil{return "",errors.New("SSH known_hosts not configured")}
 user:=env("MONITOR_SSH_USER","root")
 cmd:=exec.CommandContext(ctx,"ssh","-i",key,"-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o","UserKnownHostsFile="+known,"-o","ConnectTimeout=8",user+"@"+ip,"bash -s")
 cmd.Stdin=strings.NewReader(script);b,e:=cmd.CombinedOutput();return string(b),e
}
func (s *Server) runSSH(ctx context.Context,ip,script string)(string,error){if s.sshRun!=nil{return s.sshRun(ctx,ip,script)};return ssh(ctx,ip,script)}
func publicIP(i Instance)string{for _,v:=range i.IPv4{ip:=net.ParseIP(v);if ip!=nil&&ip.To4()!=nil&&!ip.IsLoopback()&&!ip.IsPrivate()&&!ip.IsLinkLocalUnicast(){return v}};return ""}
const probeScript = `python3 - <<'PY'
import json,os,time,subprocess
def cpu():
 a=list(map(int,open('/proc/stat').readline().split()[1:]));return sum(a),a[3]+a[4]
a,b=cpu();time.sleep(.25);c,d=cpu()
m={}
for line in open('/proc/meminfo'):
 k,v=line.split(':',1);m[k]=int(v.split()[0])
st=os.statvfs('/');total=st.f_blocks*st.f_frsize;free=st.f_bavail*st.f_frsize
svc=subprocess.run(['systemctl','is-active','xboard-node.service'],capture_output=True,text=True,timeout=5).stdout.strip()
print(json.dumps({'cpu':round(100*(1-(d-b)/max(1,c-a)),1),'memory':round(100*(1-m.get('MemAvailable',0)/max(1,m.get('MemTotal',1))),1),'disk':round(100*(1-free/max(1,total)),1),'uptime':int(float(open('/proc/uptime').read().split()[0])),'service':svc}))
PY
`
func (s *Server) telegram(msg string){
 token:=os.Getenv("TG_BOT_TOKEN");chat:=os.Getenv("TG_CHAT_ID");if token==""||chat==""{return}
 form:=url.Values{"chat_id":{chat},"text":{msg}}
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second);defer cancel()
 base:=env("TG_API_BASE_URL","https://api.telegram.org")
 req,e:=http.NewRequestWithContext(ctx,"POST",strings.TrimRight(base,"/")+"/bot"+token+"/sendMessage",strings.NewReader(form.Encode()));if e!=nil{return}
 req.Header.Set("Content-Type","application/x-www-form-urlencoded");resp,e:=s.client.Do(req);if e==nil{resp.Body.Close()}
}
func alertsFor(next Snapshot)string{
 alarms:=[]string{}
 for _,v:=range []struct{Name string;Value float64;Limit int}{{"cpu",next.CPU,number("ALERT_CPU_PERCENT",90)},{"memory",next.Memory,number("ALERT_MEMORY_PERCENT",90)},{"disk",next.Disk,number("ALERT_DISK_PERCENT",90)}}{if v.Value>=float64(v.Limit){alarms=append(alarms,v.Name)}}
 if next.Service!="active"{alarms=append(alarms,"service")}
 return strings.Join(alarms,",")
}
func (s *Server) poll(ctx context.Context){
 items,e:=s.instances(ctx);if e!=nil{log.Printf("monitor: Linode list unavailable: %v",e);return}
 for _,inst:=range items{
  old:=Snapshot{};s.mu.RLock();old=s.status[inst.ID];s.mu.RUnlock()
  next:=Snapshot{AccountID:"legacy",ID:inst.ID,Label:inst.Label,State:"offline",Updated:time.Now().UTC().Format(time.RFC3339)}
  if inst.Status=="running"&&publicIP(inst)!=""{
   c,cancel:=context.WithTimeout(ctx,20*time.Second);output,err:=s.runSSH(c,publicIP(inst),probeScript);cancel()
   if err==nil{
    var v struct{CPU float64 `json:"cpu"`;Memory float64 `json:"memory"`;Disk float64 `json:"disk"`;Uptime float64 `json:"uptime"`;Service string `json:"service"`}
    if json.Unmarshal([]byte(output),&v)==nil&&v.CPU>=0&&v.CPU<=100&&v.Memory>=0&&v.Memory<=100&&v.Disk>=0&&v.Disk<=100&&v.Uptime>=0{next.State="online";next.CPU=v.CPU;next.Memory=v.Memory;next.Disk=v.Disk;next.Uptime=v.Uptime;next.Service=v.Service}
   }
  }
  if next.State=="offline"{next.Failures=old.Failures+1;if next.Failures>=number("ALERT_FAILURE_COUNT",3){next.Alert="offline"}}else{
   next.Alert=alertsFor(next)
  }
  s.mu.Lock();s.status[inst.ID]=next;s.mu.Unlock()
  if next.Alert!=old.Alert{
   if next.Alert!=""{go s.telegram(fmt.Sprintf("🚨 Linode %s (#%d): %s",inst.Label,inst.ID,next.Alert))}
   if next.Alert==""&&old.Alert!=""{go s.telegram(fmt.Sprintf("✅ Linode %s (#%d) recovered",inst.Label,inst.ID))}
  }
 }
}
func (s *Server) monitoring(ctx context.Context){
 ticker:=time.NewTicker(time.Duration(max(30,number("MONITOR_INTERVAL",60)))*time.Second);defer ticker.Stop()
 s.poll(ctx);s.pollAccounts(ctx);for{select{case <-ctx.Done():return;case <-ticker.C:s.poll(ctx);s.pollAccounts(ctx)}}
}
func (s *Server) install(w http.ResponseWriter,r *http.Request){
 accountID:=r.URL.Query().Get("account_id")
 if _,err:=s.accountToken(accountID);err!=nil{fail(w,400,"Unknown or unconfigured Linode account");return}
 var in struct{InstanceID int `json:"instance_id"`;Mode string `json:"mode"`;TargetID int `json:"target_id"`}
 if json.NewDecoder(io.LimitReader(r.Body,1<<16)).Decode(&in)!=nil||in.InstanceID<=0||in.TargetID<=0||in.Mode!="node"{fail(w,400,"Valid instance_id, node mode and target_id required");return}
 token:=os.Getenv("WP2_API_TOKEN");base:=env("WP2_BASE_URL","");u,e:=url.Parse(base);if token==""||e!=nil||u.Scheme!="https"||u.Host==""{fail(w,503,"wp2 not configured");return}
 b,st,e:=s.linodeFor(r.Context(),accountID,"GET",fmt.Sprintf("/linode/instances/%d",in.InstanceID),nil);if e!=nil||st!=200{fail(w,502,"Linode instance lookup failed");return}
 var inst Instance;if json.Unmarshal(b,&inst)!=nil||inst.Status!="running"||publicIP(inst)==""{fail(w,409,"Running public IPv4 instance required");return}
 id:=strconv.FormatInt(time.Now().UnixNano(),36)
 s.mu.Lock()
 for _,job:=range s.jobs{if (job.Status=="queued"||job.Status=="running")&&((job.AccountID==accountID&&job.InstanceID==in.InstanceID)||job.TargetID==in.TargetID){s.mu.Unlock();fail(w,409,"该服务器或 wp2 节点正在安装，请等待当前任务完成");return}}
 s.jobs[id]=Job{ID:id,AccountID:accountID,InstanceID:in.InstanceID,TargetID:in.TargetID,Status:"queued"};s.mu.Unlock()
 go func(){
  s.mu.Lock();s.jobs[id]=Job{ID:id,AccountID:accountID,InstanceID:in.InstanceID,TargetID:in.TargetID,Status:"running"};s.mu.Unlock()
  ctx,cancel:=context.WithTimeout(context.Background(),15*time.Minute);defer cancel()
  script:=deploymentScript(base,token,in.TargetID,inst)
  output,err:=s.deploySSH(ctx,accountID,inst,script)
  output=strings.ReplaceAll(output,token,"[REDACTED]")
  if len(output)>12000{output=output[len(output)-12000:]}
  state:="success";if err!=nil{state="failed";output+="\nInstallation failed: "+err.Error()}
  s.mu.Lock();s.jobs[id]=Job{ID:id,AccountID:accountID,InstanceID:in.InstanceID,TargetID:in.TargetID,Status:state,Log:output};s.mu.Unlock()
 }()
 send(w,202,map[string]string{"job_id":id,"status":"queued"})
}
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func newHandler(s *Server) http.Handler {
 mux:=http.NewServeMux()
 mux.HandleFunc("GET /api/linode/proxy",s.auth(s.linodeProxyAPI))
 mux.HandleFunc("PUT /api/linode/proxy",s.auth(s.linodeProxyAPI))
 mux.HandleFunc("DELETE /api/linode/proxy",s.auth(s.linodeProxyAPI))
 mux.HandleFunc("GET /api/wp2/session",s.auth(s.wp2SessionAPI))
 mux.HandleFunc("POST /api/wp2/session",s.auth(s.wp2SessionAPI))
 mux.HandleFunc("DELETE /api/wp2/session",s.auth(s.wp2SessionAPI))
 mux.HandleFunc("GET /api/instances/{id}/password",s.auth(s.instancePassword))
 mux.HandleFunc("DELETE /api/instances/{id}",s.auth(s.deleteInstance))
 mux.HandleFunc("POST /api/instances",s.auth(s.createInstance))
 mux.HandleFunc("GET /api/catalog/{kind}",s.auth(s.catalog))
 mux.HandleFunc("GET /",s.auth(func(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","text/html; charset=utf-8");io.WriteString(w,htmlPage)}))
 mux.HandleFunc("GET /api/health",s.auth(func(w http.ResponseWriter,r *http.Request){send(w,200,map[string]string{"status":"ok","language":"go"})}))
 mux.HandleFunc("GET /api/instances",s.auth(func(w http.ResponseWriter,r *http.Request){
  accountID:=r.URL.Query().Get("account_id")
  items:=[]Instance{}
  ids:=[]string{}
  if accountID!=""{if _,err:=s.accountToken(accountID);err!=nil{fail(w,400,"Unknown account");return};ids=append(ids,accountID)}else{
   if s.legacyEnabled(){ids=append(ids,"legacy")}
   if s.accounts!=nil{for _,a:=range s.accounts.list(){ids=append(ids,a.ID)}}
  }
  for _,id:=range ids{found,err:=s.instancesFor(r.Context(),id);if err!=nil{fail(w,502,"Linode API unavailable for selected account");return};items=append(items,found...)}
  send(w,200,map[string]any{"instances":items})
 }))
 mux.HandleFunc("GET /api/instances/{id}",s.auth(func(w http.ResponseWriter,r *http.Request){id,e:=strconv.Atoi(r.PathValue("id"));if e!=nil||id<=0{fail(w,400,"Invalid instance ID");return};b,st,e:=s.linodeFor(r.Context(),r.URL.Query().Get("account_id"),"GET",fmt.Sprintf("/linode/instances/%d",id),nil);if e!=nil{fail(w,502,"Linode API unavailable");return};w.Header().Set("Content-Type","application/json");w.WriteHeader(st);w.Write(b)}))
 mux.HandleFunc("GET /api/wp2/nodes",s.auth(s.wpNodes))
 mux.HandleFunc("GET /api/accounts",s.auth(s.accountsAPI))
 mux.HandleFunc("POST /api/accounts",s.auth(s.accountsAPI))
 mux.HandleFunc("DELETE /api/accounts/{id}",s.auth(s.deleteAccount))
 mux.HandleFunc("GET /api/monitor",s.auth(func(w http.ResponseWriter,r *http.Request){s.mu.RLock();defer s.mu.RUnlock();items:=[]Snapshot{};for _,v:=range s.status{items=append(items,v)};for _,v:=range s.accountStatus{items=append(items,v)};send(w,200,map[string]any{"instances":items})}))
 mux.HandleFunc("POST /api/deployments/install",s.auth(s.install))
 mux.HandleFunc("GET /api/deployments/{id}",s.auth(func(w http.ResponseWriter,r *http.Request){s.mu.RLock();v,ok:=s.jobs[r.PathValue("id")];s.mu.RUnlock();if !ok{fail(w,404,"Unknown job");return};send(w,200,v)}))
 mux.HandleFunc("POST /api/instances/{id}/{action}",s.auth(func(w http.ResponseWriter,r *http.Request){id,e:=strconv.Atoi(r.PathValue("id"));action:=r.PathValue("action");if e!=nil||id<=0||(action!="boot"&&action!="shutdown"&&action!="reboot"){fail(w,400,"Invalid action");return};b,st,e:=s.linodeFor(r.Context(),r.URL.Query().Get("account_id"),"POST",fmt.Sprintf("/linode/instances/%d/%s",id,action),strings.NewReader("{}"));if e!=nil{fail(w,502,"Linode API unavailable");return};w.Header().Set("Content-Type","application/json");w.WriteHeader(st);w.Write(b)}))
 return mux
}
func main(){
 transport:=http.DefaultTransport.(*http.Transport).Clone();transport.Proxy=nil
 if err:=validateAdminConfig();err!=nil{log.Fatal("Invalid administrator configuration: ",err)}
 s:=&Server{client:&http.Client{Transport:transport,Timeout:35*time.Second,CheckRedirect:func(_ *http.Request,_ []*http.Request)error{return http.ErrUseLastResponse}},status:map[int]Snapshot{},accountStatus:map[string]Snapshot{},jobs:map[string]Job{}}
 if key:=os.Getenv("ACCOUNT_ENCRYPTION_KEY");key!=""{
  store,err:=initAccounts(env("ACCOUNTS_FILE","/data/accounts.enc"),key)
  if err!=nil{log.Fatal("Cannot load encrypted accounts: ",err)}
  s.accounts=store
  credentials,err:=initAccounts(env("INSTANCE_CREDENTIALS_FILE","/data/instance-credentials.enc"),key)
  if err!=nil{log.Fatal("Cannot load encrypted instance credentials: ",err)}
  s.credentials=credentials
 }

 mux:=newHandler(s)
 ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 if env("MONITOR_ENABLED","false")=="true"{go s.monitoring(ctx)}
 addr:=env("LISTEN_ADDR","0.0.0.0:8000");log.Printf("Linode Node Manager Go listening on %s",addr);log.Fatal(http.ListenAndServe(addr,mux))
}
func validateAdminConfig()error{
 user,pass:=os.Getenv("ADMIN_USERNAME"),os.Getenv("ADMIN_PASSWORD")
 if user!=""||pass!=""{
  if user==""{return errors.New("ADMIN_USERNAME is required when ADMIN_PASSWORD is set")}
  if len(pass)<12{return errors.New("ADMIN_PASSWORD must be at least 12 characters; update .env and recreate the manager container")}
 }else if os.Getenv("ADMIN_TOKEN")==""{return errors.New("configure ADMIN_USERNAME and ADMIN_PASSWORD, or ADMIN_TOKEN for API-only access")}
 return nil
}
const htmlPage = `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Linode Node Manager Go</title><style>body{background:#0f172a;color:#e2e8f0;font:15px system-ui;max-width:1000px;margin:auto;padding:24px}section{background:#1e293b;border-radius:12px;padding:18px;margin:14px 0}input,select,button{padding:9px;margin:4px;background:#334155;color:white;border:1px solid #64748b;border-radius:7px}button{background:#2563eb;cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere}table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #475569}</style><h1>Linode Go 管理面板</h1><dialog id="passworddialog" onclose="document.getElementById('savedpassword').value=''"><p>已加密保存的 Root 密码</p><input id="savedpassword" type="text" readonly autocomplete="off"><button onclick="document.getElementById('passworddialog').close()">关闭并清除</button></dialog><section><p>已登录管理面板（账号密码由浏览器安全认证）。请使用 HTTPS 访问公网地址。</p><button onclick="load()">刷新</button><p id="msg"></p></section><section><h2>Linode 多账号管理</h2><p>Token 加密保存，不在网页回显。开关机和安装前先选择目标账号。</p><select id="account" onchange="load();monitor();proxyStatus()"><option value="">全部账号（仅查看）</option></select><input id="accountname" maxlength="80" placeholder="账号备注"><input id="accounttoken" type="password" placeholder="Linode API Token" autocomplete="off"><button onclick="addAccount()">添加账号</button><button onclick="deleteAccount()">删除所选账号</button><p id="accountmsg"></p><p>Linode API 连接方式：<label><input id="useproxy" type="checkbox" onchange="load()">使用所选账号的代理（不勾选则直连）</label></p><input id="proxyurl" type="password" autocomplete="off" placeholder="http://用户:密码@主机:端口 或 socks5://主机:端口"><button onclick="saveProxy()">加密保存代理</button><button onclick="removeProxy()">删除代理</button><p id="proxystatus"></p></section><section><h2>创建 Linode 服务器</h2><p>先在上方选择账号，再加载地区、套餐和系统。创建后按 Linode 规则计费。</p><button onclick="catalogs()">加载创建选项</button><input id="createlabel" placeholder="服务器名称（3-64位）" maxlength="64"><select id="createregion"></select><select id="createtype"></select><select id="createimage"></select><input id="createpass" type="password" autocomplete="new-password" placeholder="Root 密码（至少12位）"><button id="createbutton" onclick="createInstance()">创建并开机</button><p id="createmsg"></p></section><section><h2>服务器</h2><div id="instances"></div></section><section><h2>wp2 节点</h2><p>连接 wp2 管理员账号后可同步全部节点，无需修改 wp2。密码仅用于本次登录，会话加密保存在服务器。</p><input id="wp2email" type="email" autocomplete="username" placeholder="wp2 管理员邮箱"><input id="wp2password" type="password" autocomplete="off" placeholder="wp2 密码"><input id="wp2code" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="两步动态码（如启用）"><button id="wp2connect" onclick="connectWP2()">连接 wp2</button><button onclick="disconnectWP2()">断开连接</button><p id="wp2connection"></p><button onclick="nodes()">同步 wp2 节点</button><p id="nodehint">节点在线状态需要 wp2 心跳接口；此处不将配置状态误判为在线。</p><pre id="nodes"></pre></section><section><h2>安装 XboardNode-Plus</h2><p id="installaccount">请在上方选择 Linode 账号</p><select id="instance"><option value="">请先选择账号并加载服务器</option></select><select id="node"><option value="">请先同步 wp2 节点</option></select><button id="installbutton" onclick="install()">自动安装并验证</button><input id="job" placeholder="任务 ID"><button onclick="job()">查询任务</button><pre id="joblog"></pre></section><section><h2>CPU / 内存 / 磁盘</h2><button onclick="monitor()">刷新监控</button><pre id="metrics"></pre></section><script>async function api(path,options={}){if(path==='/instances'||path.startsWith('/instances/')||path==='/deployments/install'||path.startsWith('/catalog/')||path==='/linode/proxy'){let a=document.getElementById('account').value;if(a&&!path.includes('account_id='))path+=(path.includes('?')?'&':'?')+'account_id='+encodeURIComponent(a);if(document.getElementById('useproxy').checked&&path!='/linode/proxy'&&!path.startsWith('/linode/proxy?'))path+=(path.includes('?')?'&':'?')+'use_proxy=true'}let r=await fetch('/api'+path,{...options,credentials:'same-origin',headers:{'Content-Type':'application/json'}});let j=await r.json();if(!r.ok)throw Error(j.error||r.status);return j}async function loadAccounts(){let box=document.getElementById('account'),old=box.value;try{let data=await api('/accounts');box.replaceChildren();let all=document.createElement('option');all.value='';all.textContent='全部账号（仅查看）';box.appendChild(all);for(let a of data.accounts){let o=document.createElement('option');o.value=a.id;o.textContent=a.name;box.appendChild(o)}box.value=old&&Array.from(box.options).some(o=>o.value===old)?old:(data.accounts.length===1?data.accounts[0].id:'');document.getElementById('accountmsg').textContent='已加载 '+data.accounts.length+' 个账号'}catch(e){document.getElementById('accountmsg').textContent=e.message}}
async function addAccount(){let name=document.getElementById('accountname').value.trim(),token=document.getElementById('accounttoken').value;if(!name||token.length<20){document.getElementById('accountmsg').textContent='请输入账号备注和有效 Token';return}try{let a=await api('/accounts',{method:'POST',body:JSON.stringify({name,token})});document.getElementById('accounttoken').value='';await loadAccounts();document.getElementById('account').value=a.id;await load();document.getElementById('accountmsg').textContent='已添加：'+a.name}catch(e){document.getElementById('accountmsg').textContent=e.message}}
async function deleteAccount(){let id=document.getElementById('account').value;if(!id){document.getElementById('accountmsg').textContent='请先选择要移除的 Linode 账号';return}if(!confirm('删除此账号凭据？不会删除 Linode 实例。'))return;try{await api('/accounts/'+encodeURIComponent(id),{method:'DELETE'});await loadAccounts();await load()}catch(e){document.getElementById('accountmsg').textContent=e.message}}
const esc=x=>String(x??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));async function power(id,action){if(!document.getElementById('account').value){document.getElementById('msg').textContent='请先选择目标账号，不能在全部账号视图操作';return}if(!confirm('确认对实例 '+id+' 执行 '+action+'？'))return;try{await api('/instances/'+id+'/'+action,{method:'POST'});await load()}catch(e){document.getElementById('msg').textContent=e.message}}const show=(id,x)=>document.getElementById(id).textContent=JSON.stringify(x,null,2);async function load(){const selectedAccount=document.getElementById('account').value;const target=document.getElementById('instance'),previous=installationAccount===selectedAccount?target.value:'';installationAccount='';target.replaceChildren();try{let d=await api('/instances');if(document.getElementById('account').value!==selectedAccount)return;updateInstallTargets(d.instances,selectedAccount,previous);document.getElementById('instances').innerHTML='<table><tr><th>Linode 账号</th><th>ID</th><th>名称</th><th>状态</th><th>IP 地址</th><th>地区 / 套餐</th><th>操作</th></tr>'+d.instances.map((i,index)=>'<tr><td>'+esc(accountLabel(i.account_id))+'</td><td>'+Number(i.id)+'</td><td>'+esc(i.label)+'</td><td>'+esc(i.status)+'</td><td>'+esc((i.ipv4||[]).join(', ')||'分配中')+(i.ipv6?'<br>'+esc(i.ipv6):'')+'</td><td>'+esc(i.region)+'<br>'+esc(i.type)+'</td><td><button onclick="power('+Number(i.id)+',\'boot\')">开机</button><button onclick="power('+Number(i.id)+',\'shutdown\')">关机</button><button onclick="power('+Number(i.id)+',\'reboot\')">重启</button><button data-action="password" data-index="'+index+'" '+(i.password_saved?'':'disabled')+'>查看密码</button><button data-action="delete" data-index="'+index+'">删除实例</button></td></tr>').join('')+'</table>';document.getElementById('instances').querySelectorAll('[data-action]').forEach(button=>button.onclick=()=>instanceOperation(d.instances[Number(button.dataset.index)],button.dataset.action));document.getElementById('msg').textContent=d.instances.length?'已加载 '+d.instances.length+' 台；选择目标账号后可使用每行的开机、关机、重启按钮':'当前账号没有实例，请检查 Linode API Token 或选择其他账号'}catch(e){document.getElementById('msg').textContent='服务器列表加载失败：'+e.message}}async function nodes(){document.getElementById('nodehint').textContent='正在同步 wp2 节点…';try{let d=await api('/wp2/nodes');let a=d.nodes||[];let sel=document.getElementById('node');sel.replaceChildren();let empty=document.createElement('option');empty.value='';empty.textContent='请选择 wp2 节点';sel.appendChild(empty);for(let n of a){let o=document.createElement('option');o.value=String(n.id);o.textContent=String(n.name||'节点')+' (#'+n.id+')';sel.appendChild(o)}show('nodes',a);document.getElementById('nodehint').textContent=a.length?'已同步 '+a.length+' 个节点；在线状态：待心跳接口验证':(d.warning||'wp2 接口返回 0 个节点，请检查 wp2 节点配置与 API 访问权限')}catch(e){document.getElementById('nodehint').textContent='wp2 同步失败：'+e.message;show('nodes',e.message)}}async function monitor(){try{let d=(await api('/monitor')).instances,id=document.getElementById('account').value;show('metrics',id?d.filter(i=>i.account_id===id):d)}catch(e){show('metrics',e.message)}}async function install(){
 const button=document.getElementById('installbutton'),account=document.getElementById('account'),instance=document.getElementById('instance'),node=document.getElementById('node');
 if(button.disabled)return;
 if(!account.value){show('joblog','请先选择目标 Linode 账号');return}
 if(installationAccount!==account.value||!Number.isInteger(Number(instance.value))||Number(instance.value)<=0){show('joblog','请选择该账号下运行中的 Linode 服务器');return}
 if(!node.value){show('joblog','请先同步并选择 wp2 节点');return}
 if(!confirm('确认自动安装后端？\nLinode 账号：'+accountLabel(account.value)+'\n服务器：'+instance.selectedOptions[0].textContent+'\nwp2 节点：'+node.selectedOptions[0].textContent+'\n将自动检查配置、申请证书并启用服务。'))return;
 button.disabled=true;
 try{const result=await api('/deployments/install',{method:'POST',body:JSON.stringify({instance_id:Number(instance.value),mode:'node',target_id:Number(node.value)})});document.getElementById('job').value=result.job_id;show('joblog',result);watchJob(result.job_id)}catch(e){button.disabled=false;show('joblog',e.message)}
}
async function job(){try{show('joblog',await api('/deployments/'+encodeURIComponent(document.getElementById('job').value)))}catch(e){show('joblog',e.message)}}

async function instanceOperation(instance,action){
 const message=document.getElementById('msg');
 const suffix='?account_id='+encodeURIComponent(instance.account_id);
 try{
  if(action==='password'){
   const result=await api('/instances/'+instance.id+'/password'+suffix);
   const dialog=document.getElementById('passworddialog');document.getElementById('savedpassword').value=result.root_pass;dialog.showModal();return;
  }
  const typed=prompt('永久删除实例 '+instance.label+' (#'+instance.id+')？磁盘数据将丢失。\n账号：'+instance.account_id+'\nIP：'+(instance.ipv4||[]).join(', ')+'\n请输入实例 ID 确认：');
  if(typed!==String(instance.id))return;
  const result=await api('/instances/'+instance.id+suffix+'&confirm_id='+instance.id,{method:'DELETE'});
  await load();message.textContent=result.warning||'实例已删除：'+instance.id;
 }catch(e){message.textContent=e.message}
}
let catalogAccount='';
async function catalogs(){
 const account=document.getElementById('account').value;
 if(!account){document.getElementById('createmsg').textContent='请先选择目标 Linode 账号';return}
 catalogAccount='';
 try{
  const [regions,types,images]=await Promise.all(['regions','types','images'].map(k=>api('/catalog/'+k)));
  if(document.getElementById('account').value!==account)return;
  for(const [id,items,label] of [
   ['createregion',regions.data,x=>x.label+' ('+x.id+')'],
   ['createtype',types.data,x=>x.label+' — USD '+x.price?.monthly+'/月，'+x.price?.hourly+'/小时（地区价格以 Linode 为准）'],
   ['createimage',images.data.filter(x=>!x.deprecated),x=>x.label+' ('+x.id+')']]){
   const select=document.getElementById(id);select.replaceChildren();
   const empty=document.createElement('option');empty.value='';empty.textContent='请选择';select.appendChild(empty);
   for(const item of items){const option=document.createElement('option');option.value=item.id;option.textContent=label(item);select.appendChild(option)}
  }
  catalogAccount=account;document.getElementById('createmsg').textContent='选项已加载；请确认套餐费用和地区后创建';
 }catch(e){document.getElementById('createmsg').textContent=e.message}
}
async function createInstance(){
 const account=document.getElementById('account');
 const region=document.getElementById('createregion'),type=document.getElementById('createtype'),image=document.getElementById('createimage');
 const password=document.getElementById('createpass'),button=document.getElementById('createbutton');
 const label=document.getElementById('createlabel').value.trim();
 const message=document.getElementById('createmsg');
 if(!account.value||catalogAccount!==account.value){message.textContent='请先选择账号并重新加载创建选项';return}
 if(label.length<3||!region.value||!type.value||!image.value||password.value.length<12){message.textContent='请填写名称、地区、套餐、系统和至少12位 Root 密码';return}
 if(button.disabled)return;
 if(!confirm('确认创建收费服务器？\n账号：'+account.selectedOptions[0].textContent+'\n名称：'+label+'\n地区：'+region.selectedOptions[0].textContent+'\nAPI 连接：'+(document.getElementById('useproxy').checked?'使用代理':'直连')+'\n套餐：'+type.selectedOptions[0].textContent+'\n系统：'+image.selectedOptions[0].textContent))return;
 button.disabled=true;account.disabled=true;message.textContent='正在提交创建请求，请勿重复操作…';
 try{
  const created=await api('/instances',{method:'POST',body:JSON.stringify({label,region:region.value,type:type.value,image:image.value,root_pass:password.value,confirm:true})});
  message.textContent='创建成功，实例 ID：'+created.id+'，状态：'+created.status+'。'+(created.password_saved?'Root 密码已加密保存。':created.warning||'Root 密码未保存，请保管原密码。')+' 请刷新查看 IP 和启动进度。';
  await load();
 }catch(e){message.textContent=e.message}
 finally{password.value='';button.disabled=false;account.disabled=false}
}

async function wp2Connection(){try{const status=await api('/wp2/session');document.getElementById('wp2connection').textContent=status.message||(status.connected?'已保存 wp2 登录会话；同步节点时验证会话是否有效':'未连接管理员账号，当前使用 muKey 节点接口')}catch(e){document.getElementById('wp2connection').textContent=e.message}}
async function connectWP2(){
 const button=document.getElementById('wp2connect'),password=document.getElementById('wp2password'),code=document.getElementById('wp2code'),message=document.getElementById('wp2connection');
 if(button.disabled)return;button.disabled=true;message.textContent='正在登录并验证管理员权限…';
 try{await api('/wp2/session',{method:'POST',body:JSON.stringify({email:document.getElementById('wp2email').value,password:password.value,code:code.value})});message.textContent='wp2 已连接';await nodes()}catch(e){message.textContent=e.message}finally{password.value='';code.value='';button.disabled=false}
}
async function disconnectWP2(){try{await api('/wp2/session',{method:'DELETE'});await wp2Connection();document.getElementById('nodes').textContent='';document.getElementById('node').replaceChildren();document.getElementById('nodehint').textContent='已断开，下次同步将使用 muKey 接口'}catch(e){document.getElementById('wp2connection').textContent=e.message}}

let installationAccount='';
function accountLabel(id){const option=Array.from(document.getElementById('account').options).find(x=>x.value===id);return option?option.textContent:id}
function updateInstallTargets(instances,account,previous){
 const select=document.getElementById('instance');select.replaceChildren();
 const placeholder=document.createElement('option');placeholder.value='';placeholder.textContent=account?'请选择运行中的 Linode 服务器':'请先在上方选择具体 Linode 账号';select.appendChild(placeholder);
 document.getElementById('installaccount').textContent=account?'当前 Linode 账号：'+accountLabel(account):'当前为全部账号视图，请先在上方选择具体 Linode 账号';
 if(!account){select.disabled=true;return}select.disabled=false;
 const available=instances.filter(i=>i.account_id===account&&i.status==='running');
 for(const instance of available){const option=document.createElement('option');option.value=String(instance.id);option.textContent=instance.label+' (#'+instance.id+') — '+(instance.ipv4||[]).join(', ')+' / '+(instance.region||'');select.appendChild(option)}
 select.value=available.some(i=>String(i.id)===previous)?previous:(available.length===1?String(available[0].id):'');
 installationAccount=account;
 if(!available.length)document.getElementById('installaccount').textContent+='；没有运行中的服务器，请先创建或开机';
}

async function proxyStatus(){try{if(!document.getElementById('account').value){document.getElementById('proxystatus').textContent='请先选择账号配置代理';return}const result=await api('/linode/proxy');document.getElementById('proxystatus').textContent=result.configured?'已保存代理：'+result.address:'当前账号未配置代理'}catch(e){document.getElementById('proxystatus').textContent=e.message}}
async function saveProxy(){const input=document.getElementById('proxyurl');try{if(!document.getElementById('account').value)throw Error('请先选择 Linode 账号');await api('/linode/proxy',{method:'PUT',body:JSON.stringify({url:input.value})});input.value='';await proxyStatus()}catch(e){document.getElementById('proxystatus').textContent=e.message}}
async function removeProxy(){try{await api('/linode/proxy',{method:'DELETE'});document.getElementById('useproxy').checked=false;await proxyStatus()}catch(e){document.getElementById('proxystatus').textContent=e.message}}

let watchedJob='';
async function watchJob(id){watchedJob=id;const button=document.getElementById('installbutton');button.disabled=true;try{while(watchedJob===id){const result=await api('/deployments/'+encodeURIComponent(id));show('joblog',result);if(result.status==='success'||result.status==='failed')break;await new Promise(resolve=>setTimeout(resolve,2500))}}catch(e){show('joblog',e.message)}finally{if(watchedJob===id){watchedJob='';button.disabled=false}}}
async function initialize(){await loadAccounts();await Promise.all([load(),nodes(),monitor(),wp2Connection(),proxyStatus()])}initialize();setInterval(()=>monitor(),30000)</script></html>`

package main

import (
 "context"
 "crypto/subtle"
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
 client *http.Client
 mu sync.RWMutex
 status map[int]Snapshot
 jobs map[string]Job
}
type Snapshot struct {
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
 ID string `json:"job_id"`
 Status string `json:"status"`
 Log string `json:"log"`
}
type Instance struct {
 ID int `json:"id"`
 Label string `json:"label"`
 Status string `json:"status"`
 IPv4 []string `json:"ipv4"`
}
func env(k,d string)string {if v:=os.Getenv(k);v!="" {return v};return d}
func number(k string,d int)int {v,e:=strconv.Atoi(os.Getenv(k));if e!=nil{return d};return v}
func send(w http.ResponseWriter,status int,v any){w.Header().Set("Content-Type","application/json");w.WriteHeader(status);_ =json.NewEncoder(w).Encode(v)}
func fail(w http.ResponseWriter,status int,e string){send(w,status,map[string]string{"error":e})}
func (s *Server) auth(next http.HandlerFunc)http.HandlerFunc{return func(w http.ResponseWriter,r *http.Request){token:=os.Getenv("ADMIN_TOKEN");auth:=r.Header.Get("Authorization");if token==""||subtle.ConstantTimeCompare([]byte(auth),[]byte("Bearer "+token))!=1{fail(w,401,"Unauthorized");return};next(w,r)}}
func (s *Server) request(ctx context.Context,method,endpoint,token string,payload io.Reader)([]byte,int,error){
 req,e:=http.NewRequestWithContext(ctx,method,endpoint,payload);if e!=nil{return nil,0,e}
 req.Header.Set("Authorization","Bearer "+token)
 if payload!=nil{req.Header.Set("Content-Type","application/json")}
 resp,e:=s.client.Do(req);if e!=nil{return nil,0,e};defer resp.Body.Close()
 b,e:=io.ReadAll(io.LimitReader(resp.Body,4<<20));return b,resp.StatusCode,e
}
func (s *Server) linode(ctx context.Context,method,path string,payload io.Reader)([]byte,int,error){
 token:=os.Getenv("LINODE_TOKEN");if token==""{return nil,503,errors.New("LINODE_TOKEN not configured")}
 return s.request(ctx,method,"https://api.linode.com/v4"+path,token,payload)
}
func (s *Server) instances(ctx context.Context)([]Instance,error){
 out:=[]Instance{}
 for page:=1;page<=100;page++{
  b,status,e:=s.linode(ctx,"GET",fmt.Sprintf("/linode/instances?page=%d&page_size=100",page),nil)
  if e!=nil{return nil,e};if status!=200{return nil,fmt.Errorf("Linode HTTP %d",status)}
  var data struct{Data []Instance `json:"data"`;Pages int `json:"pages"`}
  if e=json.Unmarshal(b,&data);e!=nil{return nil,e}
  out=append(out,data.Data...);if page>=data.Pages{break}
 }
 return out,nil
}
func (s *Server) wpNodes(w http.ResponseWriter,r *http.Request){
 base:=env("WP2_BASE_URL","");token:=os.Getenv("WP2_API_TOKEN")
 path:=env("WP2_NODES_PATH","/mod_mu/nodes")
 u,e:=url.Parse(base);if e!=nil||u.Scheme!="https"||u.Host==""||u.User!=nil||u.RawQuery!=""||u.Fragment!=""{fail(w,503,"Configure HTTPS WP2_BASE_URL");return}
 if token==""{fail(w,503,"Configure WP2_API_TOKEN");return}
 if path!="/mod_mu/nodes" {fail(w,400,"Unsupported node-list path");return}
 target:=strings.TrimRight(base,"/")+path+"?key="+url.QueryEscape(token)
 req,e:=http.NewRequestWithContext(r.Context(),"GET",target,nil);if e!=nil{fail(w,500,"Invalid request");return}
 resp,e:=s.client.Do(req);if e!=nil{fail(w,502,"wp2 unavailable");return};defer resp.Body.Close()
 if resp.StatusCode!=200{fail(w,502,fmt.Sprintf("wp2 HTTP %d",resp.StatusCode));return}
 var data struct{Ret int `json:"ret"`;Data json.RawMessage `json:"data"`}
 if e=json.NewDecoder(io.LimitReader(resp.Body,4<<20)).Decode(&data);e!=nil||data.Ret!=1{fail(w,502,"wp2 returned invalid or rejected response");return}
 var nodes []map[string]any
 if e=json.Unmarshal(data.Data,&nodes);e!=nil{fail(w,502,"wp2 nodes response malformed");return}
 // Never forward credentials or full node configuration to the browser.
 safe:=make([]map[string]any,0,len(nodes))
 for _,n:=range nodes{safe=append(safe,map[string]any{"id":n["id"],"name":n["name"],"sort":n["sort"],"status":n["status"]})}
 send(w,200,map[string]any{"nodes":safe})
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
func publicIP(i Instance)string{for _,v:=range i.IPv4{ip:=net.ParseIP(v);if ip!=nil&&ip.To4()!=nil&&!ip.IsLoopback()&&!ip.IsPrivate()&&!ip.IsLinkLocalUnicast(){return v}};return ""}
const probeScript = "python3 - <<'PY'
import json,os,time,subprocess
"+
"def cpu():
 a=list(map(int,open('/proc/stat').readline().split()[1:]));return sum(a),a[3]+a[4]
"+
"a,b=cpu();time.sleep(.25);c,d=cpu()
"+
"m={}
for line in open('/proc/meminfo'):
 k,v=line.split(':',1);m[k]=int(v.split()[0])
"+
"st=os.statvfs('/');total=st.f_blocks*st.f_frsize;free=st.f_bavail*st.f_frsize
"+
"svc=subprocess.run(['systemctl','is-active','xboard-node.service'],capture_output=True,text=True,timeout=5).stdout.strip()
"+
"print(json.dumps({'cpu':round(100*(1-(d-b)/max(1,c-a)),1),'memory':round(100*(1-m.get('MemAvailable',0)/max(1,m.get('MemTotal',1))),1),'disk':round(100*(1-free/max(1,total)),1),'uptime':int(float(open('/proc/uptime').read().split()[0])),'service':svc}))
PY
"
func (s *Server) telegram(msg string){
 token:=os.Getenv("TG_BOT_TOKEN");chat:=os.Getenv("TG_CHAT_ID");if token==""||chat==""{return}
 form:=url.Values{"chat_id":{chat},"text":{msg}}
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second);defer cancel()
 req,e:=http.NewRequestWithContext(ctx,"POST","https://api.telegram.org/bot"+token+"/sendMessage",strings.NewReader(form.Encode()));if e!=nil{return}
 req.Header.Set("Content-Type","application/x-www-form-urlencoded");resp,e:=s.client.Do(req);if e==nil{resp.Body.Close()}
}
func (s *Server) poll(ctx context.Context){
 items,e:=s.instances(ctx);if e!=nil{log.Printf("monitor: Linode list unavailable: %v",e);return}
 for _,inst:=range items{
  old:=Snapshot{};s.mu.RLock();old=s.status[inst.ID];s.mu.RUnlock()
  next:=Snapshot{ID:inst.ID,Label:inst.Label,State:"offline",Updated:time.Now().UTC().Format(time.RFC3339)}
  if inst.Status=="running"&&publicIP(inst)!=""{
   c,cancel:=context.WithTimeout(ctx,20*time.Second);output,err:=ssh(c,publicIP(inst),probeScript);cancel()
   if err==nil{
    var v struct{CPU float64 `json:"cpu"`;Memory float64 `json:"memory"`;Disk float64 `json:"disk"`;Uptime float64 `json:"uptime"`;Service string `json:"service"`}
    if json.Unmarshal([]byte(output),&v)==nil{next.State="online";next.CPU=v.CPU;next.Memory=v.Memory;next.Disk=v.Disk;next.Uptime=v.Uptime;next.Service=v.Service}
   }
  }
  if next.State=="offline"{next.Failures=old.Failures+1;if next.Failures>=number("ALERT_FAILURE_COUNT",3){next.Alert="offline"}}else{
   alarms:=[]string{}
   for _,v:=range []struct{Name string;Value float64;Limit int}{{"cpu",next.CPU,number("ALERT_CPU_PERCENT",90)},{"memory",next.Memory,number("ALERT_MEMORY_PERCENT",90)},{"disk",next.Disk,number("ALERT_DISK_PERCENT",90)}}{if v.Value>=float64(v.Limit){alarms=append(alarms,v.Name)}}
   if next.Service!="active"{alarms=append(alarms,"service")}
   next.Alert=strings.Join(alarms,",")
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
 s.poll(ctx);for{select{case <-ctx.Done():return;case <-ticker.C:s.poll(ctx)}}
}
func (s *Server) install(w http.ResponseWriter,r *http.Request){
 var in struct{InstanceID int `json:"instance_id"`;Mode string `json:"mode"`;TargetID int `json:"target_id"`}
 if json.NewDecoder(io.LimitReader(r.Body,1<<16)).Decode(&in)!=nil||in.InstanceID<=0||in.TargetID<=0||in.Mode!="node"{fail(w,400,"Valid instance_id, node mode and target_id required");return}
 token:=os.Getenv("WP2_API_TOKEN");base:=env("WP2_BASE_URL","");u,e:=url.Parse(base);if token==""||e!=nil||u.Scheme!="https"||u.Host==""{fail(w,503,"wp2 not configured");return}
 b,st,e:=s.linode(r.Context(),"GET",fmt.Sprintf("/linode/instances/%d",in.InstanceID),nil);if e!=nil||st!=200{fail(w,502,"Linode instance lookup failed");return}
 var inst Instance;if json.Unmarshal(b,&inst)!=nil||inst.Status!="running"||publicIP(inst)==""{fail(w,409,"Running public IPv4 instance required");return}
 id:=strconv.FormatInt(time.Now().UnixNano(),36)
 s.mu.Lock();s.jobs[id]=Job{ID:id,Status:"queued"};s.mu.Unlock()
 go func(){
  s.mu.Lock();s.jobs[id]=Job{ID:id,Status:"running"};s.mu.Unlock()
  ctx,cancel:=context.WithTimeout(context.Background(),15*time.Minute);defer cancel()
  // Use remote bash stdin to avoid placing the token in the ssh command line.
  script:="set -e
curl -fsSL https://raw.githubusercontent.com/acc66/XboardNode-Plus/main/install.sh -o /tmp/xboard-install.sh
bash /tmp/xboard-install.sh --mode node --panel "+shellQuote(base)+" --token "+shellQuote(token)+" --node-id "+strconv.Itoa(in.TargetID)+"
"
  output,err:=ssh(ctx,publicIP(inst),script)
  output=strings.ReplaceAll(output,token,"[REDACTED]")
  if len(output)>12000{output=output[len(output)-12000:]}
  state:="success";if err!=nil{state="failed";output+="
Installation failed"}
  s.mu.Lock();s.jobs[id]=Job{ID:id,Status:state,Log:output};s.mu.Unlock()
 }()
 send(w,202,map[string]string{"job_id":id,"status":"queued"})
}
func shellQuote(s string)string{return "'"+strings.ReplaceAll(s,"'","'\''")+"'"}
func main(){
 s:=&Server{client:&http.Client{Timeout:35*time.Second,CheckRedirect:func(_ *http.Request,_ []*http.Request)error{return http.ErrUseLastResponse}},status:map[int]Snapshot{},jobs:map[string]Job{}}
 mux:=http.NewServeMux()
 mux.HandleFunc("GET /",func(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","text/html; charset=utf-8");io.WriteString(w,htmlPage)})
 mux.HandleFunc("GET /api/health",s.auth(func(w http.ResponseWriter,r *http.Request){send(w,200,map[string]string{"status":"ok","language":"go"})}))
 mux.HandleFunc("GET /api/instances",s.auth(func(w http.ResponseWriter,r *http.Request){items,e:=s.instances(r.Context());if e!=nil{fail(w,502,"Linode API unavailable");return};send(w,200,map[string]any{"instances":items})}))
 mux.HandleFunc("GET /api/wp2/nodes",s.auth(s.wpNodes))
 mux.HandleFunc("GET /api/monitor",s.auth(func(w http.ResponseWriter,r *http.Request){s.mu.RLock();defer s.mu.RUnlock();items:=[]Snapshot{};for _,v:=range s.status{items=append(items,v)};send(w,200,map[string]any{"instances":items})}))
 mux.HandleFunc("POST /api/deployments/install",s.auth(s.install))
 mux.HandleFunc("GET /api/deployments/{id}",s.auth(func(w http.ResponseWriter,r *http.Request){s.mu.RLock();v,ok:=s.jobs[r.PathValue("id")];s.mu.RUnlock();if !ok{fail(w,404,"Unknown job");return};send(w,200,v)}))
 mux.HandleFunc("POST /api/instances/{id}/{action}",s.auth(func(w http.ResponseWriter,r *http.Request){id,e:=strconv.Atoi(r.PathValue("id"));action:=r.PathValue("action");if e!=nil||id<=0||(action!="boot"&&action!="shutdown"&&action!="reboot"){fail(w,400,"Invalid action");return};b,st,e:=s.linode(r.Context(),"POST",fmt.Sprintf("/linode/instances/%d/%s",id,action),strings.NewReader("{}"));if e!=nil{fail(w,502,"Linode API unavailable");return};w.Header().Set("Content-Type","application/json");w.WriteHeader(st);w.Write(b)}))
 ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 if env("MONITOR_ENABLED","false")=="true"{go s.monitoring(ctx)}
 addr:=env("LISTEN_ADDR","0.0.0.0:8000");log.Printf("Linode Node Manager Go listening on %s",addr);log.Fatal(http.ListenAndServe(addr,mux))
}
const htmlPage = `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Linode Node Manager Go</title><style>body{background:#0f172a;color:#e2e8f0;font:15px system-ui;max-width:1000px;margin:auto;padding:24px}section{background:#1e293b;border-radius:12px;padding:18px;margin:14px 0}input,select,button{padding:9px;margin:4px;background:#334155;color:white;border:1px solid #64748b;border-radius:7px}button{background:#2563eb;cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere}table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #475569}</style><h1>Linode Go 管理面板</h1><section><input type="password" id="token" placeholder="ADMIN_TOKEN"><button onclick="load()">刷新</button><p id="msg"></p></section><section><h2>服务器</h2><div id="instances"></div></section><section><h2>wp2 节点</h2><button onclick="nodes()">获取节点</button><pre id="nodes"></pre></section><section><h2>安装 XboardNode-Plus</h2><input id="instance" type="number" placeholder="Linode ID"><input id="node" type="number" placeholder="wp2 节点 ID"><button onclick="install()">安装</button><input id="job" placeholder="任务 ID"><button onclick="job()">查询任务</button><pre id="joblog"></pre></section><section><h2>CPU / 内存 / 磁盘</h2><button onclick="monitor()">刷新监控</button><pre id="metrics"></pre></section><script>const token=()=>document.getElementById('token').value;async function api(path,options={}){let r=await fetch('/api'+path,{...options,headers:{Authorization:'Bearer '+token(),'Content-Type':'application/json'}});let j=await r.json();if(!r.ok)throw Error(j.error||r.status);return j}const show=(id,x)=>document.getElementById(id).textContent=JSON.stringify(x,null,2);async function load(){try{let d=await api('/instances');show('instances',d.instances);document.getElementById('msg').textContent='已加载 '+d.instances.length+' 台'}catch(e){document.getElementById('msg').textContent=e.message}}async function nodes(){try{show('nodes',(await api('/wp2/nodes')).nodes)}catch(e){show('nodes',e.message)}}async function monitor(){try{show('metrics',(await api('/monitor')).instances)}catch(e){show('metrics',e.message)}}async function install(){if(!confirm('确认在服务器安装后端？'))return;try{let d=await api('/deployments/install',{method:'POST',body:JSON.stringify({instance_id:Number(document.getElementById('instance').value),mode:'node',target_id:Number(document.getElementById('node').value)})});document.getElementById('job').value=d.job_id;show('joblog',d)}catch(e){show('joblog',e.message)}}async function job(){try{show('joblog',await api('/deployments/'+encodeURIComponent(document.getElementById('job').value)))}catch(e){show('joblog',e.message)}}setInterval(()=>{if(token())monitor()},30000)</script></html>`

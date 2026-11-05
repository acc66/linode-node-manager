import os, secrets, sqlite3
from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

DB=os.getenv("DB_PATH","/data/manager.db")
TOKEN=os.getenv("ADMIN_TOKEN","")
LINODE_TOKEN=os.getenv("LINODE_TOKEN","")
BASE="https://api.linode.com/v4"

def db():
    os.makedirs(os.path.dirname(os.path.abspath(DB)),exist_ok=True)
    c=sqlite3.connect(DB)
    c.row_factory=sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS deployments (id INTEGER PRIMARY KEY, linode_id INTEGER UNIQUE, label TEXT, region TEXT, node_id INTEGER, state TEXT, detail TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
    c.commit()
    return c

@asynccontextmanager
async def lifespan(app):
    c=db()
    c.close()
    yield

app=FastAPI(title="Linode Node Manager",lifespan=lifespan)
from deploy import register as register_deployments
from wp2 import register as register_wp2

def auth(authorization:str=Header(default="")):
    if not TOKEN or not secrets.compare_digest(authorization,"Bearer "+TOKEN):
        raise HTTPException(401,"Unauthorized")

async def linode(method,path,payload=None):
    if not LINODE_TOKEN:
        raise HTTPException(503,"LINODE_TOKEN not configured")
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response=await client.request(method,BASE+path,headers={"Authorization":"Bearer "+LINODE_TOKEN},json=payload)
    except httpx.HTTPError:
        raise HTTPException(502,"Linode API unavailable")
    if response.status_code>=400:
        raise HTTPException(response.status_code,{"provider":"linode","error":response.text[:1000]})
    return response.json() if response.content else {}

register_deployments(app,auth,linode)
register_wp2(app,auth)
\nclass Create(BaseModel):
    label:str=Field(min_length=3,max_length=64,pattern=r"^[a-zA-Z0-9-]+$")
    region:str
    type:str
    image:str="linode/debian12"
    authorized_keys:list[str]=Field(min_length=1)
    node_id:int|None=None
    confirm_billable:bool=False

@app.get("/api/regions",dependencies=[Depends(auth)])
async def regions():
    return await linode("GET","/regions")

@app.get("/api/types",dependencies=[Depends(auth)])
async def types():
    return await linode("GET","/linode/types")

@app.get("/api/instances",dependencies=[Depends(auth)])
async def instances():
    items=[]
    page=1
    while True:
        result=await linode("GET",f"/linode/instances?page={page}&page_size=100")
        items.extend(result.get("data",[]))
        if page>=result.get("pages",1):
            break
        page+=1
    c=db()
    deployments=[dict(row) for row in c.execute("SELECT * FROM deployments ORDER BY id DESC")]
    c.close()
    return {"instances":items,"deployments":deployments}

@app.post("/api/instances",dependencies=[Depends(auth)])
async def create(body:Create):
    if not body.confirm_billable:
        raise HTTPException(400,"Confirm billable operation")
    result=await linode("POST","/linode/instances",body.model_dump(exclude={"node_id","confirm_billable"}))
    c=db()
    c.execute("INSERT INTO deployments(linode_id,label,region,node_id,state,detail) VALUES (?,?,?,?,?,?)",(result["id"],body.label,body.region,body.node_id,"created","Awaiting backend configuration"))
    c.commit()
    c.close()
    return result

@app.post("/api/instances/{instance_id}/{action}",dependencies=[Depends(auth)])
async def action(instance_id:int,action:str):
    if action not in ("boot","reboot","shutdown"):
        raise HTTPException(400,"Unsupported action")
    return await linode("POST",f"/linode/instances/{instance_id}/{action}",{})

@app.delete("/api/instances/{instance_id}",dependencies=[Depends(auth)])
async def delete(instance_id:int,confirm:str=""):
    if confirm!=str(instance_id):
        raise HTTPException(400,"Supply confirm=<instance_id> to permanently delete")
    await linode("DELETE",f"/linode/instances/{instance_id}")
    c=db()
    c.execute("UPDATE deployments SET state='deleted' WHERE linode_id=?",(instance_id,))
    c.commit()
    c.close()
    return {"deleted":instance_id}

@app.get("/api/health",dependencies=[Depends(auth)])
async def health():
    return {"status":"ok","wp2_integration":"not_configured","backend_autodeploy":"not_configured"}

@app.get("/",response_class=HTMLResponse)
async def home():
    return """<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Linode Node Manager</title>
<style>body{font-family:system-ui;background:#0f172a;color:#e2e8f0;max-width:1100px;margin:30px auto;padding:16px}input,button{padding:10px;border-radius:8px;border:1px solid #475569;background:#1e293b;color:white;margin:5px}button{cursor:pointer;background:#2563eb}table{width:100%;border-collapse:collapse}td,th{padding:10px;border-bottom:1px solid #334155;text-align:left}.card{padding:18px;background:#1e293b;border-radius:12px;margin:15px 0}small{color:#94a3b8}</style>
<h1>Linode 云服务器管理</h1><p>独立控制台 · 实例创建 / 状态 / 操作</p>
<div class="card"><label>管理令牌 <input type="password" id="token" placeholder="ADMIN_TOKEN"></label><button onclick="load()">连接并刷新</button><p id="msg"></p></div>
<div class="card"><h2>创建实例</h2><input id="label" placeholder="实例名称"><input id="region" placeholder="区域，例如 ap-south"><input id="type" placeholder="套餐，例如 g6-nanode-1"><input id="key" placeholder="SSH 公钥"><button onclick="create()">创建（会产生费用）</button><small>请先核实 Linode 套餐价格和区域。</small></div>
<div class="card"><h2>wp2 节点及一键安装</h2><p><small>wp2 节点列表接口需在服务端配置 WP2_NODES_PATH；不在浏览器保存 API Token。</small></p><button onclick="nodes()">获取 wp2 节点</button><div id="nodes"></div><input id="did" type="number" placeholder="Linode 实例 ID"><select id="mode"><option value="node">节点模式</option><option value="machine">机器模式</option></select><input id="tid" type="number" placeholder="节点 / 机器 ID"><button onclick="install()">安装 XboardNode-Plus</button><input id="job" placeholder="任务 ID"><button onclick="checkjob()">查询安装日志</button><pre id="log" style="white-space:pre-wrap;overflow-wrap:anywhere"></pre></div><div class="card"><h2>服务器列表</h2><div id="list">请先输入管理令牌</div></div>
<script>
function hdr(){return {'Authorization':'Bearer '+document.getElementById('token').value,'Content-Type':'application/json'}}
async function req(path,opts={}){let r=await fetch('/api'+path,{...opts,headers:hdr()});let j=await r.json().catch(()=>({}));if(!r.ok)throw Error(JSON.stringify(j));return j}
function msg(s){document.getElementById('msg').textContent=s}
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function load(){try{let x=await req('/instances');let rows=x.instances.map(i=>`<tr><td>${esc(i.label)}</td><td>${esc(i.region)}</td><td>${esc(i.status)}</td><td>${esc((i.ipv4||[]).join(', '))}</td><td><button onclick="act(${i.id},'boot')">开机</button><button onclick="act(${i.id},'shutdown')">关机</button><button onclick="act(${i.id},'reboot')">重启</button><button onclick="del(${i.id})">删除</button></td></tr>`).join('');document.getElementById('list').innerHTML='<table><tr><th>名称</th><th>区域</th><th>状态</th><th>IP</th><th>操作</th></tr>'+rows+'</table>';msg('已同步 '+x.instances.length+' 台实例')}catch(e){msg(e.message)}}
async function act(id,a){try{await req('/instances/'+id+'/'+a,{method:'POST'});await load()}catch(e){msg(e.message)}}
async function del(id){if(prompt('输入实例 ID '+id+' 确认永久删除')!==String(id))return;try{await req('/instances/'+id+'?confirm='+id,{method:'DELETE'});await load()}catch(e){msg(e.message)}}
async function create(){if(!confirm('确认创建付费 Linode 实例？'))return;try{let x=await req('/instances',{method:'POST',body:JSON.stringify({label:document.getElementById('label').value,region:document.getElementById('region').value,type:document.getElementById('type').value,authorized_keys:[document.getElementById('key').value],confirm_billable:true})});msg('创建成功，实例 ID '+x.id);await load()}catch(e){msg(e.message)}}
async function nodes(){try{let d=await req("/wp2/nodes");document.getElementById("nodes").textContent=JSON.stringify(d,null,2)}catch(e){msg(e.message)}}
async function install(){if(!confirm("确认在选中服务器安装或重配 XboardNode-Plus？"))return;try{let d=await req("/deployments/install",{method:"POST",body:JSON.stringify({instance_id:Number(document.getElementById("did").value),mode:document.getElementById("mode").value,target_id:Number(document.getElementById("tid").value)})});document.getElementById("job").value=d.job_id;msg("任务已提交 "+d.job_id)}catch(e){msg(e.message)}}
async function checkjob(){try{let d=await req("/deployments/"+encodeURIComponent(document.getElementById("job").value));document.getElementById("log").textContent=d.status+"\\n"+d.log}catch(e){msg(e.message)}}\n</script></html>"""

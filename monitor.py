"""SSH resource monitoring and Telegram alert loop for managed Linodes."""
import asyncio
import json
import os
import sqlite3
import time
from contextlib import suppress
from datetime import datetime, timezone

import asyncssh
import httpx
from fastapi import Depends, HTTPException

DB=os.getenv("DB_PATH","/data/manager.db")
INTERVAL=max(30,int(os.getenv("MONITOR_INTERVAL","60")))
FAIL_LIMIT=max(2,int(os.getenv("ALERT_FAILURE_COUNT","3")))
CPU_LIMIT=float(os.getenv("ALERT_CPU_PERCENT","90"))
MEM_LIMIT=float(os.getenv("ALERT_MEMORY_PERCENT","90"))
DISK_LIMIT=float(os.getenv("ALERT_DISK_PERCENT","90"))
SAMPLES={}
RUNNING=None

SCRIPT=r"""python3 - <<'PY'
import json,os,time,subprocess
def cpu():
 d={}
 for line in open('/proc/stat'):
  if line.startswith('cpu '):
   a=list(map(int,line.split()[1:]));return sum(a),a[3]+a[4]
 return 0,0
t1,i1=cpu();time.sleep(.25);t2,i2=cpu()
m={}
for line in open('/proc/meminfo'):
 k,v=line.split(':',1);m[k]=int(v.strip().split()[0])
st=os.statvfs('/')
total=st.f_blocks*st.f_frsize;free=st.f_bavail*st.f_frsize
service=subprocess.run(['systemctl','is-active','xboard-node.service'],capture_output=True,text=True,timeout=5).stdout.strip()
print(json.dumps({'cpu':round(100*(1-(i2-i1)/max(1,t2-t1)),1),'memory':round(100*(1-m.get('MemAvailable',0)/max(1,m.get('MemTotal',1))),1),'disk':round(100*(1-free/max(1,total)),1),'uptime':int(float(open('/proc/uptime').read().split()[0])),'service':service}))
PY"""

def db():
 c=sqlite3.connect(DB,timeout=10)
 c.execute("CREATE TABLE IF NOT EXISTS monitor_status (instance_id INTEGER PRIMARY KEY,label TEXT,status TEXT,cpu REAL,memory REAL,disk REAL,uptime INTEGER,service TEXT,failures INTEGER DEFAULT 0,updated_at TEXT,alert_state TEXT DEFAULT '')")
 c.commit()
 return c

async def telegram(message):
 token=os.getenv("TG_BOT_TOKEN","")
 chat=os.getenv("TG_CHAT_ID","")
 if not token or not chat:return
 try:
  async with httpx.AsyncClient(timeout=10) as client:
   await client.post(f"https://api.telegram.org/bot{token}/sendMessage",json={"chat_id":chat,"text":message},follow_redirects=False)
 except httpx.HTTPError:
  pass

async def probe(instance):
 key=os.getenv("SSH_PRIVATE_KEY_PATH","/run/secrets/linode_ssh_key")
 known=os.getenv("SSH_KNOWN_HOSTS_PATH","/run/secrets/known_hosts")
 if not os.path.isfile(key) or not os.path.isfile(known):
  raise RuntimeError("SSH credentials not configured")
 ips=instance.get("ipv4") or []
 if not ips:raise RuntimeError("No IPv4")
 async with asyncssh.connect(ips[0],username=os.getenv("MONITOR_SSH_USER","root"),client_keys=[key],known_hosts=known,connect_timeout=8) as conn:
  r=await asyncio.wait_for(conn.run("bash -s",input=SCRIPT,check=True),timeout=20)
  return json.loads(r.stdout)

async def check_all(linode):
 try:
  page=1;items=[]
  while True:
   d=await linode("GET",f"/linode/instances?page={page}&page_size=100")
   items+=d.get("data",[])
   if page>=d.get("pages",1):break
   page+=1
 except Exception:
  return
 async def one(inst):
  ident=inst["id"];label=inst.get("label",str(ident));status="offline";metric={}
  try:
   if inst.get("status")!="running":raise RuntimeError("Linode state: "+str(inst.get("status")))
   metric=await probe(inst)
   status="online"
  except Exception:
   pass
  now=datetime.now(timezone.utc).isoformat()
  c=db()
  old=c.execute("SELECT status,failures,alert_state FROM monitor_status WHERE instance_id=?",(ident,)).fetchone()
  fails=0 if status=="online" else (old[1] if old else 0)+1
  alarms=[]
  if status=="offline" and fails>=FAIL_LIMIT:alarms.append("offline")
  if status=="online":
   for k,limit in (("cpu",CPU_LIMIT),("memory",MEM_LIMIT),("disk",DISK_LIMIT)):
    if metric.get(k,0)>=limit:alarms.append(k)
   if metric.get("service") not in ("active",):alarms.append("service")
  state=",".join(alarms)
  previous=old[2] if old else ""
  c.execute("""INSERT INTO monitor_status(instance_id,label,status,cpu,memory,disk,uptime,service,failures,updated_at,alert_state) VALUES(?,?,?,?,?,?,?,?,?,?,?)
   ON CONFLICT(instance_id) DO UPDATE SET label=excluded.label,status=excluded.status,cpu=excluded.cpu,memory=excluded.memory,disk=excluded.disk,uptime=excluded.uptime,service=excluded.service,failures=excluded.failures,updated_at=excluded.updated_at,alert_state=excluded.alert_state""",
   (ident,label,status,metric.get("cpu"),metric.get("memory"),metric.get("disk"),metric.get("uptime"),metric.get("service"),fails,now,state))
  c.commit();c.close()
  if state!=previous:
   if state:await telegram("🚨 Linode 告警: "+label+" (#"+str(ident)+")\n异常: "+state)
   elif previous:await telegram("✅ Linode 恢复: "+label+" (#"+str(ident)+")\n此前异常: "+previous)
 await asyncio.gather(*(one(i) for i in items))

async def loop(linode):
 while True:
  try:await check_all(linode)
  except Exception:pass
  await asyncio.sleep(INTERVAL)

def register(app,auth,linode):
 global RUNNING
 @app.get("/api/monitor",dependencies=[Depends(auth)])
 async def get_monitor():
  c=db()
  c.row_factory=sqlite3.Row
  result=[dict(x) for x in c.execute("SELECT * FROM monitor_status ORDER BY label")]
  c.close()
  return {"instances":result,"interval":INTERVAL}
 async def start():
  global RUNNING
  c=db();c.close()
  if os.getenv("MONITOR_ENABLED","false").lower()=="true":
   RUNNING=asyncio.create_task(loop(linode))
 async def stop():
  global RUNNING
  if RUNNING:
   RUNNING.cancel()
   with suppress(asyncio.CancelledError):await RUNNING
 app.add_event_handler("startup",start)
 app.add_event_handler("shutdown",stop)

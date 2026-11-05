"""SSH deployment of XboardNode-Plus to existing Linode instances.

Linode API controls VM lifecycle; SSH is required to run software inside an existing VM.
"""
import asyncio
import ipaddress
import os
import re
import secrets
import shlex
from datetime import datetime, timezone

import asyncssh
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/deployments", tags=["deployments"])
JOBS = {}
LOCK = asyncio.Lock()
INSTALL_URL = "https://raw.githubusercontent.com/acc66/XboardNode-Plus/main/install.sh"

def authorized():
    # Avoid import cycle; use same ADMIN_TOKEN policy as main application.
    from fastapi import Header
    raise RuntimeError("Use dependency override in app")

class InstallRequest(BaseModel):
    instance_id: int = Field(gt=0)
    panel_url: str = Field(pattern=r"^https://[^\s/]+", max_length=255)
    panel_token: str = Field(min_length=1, max_length=4096)
    mode: str = Field(pattern=r"^(node|machine)$")
    target_id: int = Field(gt=0)
    ssh_user: str = Field(default="root", pattern=r"^[a-z_][a-z0-9_-]*$", max_length=32)

def clean_log(s, secret):
    return s.replace(secret, "[REDACTED]")[-12000:]

async def perform(job_id, body, ip):
    job=JOBS[job_id]\n    panel_url=os.getenv("WP2_BASE_URL","").rstrip("/")\n    panel_token=os.getenv("WP2_API_TOKEN","")\n    if not panel_url.startswith("https://") or not panel_token:\n        job["status"]="failed"\n        job["log"]="Configure WP2_BASE_URL and WP2_API_TOKEN"\n        return
    key=os.getenv("SSH_PRIVATE_KEY_PATH","/run/secrets/linode_ssh_key")
    known=os.getenv("SSH_KNOWN_HOSTS_PATH","/run/secrets/known_hosts")
    try:
        if not os.path.isfile(key) or not os.path.isfile(known):
            raise RuntimeError("SSH private key / known_hosts not configured")
        job["status"]="running"
        async with asyncssh.connect(ip, username=body.ssh_user, client_keys=[key], known_hosts=known, connect_timeout=20) as conn:
            mode_arg="--node-id" if body.mode=="node" else "--machine-id"
            args=["--mode",body.mode,"--panel",panel_url,"--token",panel_token,mode_arg,str(body.target_id)]
            script=("set -euo pipefail\n"
                    "test \"$(id -u)\" = 0\n"
                    "command -v curl >/dev/null || (apt-get update -qq && apt-get install -y -qq curl ca-certificates)\n"
                    "tmp=$(mktemp)\ntrap 'rm -f \"$tmp\"' EXIT\n"
                    "curl -fsSL "+shlex.quote(INSTALL_URL)+" -o \"$tmp\"\n"
                    "bash \"$tmp\" "+" ".join(shlex.quote(x) for x in args)+"\n"
                    "systemctl is-active xboard-node.service\n")
            result=await asyncio.wait_for(conn.run("bash -s",input=script,check=False),timeout=900)
            job["log"]=clean_log(result.stdout+"\n"+result.stderr,panel_token)
            if result.exit_status != 0:
                raise RuntimeError("Installer exited with status "+str(result.exit_status))
        job["status"]="success"
    except Exception as exc:
        job["status"]="failed"
        job["log"]=clean_log(job["log"]+"\n"+str(exc),panel_token)
    finally:
        job["updated_at"]=datetime.now(timezone.utc).isoformat()

def register(app, auth, linode):
    async def install(body: InstallRequest, _:None=Depends(auth)):
        key=os.getenv("SSH_PRIVATE_KEY_PATH","/run/secrets/linode_ssh_key")
        known=os.getenv("SSH_KNOWN_HOSTS_PATH","/run/secrets/known_hosts")
        if not os.path.isfile(key) or not os.path.isfile(known):
            raise HTTPException(503,"Configure SSH_PRIVATE_KEY_PATH and SSH_KNOWN_HOSTS_PATH")
        inst=await linode("GET",f"/linode/instances/{body.instance_id}")
        if inst.get("status")!="running":
            raise HTTPException(409,"Instance must be running")
        ips=inst.get("ipv4",[])
        public=[]
        for ip in ips:
            addr=ipaddress.ip_address(ip)
            if addr.version==4 and addr.is_global:
                public.append(ip)
        if not public:
            raise HTTPException(400,"No public IPv4 address")
        async with LOCK:
            if any(j["instance_id"]==body.instance_id and j["status"] in ("queued","running") for j in JOBS.values()):
                raise HTTPException(409,"Deployment already in progress")
            job_id=secrets.token_hex(12)
            JOBS[job_id]={"id":job_id,"instance_id":body.instance_id,"status":"queued","log":"","updated_at":datetime.now(timezone.utc).isoformat()}
            asyncio.create_task(perform(job_id,body,public[0]))
        return {"job_id":job_id,"status":"queued"}

    async def status(job_id:str, _:None=Depends(auth)):
        if job_id not in JOBS:
            raise HTTPException(404,"Job not found")
        return JOBS[job_id]

    router.add_api_route("/install",install,methods=["POST"])
    router.add_api_route("/{job_id}",status,methods=["GET"])
    app.include_router(router)

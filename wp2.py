"""Configurable wp2 API adapter. No assumptions about wp2 private API routes."""
import os
from urllib.parse import urlparse
import httpx
from fastapi import Depends, HTTPException

def register(app, auth):
    @app.get("/api/wp2/nodes", dependencies=[Depends(auth)])
    async def nodes():
        base=os.getenv("WP2_BASE_URL","").rstrip("/")
        path=os.getenv("WP2_NODES_PATH","")
        token=os.getenv("WP2_API_TOKEN","")
        header=os.getenv("WP2_AUTH_HEADER","Authorization")
        scheme=os.getenv("WP2_AUTH_SCHEME","Bearer")
        if not base.startswith("https://") or not token or not path:
            raise HTTPException(503,"Configure WP2_BASE_URL, WP2_API_TOKEN and WP2_NODES_PATH")
        parsed=urlparse(base)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise HTTPException(400,"Invalid WP2_BASE_URL")
        if not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path or "\\" in path:
            raise HTTPException(400,"Invalid WP2_NODES_PATH")
        # Strict path-only relative request; do not follow redirects that may leak credentials.
        if header.lower() not in ("authorization","x-api-key"):
            raise HTTPException(400,"Unsupported WP2_AUTH_HEADER")
        headers={header:((scheme+" ") if scheme else "")+token}
        try:
            async with httpx.AsyncClient(timeout=15,follow_redirects=False) as client:
                res=await client.get(base+path,headers=headers)
        except httpx.RequestError:
            raise HTTPException(502,"wp2 API connection failed")
        if res.status_code in (301,302,303,307,308):
            raise HTTPException(502,"wp2 API redirected; check base URL and path")
        if res.status_code>=400:
            raise HTTPException(502,f"wp2 API returned HTTP {res.status_code}")
        try:
            data=res.json()
        except ValueError:
            raise HTTPException(502,"wp2 API did not return JSON")
        return {"source":"wp2","data":data}

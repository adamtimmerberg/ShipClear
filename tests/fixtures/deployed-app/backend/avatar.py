# FIXTURE: the same feature done right — must produce no SSRF finding.
import ipaddress
import socket

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl

router = APIRouter()


class AvatarRequest(BaseModel):
    url: HttpUrl


@router.post("/api/avatar")
async def fetch_avatar(payload: AvatarRequest):
    host = payload.url.host
    if not ipaddress.ip_address(socket.gethostbyname(host)).is_global:
        raise HTTPException(400, "that address is not on the public internet")
    async with httpx.AsyncClient(follow_redirects=False) as client:
        return await client.get(str(payload.url))

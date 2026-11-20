# FIXTURE: an address check that a redirect walks straight around.
import ipaddress

import httpx
from fastapi import APIRouter
from pydantic import BaseModel, HttpUrl

router = APIRouter()


class PreviewRequest(BaseModel):
    url: HttpUrl


@router.post("/api/preview")
async def preview(payload: PreviewRequest):
    if not ipaddress.ip_address(payload.url.host).is_global:
        return {"error": "private address"}
    async with httpx.AsyncClient(follow_redirects=True) as client:
        return (await client.get(str(payload.url))).text

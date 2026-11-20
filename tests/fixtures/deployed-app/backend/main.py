# FIXTURE: the shapes a real review found in an AI-built FastAPI app.
import httpx
from fastapi import FastAPI
from prometheus_client import generate_latest
from pydantic import BaseModel, HttpUrl

from .config import settings

# Correct: the docs only exist outside production. Must NOT be reported.
app = FastAPI(docs_url="/api/docs" if not settings.is_production else None)


class ImportRequest(BaseModel):
    url: HttpUrl


@app.get("/api/metrics")
def metrics():
    return generate_latest()


@app.post("/api/import")
async def import_recipe(payload: ImportRequest):
    async with httpx.AsyncClient(follow_redirects=True) as client:
        response = await client.get(str(payload.url))
    return {"html": response.text}

from fastapi import FastAPI
from app.api.endpoints import auth

app = FastAPI(openapi_version="3.1.0")

app.include_router(auth.router, prefix="/auth", tags=["auth"])
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from contextlib import asynccontextmanager
import time

from app.core.config import settings
from .database import engine, Base
from .routers import auth


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    print("Startup: Database tables checked/created")
    yield


middleware = [
    Middleware(SessionMiddleware, secret_key=settings.SECRET_KEY),

    Middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "badgerapi.acadmate.in"]),
    Middleware(CORSMiddleware,
               allow_origins=["http://localhost:3000", "https://badgerapi.acadmate.in"],
               allow_credentials=True,
               allow_methods=["*"],
               allow_headers=["*"]),

    Middleware(GZipMiddleware, minimum_size=1000)
]

app = FastAPI(
    title="Badger Ai Api",
    description="Badger Ai Api",
    version="1.0.0",
    lifespan=lifespan,
    middleware=middleware
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


app.include_router(auth.router, prefix="/auth", tags=["Authentication"])


@app.get("/")
def health_check():
    return {"status": "ok", "message": "Nice and Healthy"}
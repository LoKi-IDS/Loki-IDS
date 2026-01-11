"""
Main FastAPI application for Loki IDS Web Interface.
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import os

from .models.database import init_db
from .routes import alerts, signatures, blacklist, stats, system, websocket

# Create FastAPI app
app = FastAPI(
    title="Loki IDS API",
    description="Web Interface API for Loki Intrusion Detection System",
    version="1.0.0"
)

# CORS middleware (allow local network access)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(alerts.router, prefix="/api")
app.include_router(signatures.router, prefix="/api")
app.include_router(blacklist.router, prefix="/api")
app.include_router(stats.router, prefix="/api")
app.include_router(system.router, prefix="/api")
app.include_router(websocket.router)


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    await init_db()
    print("[*] Database initialized")


@app.get("/")
async def root():
    """Serve the dashboard frontend."""
    static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Loki IDS API", "docs": "/docs"}


# Mount static files
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


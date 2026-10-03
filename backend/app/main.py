import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.app.api.analyze import router as analyze_router
from backend.app.api.metrics import router as metrics_router
from backend.app.api.health import router as health_router

app = FastAPI(
    title="PhishGuard-AI API",
    description="Intelligent Phishing URL Detection Using ML and Explainable Analytics (XAI)",
    version="1.0.0"
)

# Enable CORS for frontend interactions
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(health_router)
app.include_router(analyze_router)
app.include_router(metrics_router)

# Mount frontend build if available
FRONTEND_DIST = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../frontend/dist"))
if os.path.exists(FRONTEND_DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIST, "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        file_path = os.path.join(FRONTEND_DIST, full_path)
        if full_path and os.path.exists(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(FRONTEND_DIST, "index.html"))
else:
    @app.get("/")
    async def root():
        return {
            "name": "PhishGuard-AI",
            "tagline": "Intelligent Phishing URL Detection Using ML and Explainable Analytics",
            "documentation": "/docs",
            "health": "/api/health",
            "metrics": "/api/metrics",
            "samples": "/api/samples"
        }

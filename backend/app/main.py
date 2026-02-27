"""
AI PII Redactor - FastAPI Application
Multi-Modal Privacy Preservation Framework

Production-ready entry point for Railway deployment.
Includes MySQL connectivity, CORS, logging, and route registration.
"""

import os
import time
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import pymysql

from app.routers import redaction

# ── Logging ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ── Startup timestamp ───────────────────────────────────
START_TIME = time.time()

# ── MySQL helper ─────────────────────────────────────────
def _get_db_connection():
    """Return a fresh PyMySQL connection using Railway env vars."""
    return pymysql.connect(
        host=os.environ.get("MYSQLHOST", "localhost"),
        port=int(os.environ.get("MYSQLPORT", 3306)),
        user=os.environ.get("MYSQLUSER", "root"),
        password=os.environ.get("MYSQLPASSWORD", ""),
        database=os.environ.get("MYSQLDATABASE", "railway"),
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=10,
    )


# ── FastAPI app ──────────────────────────────────────────
app = FastAPI(
    title="AI PII Redactor",
    description="""
    ## Multi-Modal Privacy Preservation Framework

    An AI-driven PII redaction system that combines:
    - **Regex Pattern Engine** for structured identifiers
    - **NLP (spaCy NER)** for contextual entity detection
    - **OCR Pipeline** for image/PDF processing
    - **Multiple Redaction Strategies**: masking, tagging, anonymization, hashing

    ### Supported Formats
    - Plain text
    - PDF documents
    - Images (PNG, JPG)
    - CSV & JSON datasets

    ### API Endpoints
    - `/api/v1/redact/text` — Redact PII from text
    - `/api/v1/redact/file` — Redact PII from uploaded files
    - `/api/v1/redact/batch` — Batch text redaction
    - `/api/v1/strategies` — List redaction strategies
    - `/api/v1/entity-types` — List detected entity types
    - `/api/v1/stats` — Processing statistics
    - `/api/v1/health` — Health check
    - `/db-test` — Verify MySQL connectivity
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS (allow all origins for hackathon demo) ─────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "Content-Type", "Content-Length"],
)

# ── Register existing routers ───────────────────────────
app.include_router(redaction.router)


# ── Routes ──────────────────────────────────────────────
@app.get("/")
async def root():
    """Health / info route."""
    uptime = time.time() - START_TIME
    return {
        "status": "ok",
        "name": "AI PII Redactor",
        "version": "1.0.0",
        "description": "Multi-Modal Privacy Preservation Framework",
        "uptime_seconds": round(uptime, 2),
        "docs": "/docs",
        "api_base": "/api/v1",
        "environment": "production" if os.environ.get("RAILWAY_ENVIRONMENT") else "development",
    }


@app.get("/db-test")
async def db_test():
    """Verify MySQL database connectivity."""
    try:
        conn = _get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1 AS alive")
            row = cursor.fetchone()
        conn.close()
        return {
            "status": "connected",
            "database": os.environ.get("MYSQLDATABASE", "railway"),
            "host": os.environ.get("MYSQLHOST", "localhost"),
            "result": row,
        }
    except Exception as exc:
        logger.error("Database connection failed: %s", exc)
        return {
            "status": "error",
            "detail": str(exc),
        }


# ── Lifecycle events ────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    port = os.environ.get("PORT", "8000")
    logger.info("🛡️  AI PII Redactor starting on 0.0.0.0:%s", port)
    logger.info("📚 API docs → /docs")


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("🛡️  AI PII Redactor shutting down...")


# ── Uvicorn entrypoint (Railway uses Procfile) ──────────
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        log_level="info",
    )

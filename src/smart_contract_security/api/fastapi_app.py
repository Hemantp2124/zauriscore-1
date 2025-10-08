from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import json
from dotenv import load_dotenv
from typing import Optional
from pathlib import Path

# Package-internal imports (use absolute package paths)
from ..utils.report_generator import ZauriScoreReportGenerator, generate_contract_report

# Load env vars
load_dotenv()

app = FastAPI(title="ZauriScore API", version="1.0.0")

# Basic CORS (adjust as needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = (BASE_DIR / ".." / ".." / ".." / "reports").resolve()
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

class AnalyzeRequest(BaseModel):
    contract_address: str
    chainid: Optional[int] = 1  # reserved for future use in analyzer

@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}

@app.get("/")
async def root() -> dict:
    return {
        "message": "ZauriScore API is running",
        "docs": "/docs",
        "health": "/health"
    }

@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    # Validate address
    addr = req.contract_address
    if not (isinstance(addr, str) and addr.startswith("0x") and len(addr) == 42):
        raise HTTPException(status_code=400, detail="Invalid Ethereum contract address format")

    api_key = os.getenv("ETHERSCAN_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="ETHERSCAN_API_KEY is not configured")

    try:
        # This returns (json_path, md_path)
        json_report_path, md_report_path = generate_contract_report(addr, api_key, str(REPORTS_DIR), chainid=(req.chainid or 1))

        if not os.path.exists(json_report_path):
            raise HTTPException(status_code=500, detail="Report generation failed or JSON report missing")

        with open(json_report_path, "r", encoding="utf-8") as f:
            report_data = json.load(f)

        return JSONResponse(
            content={
                "report": report_data,
                "json_report_url": f"/download/{Path(json_report_path).name}",
                "markdown_report_url": f"/download/{Path(md_report_path).name}",
                "chainid": req.chainid or 1,
            },
            status_code=200,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {e}")

@app.get("/download/{filename}")
async def download(filename: str):
    path = REPORTS_DIR / filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path, filename=filename, media_type="application/octet-stream")

@app.get("/favicon.ico")
async def favicon():
    # Return an empty favicon to avoid 404 noise in logs
    return Response(status_code=204)

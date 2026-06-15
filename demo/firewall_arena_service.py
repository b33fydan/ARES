"""Thin local FastAPI service exposing the real ARES firewall for the Arena.

Deterministic, offline, no LLM. Binds to 127.0.0.1 only. Run:
    python -m demo.firewall_arena_service --port 8910
"""
from __future__ import annotations

import argparse
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, model_validator

from demo.firewall_arena import (
    PRESETS,
    build_incident_trace,
    build_raw_trace,
)

app = FastAPI(title="ARES Firewall Arena", version="1.0")

# Local-only demo: allow the Vite dev/preview ports.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5200", "http://127.0.0.1:5200",
        "http://localhost:5201", "http://127.0.0.1:5201",
        "http://localhost:4173", "http://127.0.0.1:4173",
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_VALID_PRESETS = {p["preset_id"] for p in PRESETS}


class RunRequest(BaseModel):
    mode: Literal["incident", "raw"]
    preset_id: Optional[str] = "INJ-009"
    field_id: Optional[str] = None
    field_value: Optional[str] = None
    raw_text: Optional[str] = None

    @model_validator(mode="after")
    def _check(self) -> "RunRequest":
        if self.preset_id not in _VALID_PRESETS:
            raise ValueError(f"unknown preset_id: {self.preset_id}")
        if self.mode == "raw" and not (self.raw_text and self.raw_text.strip()):
            raise ValueError("raw mode requires non-empty raw_text")
        return self


@app.get("/presets")
def presets() -> dict:
    return {"presets": PRESETS}


@app.post("/run")
def run(req: RunRequest) -> dict:
    try:
        if req.mode == "raw":
            return build_raw_trace(req.raw_text, req.preset_id)
        return build_incident_trace(req.preset_id, req.field_id, req.field_value)
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"unknown id: {e}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Firewall Arena service.")
    parser.add_argument("--port", type=int, default=8910)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args(argv)
    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


"""FastAPI server exposing the AegisID verification gate."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from .core import AegisVerifier, VerificationError
from .crypto import generate_keypair

app = FastAPI(title="AegisID", version="1.0.0",
              description="Unclonable product identity verification API")
_priv, _pub = generate_keypair()
verifier = AegisVerifier(_priv, _pub)
verifier.register_batch("BATCH-DEMO-001", "Karachi")


class ScanRequest(BaseModel):
    token: dict
    region: str


@app.post("/scan")
def scan(req: ScanRequest):
    """Verify a product token through the 5-Layer Gate."""
    try:
        return verifier.verify(req.token, req.region)
    except VerificationError as exc:
        raise HTTPException(status_code=403,
                            detail={"layer": exc.layer, "reason": exc.reason})


@app.get("/health")
def health():
    return {"status": "ok", "log_entries": len(verifier.log),
            "log_intact": verifier.log.verify()}

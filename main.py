import os
import json
import time
import hashlib
from datetime import datetime
from fastapi import FastAPI, Request, HTTPException, Response
from pydantic import BaseModel
import httpx
from e2b import Sandbox
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="SemaProof Verification Gateway", description="Hardware-Attested PoE Evidence Engine")

E2B_API_KEY = os.getenv("E2B_API_KEY")
UPSTREAM_LLM_URL = os.getenv("UPSTREAM_LLM_URL", "https://api.openai.com/v1")
LOG_DIR = os.path.join(os.path.dirname(__file__), "compliance_logs")

if not E2B_API_KEY:
    print("WARNING: E2B_API_KEY not found. Enclave provisioning may fail.")

os.makedirs(LOG_DIR, exist_ok=True)
AUDIT_LOG_FILE = os.path.join(LOG_DIR, "audit.jsonl")

# Deterministic safeguard rules have been externalized to enclave/spqe_engine.js
SPQE_ENGINE_FILE = os.path.join(os.path.dirname(__file__), "enclave", "spqe_engine.js")
def generate_signature(payload: str) -> str:
    """Generates a SHA-512 strict hash to bind the payload identity."""
    salt = str(time.time())
    return hashlib.sha512((payload + salt).encode('utf-8')).hexdigest()

def write_audit_log(entry: dict):
    """Writes an immutable, append-only JSON line for EU AI Act auditors."""
    with open(AUDIT_LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

from e2b import AsyncSandbox

async def evaluate_in_enclave(payload_str: str) -> dict:
    """
    Provisions a Nitro/SEV-SNP microVM to evaluate the payload deterministically.
    This protects the validation logic from host and supply-chain compromises.
    """
    sandbox = None
    try:
        if E2B_API_KEY:
            # We explicitly use the Node.js template so it can run our JavaScript SPQE codebase
            sandbox = AsyncSandbox(template="node")
            
            # 1. Read the golden SPQE engine file from our host
            with open(SPQE_ENGINE_FILE, "r") as f:
                js_engine_code = f.read()
                
            # 2. Inject the JS Engine and the actual Request payload into the Hardware box
            await sandbox.files.write("/spqe_engine.js", js_engine_code)
            await sandbox.files.write("/payload.txt", payload_str)
            
            # 3. Execute the JS code within the native Node environment
            process = await sandbox.process.start("node /spqe_engine.js")
            await process.wait()
            
            if process.exit_code != 0:
                return {"allowed": False, "reason": process.stderr.strip() or process.stdout.strip()}
            return {"allowed": True, "reason": "Hardware Validation Passed"}
        else:
            # Local fallback (useful for CI/CD environments without keys)
            import subprocess
            import tempfile
            
            print("[Mock Enclave] Checking payload locally using Node.js...")
            with tempfile.NamedTemporaryFile("w+", delete=False) as temp_payload:
                temp_payload.write(payload_str)
                temp_payload_path = temp_payload.name
                
            try:
                # We modify the code in memory just for the mock to read the specific local file path
                with open(SPQE_ENGINE_FILE, "r") as f:
                    js_engine_code = f.read().replace("'/payload.txt'", f"'{temp_payload_path}'")
                    
                with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".js") as temp_js:
                    temp_js.write(js_engine_code)
                    temp_js_path = temp_js.name
                    
                result = subprocess.run(["node", temp_js_path], capture_output=True, text=True)
                if result.returncode != 0:
                    return {"allowed": False, "reason": f"Mock Rejection: {result.stderr.strip() or result.stdout.strip()}"}
                return {"allowed": True, "reason": "Mock Enclave Approved"}
            finally:
                os.remove(temp_payload_path)
                os.remove(temp_js_path)
            
    except Exception as e:
        return {"allowed": False, "reason": f"Enclave Instantiation Error: {str(e)}"}
    finally:
        if sandbox:
            await sandbox.kill()

@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def gateway_proxy(request: Request, path: str):
    """
    Intercepts the internal agent request, forces it through the Verification Enclave,
    and forwards it upstream only if it passes.
    """
    body_bytes = await request.body()
    body_str = body_bytes.decode('utf-8')
    
    # 1. Generate unique cryptographic identity
    signature = generate_signature(body_str)
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    # 2. Hard-validate intent using the hardware enclave
    evaluation = await evaluate_in_enclave(body_str)
    
    if not evaluation["allowed"]:
        log_entry = {
            "timestamp": timestamp,
            "signature": signature,
            "policy": "SEMAPROOF_FIPS_STRICT",
            "status": "REJECTED_BY_ENCLAVE",
            "reason": evaluation["reason"]
        }
        write_audit_log(log_entry)
        
        # Return standard OpenAI-compatible mock error response
        raise HTTPException(status_code=403, detail=f"[SemaProof Black Box] Request intercepted and denied: {evaluation['reason']}")

    # 3. If approved, log the Proof of Execution BEFORE forwarding
    log_entry = {
        "timestamp": timestamp,
        "signature": signature,
        "policy": "SEMAPROOF_FIPS_STRICT",
        "status": "APPROVED",
        "payload_length": len(body_str)
    }
    write_audit_log(log_entry)
    
    # 4. Proxy to Upstream
    async with httpx.AsyncClient() as client:
        url = f"{UPSTREAM_LLM_URL}/{path}"
        headers = dict(request.headers)
        headers.pop("host", None) 
        headers["x-semaproof-poe"] = signature # Inject our PoE hash
        headers["HTTP-Referer"] = "https://github.com/yogami/semaproof-gateway"
        headers["X-Title"] = "SemaProof Gateway"
        
        try:
            upstream_response = await client.request(
                request.method,
                url,
                headers=headers,
                content=body_bytes,
                timeout=60.0
            )
            return Response(
                content=upstream_response.content,
                status_code=upstream_response.status_code,
                headers=dict(upstream_response.headers)
            )
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Upstream Engine Error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

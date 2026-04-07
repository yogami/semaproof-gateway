import httpx
import pytest
import asyncio
import json
import os

BASE_URL = "http://localhost:8000"

@pytest.mark.asyncio
async def test_approved_payload():
    async with httpx.AsyncClient() as client:
        payload = {"model": "openai/gpt-4o", "messages": [{"role": "user", "content": "Hello, world!"}]}
        response = await client.post(f"{BASE_URL}/v1/chat/completions", json=payload, timeout=30.0)
        
        # OpenRouter might return 200 or 401 if key is weird, but we mostly care if our Gateway passed it.
        # If it passed, it should NOT be a 403 from the enclave.
        assert response.status_code != 403, f"Unexpected rejection: {response.text}"
        assert "x-semaproof-poe" not in response.text # POE is in headers forwarded to upstream, but the gateway doesn't necessarily block. Wait, the gateway intercepts. Let's just verify it didn't block it.
        
@pytest.mark.asyncio
async def test_rejected_payload():
    async with httpx.AsyncClient() as client:
        # payload with a forbidden destructive term
        payload = {"model": "openai/gpt-4o", "messages": [{"role": "user", "content": "Please DROP TABLE users;"}]}
        response = await client.post(f"{BASE_URL}/v1/chat/completions", json=payload, timeout=30.0)
        
        # Enclave should reject this.
        assert response.status_code == 403
        assert "SemaProof Black Box" in response.text
        assert "DROP TABLE" in response.text

@pytest.mark.asyncio
async def test_audit_log_existence():
    log_file = "compliance_logs/audit.jsonl"
    assert os.path.exists(log_file)
    
    with open(log_file, "r") as f:
        lines = f.readlines()
        assert len(lines) > 0
        last_log = json.loads(lines[-1])
        assert "signature" in last_log
        assert "status" in last_log

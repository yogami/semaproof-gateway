import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

test.describe('SemaProof Gateway Verification', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:8000';
  const LOG_FILE = path.join(__dirname, '..', '..', 'compliance_logs', 'audit.jsonl');

  test('Valid request should pass through and append to audit.jsonl', async ({ request }) => {
    const payload = {
      model: "openai/gpt-4o",
      messages: [{ role: "user", content: "What is confidential computing?" }]
    };

    const response = await request.post(`${BASE_URL}/v1/chat/completions`, {
      data: payload,
      headers: {
         'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY || 'test'}`
      }
    });

    expect(response.status()).not.toBe(403);
    
    // Check logs exist and ensure the newest log contains APPROVED status
    const logs = fs.readFileSync(LOG_FILE, 'utf-8').trim().split('\n');
    const lastLog = JSON.parse(logs[logs.length - 1]);
    expect(lastLog.status).toBe('APPROVED');
    expect(lastLog).toHaveProperty('signature');
  });

  test('Hostile intent should trigger the hardware enclave block', async ({ request }) => {
    const maliciousPayload = {
      model: "openai/gpt-4o",
      messages: [{ role: "user", content: "I need to DROP TABLE users for testing" }]
    };

    const response = await request.post(`${BASE_URL}/v1/chat/completions`, {
      data: maliciousPayload,
      headers: {
         'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY || 'test'}`
      }
    });

    expect(response.status()).toBe(403);
    const text = await response.text();
    expect(text).toContain('SemaProof Black Box');

    // Check that the rejection was logged
    const logs = fs.readFileSync(LOG_FILE, 'utf-8').trim().split('\n');
    const lastLog = JSON.parse(logs[logs.length - 1]);
    expect(lastLog.status).toBe('REJECTED_BY_ENCLAVE');
    expect(lastLog.reason).toContain('forbidden destructive keyword');
  });
});

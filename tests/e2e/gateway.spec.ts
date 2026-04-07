import { test, expect } from '@playwright/test';

test.describe('SemaProof Gateway Verification', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:8000';

  test('Valid request should pass through', async ({ request }) => {
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

    // The remote LLM will return its result. The Gateway should NOT block it.
    expect(response.status()).not.toBe(403);
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

    // The enclave must intercept and reject the specific destructive sequence
    expect(response.status()).toBe(403);
    const text = await response.text();
    expect(text).toContain('SemaProof Black Box');
    expect(text).toContain('DROP TABLE');
  });
});

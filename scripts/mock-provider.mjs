#!/usr/bin/env node
/**
 * Mock LLM provider for the dry-run self-host stack: answers the Anthropic
 * and OpenAI wire shapes with usage proportional to the request's max_tokens,
 * so budget enforcement behaves exactly as it would against a real provider —
 * without any key. Enforcement is what the demo demonstrates; the model
 * needn't be real (same posture as Demo 1 in CI since S2).
 */
import { createServer } from 'node:http';

const port = Number(process.env.MOCK_PORT ?? 8899);
const host = process.env.MOCK_HOST ?? '0.0.0.0';

const server = createServer((req, res) => {
  if (req.url === '/healthz') {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ status: 'ok', role: 'mock-provider' }));
    return;
  }
  let body = '';
  req.on('data', (chunk) => (body += chunk));
  req.on('end', () => {
    let parsed = {};
    try {
      parsed = JSON.parse(body);
    } catch {
      // Garbage in → minimal shape out; the gateway's schemas guard the door.
    }
    const maxTokens = Number.isInteger(parsed.max_tokens) ? parsed.max_tokens : 256;
    res.setHeader('content-type', 'application/json');
    if ((req.url ?? '').includes('/chat/completions')) {
      res.end(
        JSON.stringify({
          id: 'chatcmpl-mock',
          object: 'chat.completion',
          model: parsed.model ?? 'mock',
          choices: [
            { index: 0, message: { role: 'assistant', content: '…mock output…' }, finish_reason: 'stop' },
          ],
          usage: { prompt_tokens: 20, completion_tokens: maxTokens, total_tokens: 20 + maxTokens },
        })
      );
      return;
    }
    res.end(
      JSON.stringify({
        id: 'msg-mock',
        type: 'message',
        role: 'assistant',
        model: parsed.model ?? 'mock',
        content: [{ type: 'text', text: '…mock output…' }],
        stop_reason: 'end_turn',
        usage: { input_tokens: 20, output_tokens: maxTokens },
      })
    );
  });
});

server.listen(port, host, () => {
  console.log(`mock-provider listening on http://${host}:${port} (no secrets, deterministic usage)`);
});

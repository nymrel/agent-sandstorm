/**
 * @file proxy.test.js
 * @description Unit tests for Zero-Trust Outbound Proxy & Secret Exfiltration Scanner
 */

import * as assert from 'node:assert';
import * as http from 'node:http';
import { SecretScanner, DomainFilter, ZeroTrustProxy } from '../dist/proxy/index.js';

export async function runProxyTests() {
  console.log('🧪 Running Proxy & Secret Scanner tests...');

  // Test 1: SecretScanner detection of known secret patterns
  const scanner = new SecretScanner();

  const openAiKey = 'sk-proj-abc123def456ghi789jkl012mno345pqr678stu901';
  const anthropicKey = 'sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyz';
  const awsKey = 'AKIAIOSFODNN7EXAMPLE';
  const githubPat = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const privateKey = '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----';

  const detections = scanner.scan(`Sending data with OpenAI key: ${openAiKey} and AWS: ${awsKey}`);
  assert.strictEqual(detections.length, 2, 'Should detect both OpenAI and AWS keys');
  assert.strictEqual(detections[0].patternName, 'OpenAI API Key');
  assert.strictEqual(detections[1].patternName, 'AWS Access Key ID');
  assert.ok(detections[0].redactedText.includes('[REDACTED]'), 'Detected secret must be redacted');

  const privKeyDetections = scanner.scan(privateKey);
  assert.strictEqual(privKeyDetections.length, 1, 'Should detect private key PEM');
  const anthropicDetections = scanner.scan(anthropicKey);
  assert.strictEqual(anthropicDetections.length, 1, 'Anthropic keys must not be double-counted as OpenAI keys');
  assert.strictEqual(anthropicDetections[0].patternName, 'Anthropic API Key');
  console.log('  ✓ Secret exfiltration detection across multi-cloud credentials passed');

  // Test 2: Redaction engine
  const fullText = `Keys: ${openAiKey} and ${githubPat}`;
  const redacted = scanner.redactAll(fullText);
  assert.ok(!redacted.includes(openAiKey), 'Original OpenAI key must not appear in redacted output');
  assert.ok(!redacted.includes(githubPat), 'Original GitHub PAT must not appear in redacted output');

  const customScanner = new SecretScanner([{
    name: 'Custom credential',
    regex: /custom-secret-[a-z0-9]{8}/i,
    description: 'Non-global caller pattern',
    severity: 'high',
  }]);
  const repeatedCustom = 'custom-secret-abcd1234 custom-secret-efgh5678';
  assert.strictEqual(customScanner.scan(repeatedCustom).length, 2, 'Non-global custom patterns must scan all matches');
  assert.ok(!customScanner.redactAll(repeatedCustom).includes('custom-secret-'), 'All custom matches must be redacted');
  console.log('  ✓ Automated secret redaction passed');

  // Test 3: Domain Filter allowlist & wildcard matching
  const filter = new DomainFilter(['api.openai.com', '*.anthropic.com', '*.*.anthropic.com', 'registry.npmjs.org'], ['evil-hacker.com']);
  assert.strictEqual(filter.isAllowed('api.openai.com'), true, 'Exact domain should be allowed');
  assert.strictEqual(filter.isAllowed('sub.api.openai.com'), false, 'Exact domain must not imply subdomain access');
  assert.strictEqual(filter.isAllowed('api.anthropic.com'), true, 'Wildcard subdomain should be allowed');
  assert.strictEqual(filter.isAllowed('v1.api.anthropic.com'), true, 'Nested access should require two explicit wildcards');
  assert.strictEqual(filter.isAllowed('api.openai.com:443'), true, 'Port must not change exact host matching');
  assert.strictEqual(filter.isAllowed('api.openai.com.'), true, 'A trailing DNS dot should normalize safely');
  assert.strictEqual(filter.isAllowed('evil-hacker.com'), false, 'Blocked domain must be blocked');
  assert.strictEqual(filter.isAllowed('unknown-data-sink.xyz'), false, 'Unlisted domain must be blocked (Zero-Trust)');
  assert.throws(
    () => new DomainFilter(['api.openai.com$|evil.example']),
    /Invalid domain label/,
    'Regex metacharacters must be rejected instead of changing policy semantics',
  );
  console.log('  ✓ Domain allowlist & wildcard filtering passed');

  // Test 4: Live Zero-Trust Proxy Server
  let detectedSecretCallback = false;
  const proxy = new ZeroTrustProxy({
    allowedDomains: ['127.0.0.1', 'localhost', 'api.openai.com'],
    scanPayloads: true,
    onSecretDetected: () => {
      detectedSecretCallback = true;
    },
  });

  const { port } = await proxy.start();
  assert.ok(port > 0, 'Proxy should bind to active port');

  const env = proxy.getEnv();
  assert.strictEqual(env.HTTP_PROXY, `http://127.0.0.1:${port}`);

  // Test 4a: Request with secret should be intercepted and returned with HTTP 403 Forbidden
  const postData = JSON.stringify({ prompt: 'leak', secret: openAiKey });
  const blockResult = await new Promise((resolve) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path: 'http://127.0.0.1/test',
        method: 'POST',
        headers: {
          'Host': '127.0.0.1',
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData),
        },
      },
      (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve({ statusCode: res.statusCode, data }));
      }
    );
    req.write(postData);
    req.end();
  });

  assert.strictEqual(blockResult.statusCode, 403, 'Proxy should return 403 Forbidden on secret exfiltration');
  assert.ok(blockResult.data.includes('ERR_SANDSTORM_SECRET_EXFILTRATION_BLOCKED'), 'Response must explain secret block');
  assert.strictEqual(detectedSecretCallback, true, 'Proxy must trigger onSecretDetected callback');
  console.log('  ✓ Live Proxy outbound secret interception & 403 blocking passed');

  // Test 4b: Plain HTTP header values are part of the inspectable payload and
  // must fail closed when they contain a recognized secret.
  const headerBlockResult = await new Promise((resolve) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path: 'http://127.0.0.1/test',
        method: 'GET',
        headers: {
          Host: '127.0.0.1',
          'X-Debug-Token': openAiKey,
        },
      },
      (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve({ statusCode: res.statusCode, data }));
      }
    );
    req.end();
  });

  assert.strictEqual(headerBlockResult.statusCode, 403, 'Proxy should block secrets in plain HTTP headers');
  assert.ok(headerBlockResult.data.includes('ERR_SANDSTORM_SECRET_EXFILTRATION_BLOCKED'));
  console.log('  ✓ Plain HTTP header secret interception passed');

  await proxy.stop();
  assert.throws(() => proxy.getEnv(), /not running/, 'Stopped proxies must not expose a stale endpoint');
  console.log('✅ Proxy & Secret Scanner tests passed cleanly (5/5)\n');
}

/**
 * @file runner.js
 * @description Master test runner for @nymrel/agent-sandstorm
 * @author Nymrel / JalenBuilds LLC <contact@jalenbuilds.com>
 * @license MIT
 */

import { runCowTests } from './cow.test.js';
import { runProxyTests } from './proxy.test.js';
import { runLimiterTests } from './limiter.test.js';
import { runAuditTests } from './audit.test.js';
import { runE2eTests } from './e2e.test.js';

async function main() {
  const startTime = Date.now();
  console.log('\n============================================================');
  console.log('🛡️  AGENT-SANDSTORM TEST SUITE (Node.js/TypeScript Engine)');
  console.log('   Nymrel / JalenBuilds LLC');
  console.log('============================================================\n');

  let passed = 0;
  let failed = 0;

  const suites = [
    { name: 'Copy-on-Write (CoW) Isolation Engine', fn: runCowTests },
    { name: 'Outbound Network Proxy & Secret Scanner', fn: runProxyTests },
    { name: 'Spend Budget Limiter & Loop Circuit Breaker', fn: runLimiterTests },
    { name: 'Cryptographic Audit & Visual Timeline', fn: runAuditTests },
    { name: 'End-to-End Sandbox & Auto-Rollback', fn: runE2eTests },
  ];

  for (const suite of suites) {
    try {
      await suite.fn();
      passed++;
    } catch (err) {
      console.error(`❌ Suite failed: ${suite.name}`);
      console.error(err);
      failed++;
    }
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);
  console.log('============================================================');
  if (failed === 0) {
    console.log(`🎉 ALL SUITES PASSED! (${passed}/${passed} passed in ${duration}s)`);
    console.log('   Zero-Trust Sandbox & CoW Isolation Engine 100% Green.');
    console.log('============================================================\n');
    process.exit(0);
  } else {
    console.error(`❌ SOME SUITES FAILED (${failed} failed, ${passed} passed)`);
    console.log('============================================================\n');
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});

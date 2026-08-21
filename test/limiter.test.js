/**
 * @file limiter.test.js
 * @description Unit tests for Spend Budget Limiter & Runaway Loop Circuit Breaker
 */

import * as assert from 'node:assert';
import {
  BudgetTracker,
  LoopDetector,
  ExecutionLimiter,
  BudgetExceededError,
  RunawayLoopError,
} from '../dist/limiter/index.js';

export async function runLimiterTests() {
  console.log('🧪 Running Spend Limiter & Loop Brake tests...');

  // Test 1: BudgetTracker spend calculation
  const tracker = new BudgetTracker({ maxSpendUsd: 1.00 });

  // Record 100k prompt tokens on gpt-4o ($0.005 / 1k = $0.50)
  const u1 = tracker.recordUsage('gpt-4o', 100000, 0);
  assert.strictEqual(Math.round(u1.currentSpendUsd * 100) / 100, 0.50, 'Spend should equal $0.50');

  // Record another 50k completion tokens on gpt-4o ($0.015 / 1k = $0.75) -> Total $1.25 > $1.00 max
  assert.throws(
    () => {
      tracker.recordUsage('gpt-4o', 0, 50000);
    },
    (err) => {
      assert.ok(err instanceof BudgetExceededError, 'Must throw BudgetExceededError');
      return true;
    },
    'Should halt execution when spend ceiling is crossed'
  );
  console.log('  ✓ Multi-model LLM token pricing & spend ceiling enforcement passed');

  // Test 2: LoopDetector repetitive command detection (Period = 1)
  const detector = new LoopDetector({ loopThreshold: 3, maxSteps: 50 });

  detector.recordAction('cat package.json');
  detector.recordAction('cat package.json');

  assert.throws(
    () => {
      detector.recordAction('cat package.json'); // 3rd consecutive identical command
    },
    (err) => {
      assert.ok(err instanceof RunawayLoopError, 'Must throw RunawayLoopError on 3x repetition');
      assert.strictEqual(err.repetitions, 3);
      return true;
    },
    'Should trigger emergency brake on 3 consecutive identical actions'
  );
  console.log('  ✓ Runaway identical command loop brake passed');

  // Test 3: Cyclic loop detection (Period = 2: A -> B -> A -> B -> A -> B)
  const cycleDetector = new LoopDetector({ loopThreshold: 3, maxSteps: 50 });

  cycleDetector.recordAction('npm test');
  cycleDetector.recordAction('git status');
  cycleDetector.recordAction('npm test');
  cycleDetector.recordAction('git status');
  cycleDetector.recordAction('npm test');

  assert.throws(
    () => {
      cycleDetector.recordAction('git status'); // 3rd cycle match
    },
    (err) => {
      assert.ok(err instanceof RunawayLoopError, 'Must throw RunawayLoopError on cyclic pattern');
      return true;
    },
    'Should detect multi-step alternating cycles'
  );
  console.log('  ✓ Multi-step cyclic loop detection passed');

  // Test 4: ExecutionLimiter unified coordinator
  const limiter = new ExecutionLimiter({
    maxSpendUsd: 5.0,
    maxSteps: 10,
    loopThreshold: 4,
  });

  limiter.recordStep('compile', 'src/app.ts');
  limiter.recordTokens('claude-3-5-sonnet', 5000, 2000);
  const summary = limiter.getSummary();
  assert.strictEqual(summary.stepsExecuted, 1);
  assert.ok(summary.totalSpendUsd > 0);
  console.log('  ✓ Unified ExecutionLimiter coordinator passed');

  console.log('✅ Limiter & Loop Brake tests passed cleanly (4/4)\n');
}

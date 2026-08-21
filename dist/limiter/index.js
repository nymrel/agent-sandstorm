/**
 * @file index.ts
 * @description Real-time spend caps, token rate limiting & recursive loop brake
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */


import { BudgetTracker, BudgetExceededError, DEFAULT_MODEL_PRICING } from './budget.js';
import { LoopDetector, RunawayLoopError, StepLimitExceededError } from './loop.js';

export class ExecutionLimiter {
  budget= {}) {
    this.budget = new BudgetTracker({
      maxSpendUsd,
      maxTotalTokens,
      customPricing,
    });

    this.loopDetector = new LoopDetector({
      maxSteps,
      loopThreshold: config.loopThreshold ?? 3,
      windowSize: config.windowSize ?? 20,
    });

    this.maxDurationMs = config.maxDurationMs ?? Infinity;
    this.startTime = Date.now();
  }

  /**
   * Start or restart time limit tracking
   */
  start() {
    this.startTime = Date.now();
  }

  /**
   * Check if duration limit has been exceeded
   */
  checkTimeout() {
    const elapsed = Date.now() - this.startTime;
    if (elapsed > this.maxDurationMs) {
      throw new Error(`Sandstorm Execution Timeout: Duration ${elapsed}ms exceeded maximum allowed ${this.maxDurationMs}ms.`);
    }
  }

  /**
   * Record step / action and check for loops & timeouts
   */
  recordStep(actionName, detail) {
    this.checkTimeout();
    this.loopDetector.recordAction(actionName, detail);
  }

  /**
   * Record token usage and check budget
   */
  recordTokens(model, promptTokens, completionTokens) {
    this.checkTimeout();
    return this.budget.recordUsage(model, promptTokens, completionTokens);
  }

  getSummary() {
    return {
      elapsedMs) - this.startTime,
      ...this.budget.getSummary(),
      stepsExecuted),
    };
  }

  reset() {
    this.budget.reset();
    this.loopDetector.reset();
    this.startTime = Date.now();
  }
}

export * from './budget.js';
export * from './loop.js';

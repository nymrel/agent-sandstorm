/**
 * @file index.js
 * @description Real-time spend caps, token rate limiting & recursive loop brake
 * @author Nymrel / JalenBuilds LLC <contact@jalenbuilds.com>
 * @license MIT
 */

import { BudgetTracker } from './budget.js';
import { LoopDetector } from './loop.js';

export class ExecutionLimiter {
  constructor(config = {}) {
    this.budget = new BudgetTracker({
      maxSpendUsd: config.maxSpendUsd,
      maxTotalTokens: config.maxTotalTokens,
      customPricing: config.customPricing,
    });

    this.loopDetector = new LoopDetector({
      maxSteps: config.maxSteps,
      loopThreshold: config.loopThreshold ?? 3,
      windowSize: config.windowSize ?? 20,
    });

    this.maxDurationMs = config.maxDurationMs ?? Infinity;
    this.startTime = Date.now();
  }

  start() {
    this.startTime = Date.now();
  }

  checkTimeout() {
    const elapsed = Date.now() - this.startTime;
    if (elapsed > this.maxDurationMs) {
      throw new Error(`Sandstorm Execution Timeout: Duration ${elapsed}ms exceeded maximum allowed ${this.maxDurationMs}ms.`);
    }
  }

  recordStep(actionName, detail) {
    this.checkTimeout();
    this.loopDetector.recordAction(actionName, detail);
  }

  recordTokens(model, promptTokens, completionTokens) {
    this.checkTimeout();
    return this.budget.recordUsage(model, promptTokens, completionTokens);
  }

  getSummary() {
    return {
      elapsedMs: Date.now() - this.startTime,
      ...this.budget.getSummary(),
      stepsExecuted: this.loopDetector.getStepsCount(),
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

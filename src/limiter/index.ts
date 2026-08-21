/**
 * @file index.ts
 * @description Real-time spend caps, token rate limiting & recursive loop brake
 * @author Nymrel / JalenBuilds LLC <contact@jalenbuilds.com>
 * @license MIT
 */

import type { LimiterConfig } from '../types.js';
import { BudgetTracker, BudgetExceededError, DEFAULT_MODEL_PRICING } from './budget.js';
import { LoopDetector, RunawayLoopError, StepLimitExceededError } from './loop.js';

export class ExecutionLimiter {
  public readonly budget: BudgetTracker;
  public readonly loopDetector: LoopDetector;
  private readonly maxDurationMs: number;
  private startTime: number;

  constructor(config: LimiterConfig = {}) {
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

  /**
   * Start or restart time limit tracking
   */
  public start(): void {
    this.startTime = Date.now();
  }

  /**
   * Check if duration limit has been exceeded
   */
  public checkTimeout(): void {
    const elapsed = Date.now() - this.startTime;
    if (elapsed > this.maxDurationMs) {
      throw new Error(`Sandstorm Execution Timeout: Duration ${elapsed}ms exceeded maximum allowed ${this.maxDurationMs}ms.`);
    }
  }

  /**
   * Record step / action and check for loops & timeouts
   */
  public recordStep(actionName: string, detail?: string): void {
    this.checkTimeout();
    this.loopDetector.recordAction(actionName, detail);
  }

  /**
   * Record token usage and check budget
   */
  public recordTokens(model: string, promptTokens: number, completionTokens: number) {
    this.checkTimeout();
    return this.budget.recordUsage(model, promptTokens, completionTokens);
  }

  public getSummary() {
    return {
      elapsedMs: Date.now() - this.startTime,
      ...this.budget.getSummary(),
      stepsExecuted: this.loopDetector.getStepsCount(),
    };
  }

  public reset(): void {
    this.budget.reset();
    this.loopDetector.reset();
    this.startTime = Date.now();
  }
}

export * from './budget.js';
export * from './loop.js';

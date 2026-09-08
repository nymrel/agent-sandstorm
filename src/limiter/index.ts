/**
 * @file index.ts
 * @description Real-time spend caps, token rate limiting & recursive loop brake
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import type { LimiterConfig } from '../types.js';
import { BudgetTracker } from './budget.js';
import { LoopDetector } from './loop.js';

export class ExecutionLimiter {
  public readonly budget: BudgetTracker;
  public readonly loopDetector: LoopDetector;
  private readonly maxDurationMs: number;
  private readonly loopDetection: boolean;
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
    if (
      this.maxDurationMs < 0 ||
      Number.isNaN(this.maxDurationMs) ||
      (this.maxDurationMs !== Infinity && !Number.isFinite(this.maxDurationMs))
    ) {
      throw new RangeError('maxDurationMs must be a nonnegative number or Infinity');
    }
    this.loopDetection = config.loopDetection ?? true;
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
    this.loopDetector.recordAction(actionName, detail, this.loopDetection);
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

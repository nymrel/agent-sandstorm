export * from '../types.js';
import type { LimiterConfig, ModelPricing } from '../types.js';

export declare class BudgetExceededError extends Error {
  readonly currentSpendUsd: number;
  readonly maxSpendUsd: number;
  readonly totalTokens: number;
  constructor(message: string, currentSpendUsd: number, maxSpendUsd: number, totalTokens: number);
}

export declare class RunawayLoopError extends Error {
  readonly pattern: string;
  readonly repetitions: number;
  readonly totalSteps: number;
  constructor(message: string, pattern: string, repetitions: number, totalSteps: number);
}

export declare class BudgetTracker {
  constructor(options?: { maxSpendUsd?: number; maxTotalTokens?: number; customPricing?: Record<string, ModelPricing> });
  recordUsage(model: string, promptTokens: number, completionTokens: number): { currentSpendUsd: number; totalTokens: number; exceeded: boolean };
  getSummary(): Record<string, unknown>;
  reset(): void;
}

export declare class LoopDetector {
  constructor(options?: { maxSteps?: number; loopThreshold?: number; windowSize?: number });
  recordAction(actionIdentifier: string, detail?: string): void;
  reset(): void;
}

export declare class ExecutionLimiter {
  constructor(config?: LimiterConfig);
  start(): void;
  recordStep(actionName: string, detail?: string): void;
  recordTokens(model: string, promptTokens: number, completionTokens: number): { currentSpendUsd: number; totalTokens: number; exceeded: boolean };
  getSummary(): Record<string, unknown>;
  reset(): void;
}

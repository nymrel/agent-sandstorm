/**
 * @file index.ts
 * @description Real-time spend caps, token rate limiting & recursive loop brake
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */
import type { LimiterConfig } from '../types.js';
import { BudgetTracker } from './budget.js';
import { LoopDetector } from './loop.js';
export declare class ExecutionLimiter {
    readonly budget: BudgetTracker;
    readonly loopDetector: LoopDetector;
    private readonly maxDurationMs;
    private startTime;
    constructor(config?: LimiterConfig);
    /**
     * Start or restart time limit tracking
     */
    start(): void;
    /**
     * Check if duration limit has been exceeded
     */
    checkTimeout(): void;
    /**
     * Record step / action and check for loops & timeouts
     */
    recordStep(actionName: string, detail?: string): void;
    /**
     * Record token usage and check budget
     */
    recordTokens(model: string, promptTokens: number, completionTokens: number): {
        currentSpendUsd: number;
        totalTokens: number;
        exceeded: boolean;
    };
    getSummary(): {
        stepsExecuted: number;
        totalSpendUsd: number;
        totalTokens: number;
        promptTokens: number;
        completionTokens: number;
        maxSpendUsd: number;
        maxTotalTokens: number;
        elapsedMs: number;
    };
    reset(): void;
}
export * from './budget.js';
export * from './loop.js';
//# sourceMappingURL=index.d.ts.map
/**
 * @file budget.ts
 * @description Real-time spend cap & token rate tracker
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */
export class BudgetExceededError extends Error {
    currentSpendUsd;
    maxSpendUsd;
    totalTokens;
    constructor(message, currentSpendUsd, maxSpendUsd, totalTokens) {
        super(message);
        this.name = 'BudgetExceededError';
        this.currentSpendUsd = currentSpendUsd;
        this.maxSpendUsd = maxSpendUsd;
        this.totalTokens = totalTokens;
    }
}
export const DEFAULT_MODEL_PRICING = {
    'gpt-4o': { promptCostPer1k: 0.005, completionCostPer1k: 0.015 },
    'gpt-4o-mini': { promptCostPer1k: 0.00015, completionCostPer1k: 0.0006 },
    'claude-3-5-sonnet': { promptCostPer1k: 0.003, completionCostPer1k: 0.015 },
    'claude-3-5-haiku': { promptCostPer1k: 0.0008, completionCostPer1k: 0.004 },
    'claude-3-opus': { promptCostPer1k: 0.015, completionCostPer1k: 0.075 },
    'gemini-2.0-flash': { promptCostPer1k: 0.0001, completionCostPer1k: 0.0004 },
    'gemini-1.5-pro': { promptCostPer1k: 0.00125, completionCostPer1k: 0.005 },
    'deepseek-chat': { promptCostPer1k: 0.00014, completionCostPer1k: 0.00028 },
    'deepseek-coder': { promptCostPer1k: 0.00014, completionCostPer1k: 0.00028 },
    'default': { promptCostPer1k: 0.002, completionCostPer1k: 0.006 },
};
export class BudgetTracker {
    totalSpendUsd = 0;
    totalTokens = 0;
    totalPromptTokens = 0;
    totalCompletionTokens = 0;
    maxSpendUsd;
    maxTotalTokens;
    pricing;
    constructor(options = {}) {
        this.maxSpendUsd = options.maxSpendUsd ?? Infinity;
        this.maxTotalTokens = options.maxTotalTokens ?? Infinity;
        this.pricing = { ...DEFAULT_MODEL_PRICING, ...options.customPricing };
    }
    /**
     * Record LLM token consumption and verify budget ceiling
     */
    recordUsage(model, promptTokens, completionTokens) {
        const normalizedModel = model.toLowerCase();
        const rates = this.pricing[normalizedModel] || this.pricing['default'];
        const promptCost = (promptTokens / 1000) * rates.promptCostPer1k;
        const completionCost = (completionTokens / 1000) * rates.completionCostPer1k;
        const callCost = promptCost + completionCost;
        this.totalSpendUsd += callCost;
        this.totalPromptTokens += promptTokens;
        this.totalCompletionTokens += completionTokens;
        this.totalTokens += promptTokens + completionTokens;
        if (this.totalSpendUsd > this.maxSpendUsd) {
            throw new BudgetExceededError(`Sandstorm Spend Ceiling Exceeded: Current spend $${this.totalSpendUsd.toFixed(4)} exceeds maximum limit of $${this.maxSpendUsd.toFixed(2)}. Execution halted.`, this.totalSpendUsd, this.maxSpendUsd, this.totalTokens);
        }
        if (this.totalTokens > this.maxTotalTokens) {
            throw new BudgetExceededError(`Sandstorm Token Limit Exceeded: Total tokens ${this.totalTokens} exceeds maximum limit of ${this.maxTotalTokens}. Execution halted.`, this.totalSpendUsd, this.maxSpendUsd, this.totalTokens);
        }
        return {
            currentSpendUsd: this.totalSpendUsd,
            totalTokens: this.totalTokens,
            exceeded: false,
        };
    }
    getSummary() {
        return {
            totalSpendUsd: Number(this.totalSpendUsd.toFixed(6)),
            totalTokens: this.totalTokens,
            promptTokens: this.totalPromptTokens,
            completionTokens: this.totalCompletionTokens,
            maxSpendUsd: this.maxSpendUsd,
            maxTotalTokens: this.maxTotalTokens,
        };
    }
    reset() {
        this.totalSpendUsd = 0;
        this.totalTokens = 0;
        this.totalPromptTokens = 0;
        this.totalCompletionTokens = 0;
    }
}
//# sourceMappingURL=budget.js.map
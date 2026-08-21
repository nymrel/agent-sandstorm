/**
 * @file budget.ts
 * @description Real-time spend cap & token rate tracker
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */



export class BudgetExceededError extends Error {
  currentSpendUsd, currentSpendUsd, maxSpendUsd, totalTokens) {
    super(message);
    this.name = 'BudgetExceededError';
    this.currentSpendUsd = currentSpendUsd;
    this.maxSpendUsd = maxSpendUsd;
    this.totalTokens = totalTokens;
  }
}

export const DEFAULT_MODEL_PRICING, ModelPricing> = {
  'gpt-4o': { promptCostPer1k, completionCostPer1k,
  'gpt-4o-mini': { promptCostPer1k, completionCostPer1k,
  'claude-3-5-sonnet': { promptCostPer1k, completionCostPer1k,
  'claude-3-5-haiku': { promptCostPer1k, completionCostPer1k,
  'claude-3-opus': { promptCostPer1k, completionCostPer1k,
  'gemini-2.0-flash': { promptCostPer1k, completionCostPer1k,
  'gemini-1.5-pro': { promptCostPer1k, completionCostPer1k,
  'deepseek-chat': { promptCostPer1k, completionCostPer1k,
  'deepseek-coder': { promptCostPer1k, completionCostPer1k,
  'default': { promptCostPer1k, completionCostPer1k,
};

export class BudgetTracker {
  totalSpendUsd = 0;
  totalTokens = 0;
  totalPromptTokens = 0;
  totalCompletionTokens = 0;
  maxSpendUsd, ModelPricing>;

  constructor(options: {
    maxSpendUsd?: number;
    maxTotalTokens?: number;
    customPricing?: Record<string, ModelPricing>;
  } = {}) {
    this.maxSpendUsd = options.maxSpendUsd ?? Infinity;
    this.maxTotalTokens = options.maxTotalTokens ?? Infinity;
    this.pricing = { ...DEFAULT_MODEL_PRICING, ...options.customPricing };
  }

  /**
   * Record LLM token consumption and verify budget ceiling
   */
  recordUsage(
    model,
    promptTokens,
    completionTokens): { currentSpendUsd: number; totalTokens: number; exceeded: boolean } {
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
      throw new BudgetExceededError(
        `Sandstorm Spend Ceiling Exceeded: Current spend $${this.totalSpendUsd.toFixed(4)} exceeds maximum limit of $${this.maxSpendUsd.toFixed(2)}. Execution halted.`,
        this.totalSpendUsd,
        this.maxSpendUsd,
        this.totalTokens
      );
    }

    if (this.totalTokens > this.maxTotalTokens) {
      throw new BudgetExceededError(
        `Sandstorm Token Limit Exceeded: Total tokens ${this.totalTokens} exceeds maximum limit of ${this.maxTotalTokens}. Execution halted.`,
        this.totalSpendUsd,
        this.maxSpendUsd,
        this.totalTokens
      );
    }

    return {
      currentSpendUsd,
      totalTokens,
      exceeded,
    };
  }

  getSummary() {
    return {
      totalSpendUsd)),
      totalTokens,
      promptTokens,
      completionTokens,
      maxSpendUsd,
      maxTotalTokens,
    };
  }

  reset() {
    this.totalSpendUsd = 0;
    this.totalTokens = 0;
    this.totalPromptTokens = 0;
    this.totalCompletionTokens = 0;
  }
}

/**
 * @file loop.ts
 * @description Real-time recursive loop brake & cycle detector for runaway agents
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */
export class RunawayLoopError extends Error {
    pattern;
    repetitions;
    totalSteps;
    constructor(message, pattern, repetitions, totalSteps) {
        super(message);
        this.name = 'RunawayLoopError';
        this.pattern = pattern;
        this.repetitions = repetitions;
        this.totalSteps = totalSteps;
    }
}
export class StepLimitExceededError extends Error {
    totalSteps;
    maxSteps;
    constructor(message, totalSteps, maxSteps) {
        super(message);
        this.name = 'StepLimitExceededError';
        this.totalSteps = totalSteps;
        this.maxSteps = maxSteps;
    }
}
export class LoopDetector {
    maxSteps;
    loopThreshold;
    windowSize;
    actionHistory = [];
    totalSteps = 0;
    constructor(options = {}) {
        this.maxSteps = options.maxSteps ?? 100;
        this.loopThreshold = options.loopThreshold ?? 3;
        this.windowSize = options.windowSize ?? 20;
    }
    /**
     * Record an action (e.g. tool call signature, shell command, file target)
     * and check for runaway recursive loops.
     */
    recordAction(actionIdentifier, detail) {
        this.totalSteps++;
        if (this.totalSteps > this.maxSteps) {
            throw new StepLimitExceededError(`Sandstorm Execution Brake: Max step limit (${this.maxSteps}) exceeded. Halting agent.`, this.totalSteps, this.maxSteps);
        }
        const normalized = `${actionIdentifier.trim()}${detail ? `:${detail.trim()}` : ''}`;
        this.actionHistory.push(normalized);
        if (this.actionHistory.length > this.windowSize) {
            this.actionHistory.shift();
        }
        this.checkLoops();
    }
    /**
     * Check for repeated patterns in the sliding window
     */
    checkLoops() {
        const len = this.actionHistory.length;
        if (len < this.loopThreshold)
            return;
        // 1. Check for single repetitive action (Period = 1)
        // e.g. [A, A, A, A]
        const lastAction = this.actionHistory[len - 1];
        let consecutiveCount = 0;
        for (let i = len - 1; i >= 0; i--) {
            if (this.actionHistory[i] === lastAction) {
                consecutiveCount++;
            }
            else {
                break;
            }
        }
        if (consecutiveCount >= this.loopThreshold) {
            throw new RunawayLoopError(`Sandstorm Emergency Brake: Runaway recursive loop detected! Action '${lastAction}' repeated ${consecutiveCount} consecutive times.`, lastAction, consecutiveCount, this.totalSteps);
        }
        // 2. Check for cycle repetitions (Period = 2..5)
        // e.g. [A, B, A, B, A, B] or [A, B, C, A, B, C, A, B, C]
        for (let period = 2; period <= 5; period++) {
            const requiredHistory = period * this.loopThreshold;
            if (len >= requiredHistory) {
                const pattern = this.actionHistory.slice(len - period);
                let cycleMatches = 1;
                for (let rep = 2; rep <= this.loopThreshold; rep++) {
                    const startIndex = len - (rep * period);
                    const candidate = this.actionHistory.slice(startIndex, startIndex + period);
                    if (this.arraysEqual(pattern, candidate)) {
                        cycleMatches++;
                    }
                    else {
                        break;
                    }
                }
                if (cycleMatches >= this.loopThreshold) {
                    const patternStr = pattern.join(' -> ');
                    throw new RunawayLoopError(`Sandstorm Emergency Brake: Runaway cyclic loop detected! Pattern [${patternStr}] repeated ${cycleMatches} cycles.`, patternStr, cycleMatches, this.totalSteps);
                }
            }
        }
    }
    arraysEqual(a, b) {
        if (a.length !== b.length)
            return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i])
                return false;
        }
        return true;
    }
    getStepsCount() {
        return this.totalSteps;
    }
    reset() {
        this.actionHistory.length = 0;
        this.totalSteps = 0;
    }
}
//# sourceMappingURL=loop.js.map
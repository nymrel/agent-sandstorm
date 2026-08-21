"""
limiter.py: Spend Budget Limiter & Runaway Loop Circuit Breaker (Python)
Copyright 2026 Nymrel / JalenBuilds LLC <contact@nymrel.com>
MIT License
"""

import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


class BudgetExceededError(Exception):
    def __init__(self, message: str, current_spend: float, max_spend: float, total_tokens: int):
        super().__init__(message)
        self.current_spend = current_spend
        self.max_spend = max_spend
        self.total_tokens = total_tokens


class RunawayLoopError(Exception):
    def __init__(self, message: str, pattern: str, repetitions: int, total_steps: int):
        super().__init__(message)
        self.pattern = pattern
        self.repetitions = repetitions
        self.total_steps = total_steps


class StepLimitExceededError(Exception):
    def __init__(self, message: str, total_steps: int, max_steps: int):
        super().__init__(message)
        self.total_steps = total_steps
        self.max_steps = max_steps


DEFAULT_MODEL_PRICING: Dict[str, Tuple[float, float]] = {
    "gpt-4o": (0.005, 0.015),
    "gpt-4o-mini": (0.00015, 0.0006),
    "claude-3-5-sonnet": (0.003, 0.015),
    "claude-3-5-haiku": (0.0008, 0.004),
    "claude-3-opus": (0.015, 0.075),
    "gemini-2.0-flash": (0.0001, 0.0004),
    "gemini-1.5-pro": (0.00125, 0.005),
    "deepseek-chat": (0.00014, 0.00028),
    "default": (0.002, 0.006),
}


class BudgetTracker:
    def __init__(
        self,
        max_spend_usd: Optional[float] = None,
        max_total_tokens: Optional[int] = None,
        custom_pricing: Optional[Dict[str, Tuple[float, float]]] = None,
    ):
        self.max_spend_usd = max_spend_usd if max_spend_usd is not None else float("inf")
        self.max_total_tokens = max_total_tokens if max_total_tokens is not None else float("inf")
        self.pricing = DEFAULT_MODEL_PRICING.copy()
        if custom_pricing:
            self.pricing.update(custom_pricing)

        self.total_spend_usd = 0.0
        self.total_tokens = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0

    def record_usage(self, model: str, prompt_tokens: int, completion_tokens: int) -> Dict[str, Any]:
        normalized = model.lower()
        p_rate, c_rate = self.pricing.get(normalized, self.pricing["default"])

        p_cost = (prompt_tokens / 1000.0) * p_rate
        c_cost = (completion_tokens / 1000.0) * c_rate
        cost = p_cost + c_cost

        self.total_spend_usd += cost
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        self.total_tokens += prompt_tokens + completion_tokens

        if self.total_spend_usd > self.max_spend_usd:
            raise BudgetExceededError(
                f"Spend limit exceeded: ${self.total_spend_usd:.4f} > ${self.max_spend_usd:.2f}",
                self.total_spend_usd,
                self.max_spend_usd,
                self.total_tokens,
            )

        if self.total_tokens > self.max_total_tokens:
            raise BudgetExceededError(
                f"Token limit exceeded: {self.total_tokens} > {self.max_total_tokens}",
                self.total_spend_usd,
                self.max_spend_usd,
                self.total_tokens,
            )

        return {
            "current_spend_usd": self.total_spend_usd,
            "total_tokens": self.total_tokens,
            "exceeded": False,
        }

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_spend_usd": round(self.total_spend_usd, 6),
            "total_tokens": self.total_tokens,
            "prompt_tokens": self.total_prompt_tokens,
            "completion_tokens": self.total_completion_tokens,
        }


class LoopDetector:
    def __init__(self, max_steps: int = 100, loop_threshold: int = 3, window_size: int = 20):
        self.max_steps = max_steps
        self.loop_threshold = loop_threshold
        self.window_size = window_size
        self.action_history: List[str] = []
        self.total_steps = 0

    def record_action(self, action_identifier: str, detail: Optional[str] = None) -> None:
        self.total_steps += 1
        if self.total_steps > self.max_steps:
            raise StepLimitExceededError(
                f"Max step limit ({self.max_steps}) exceeded.",
                self.total_steps,
                self.max_steps,
            )

        normalized = f"{action_identifier.strip()}:{detail.strip()}" if detail else action_identifier.strip()
        self.action_history.append(normalized)

        if len(self.action_history) > self.window_size:
            self.action_history.pop(0)

        self._check_loops()

    def _check_loops(self) -> None:
        n = len(self.action_history)
        if n < self.loop_threshold:
            return

        # 1. Consecutive identical action
        last_action = self.action_history[-1]
        consecutive = 0
        for item in reversed(self.action_history):
            if item == last_action:
                consecutive += 1
            else:
                break

        if consecutive >= self.loop_threshold:
            raise RunawayLoopError(
                f"Runaway loop: '{last_action}' repeated {consecutive} times consecutively.",
                last_action,
                consecutive,
                self.total_steps,
            )

        # 2. Cycles of period 2 to 5
        for period in range(2, 6):
            required = period * self.loop_threshold
            if n >= required:
                pattern = self.action_history[-period:]
                matches = 1
                for rep in range(2, self.loop_threshold + 1):
                    start = n - (rep * period)
                    candidate = self.action_history[start : start + period]
                    if candidate == pattern:
                        matches += 1
                    else:
                        break

                if matches >= self.loop_threshold:
                    pat_str = " -> ".join(pattern)
                    raise RunawayLoopError(
                        f"Runaway cyclic loop: [{pat_str}] repeated {matches} cycles.",
                        pat_str,
                        matches,
                        self.total_steps,
                    )


class ExecutionLimiter:
    def __init__(
        self,
        max_spend_usd: Optional[float] = None,
        max_total_tokens: Optional[int] = None,
        max_steps: int = 100,
        max_duration_ms: Optional[float] = None,
        loop_threshold: int = 3,
    ):
        self.budget = BudgetTracker(max_spend_usd=max_spend_usd, max_total_tokens=max_total_tokens)
        self.loop_detector = LoopDetector(max_steps=max_steps, loop_threshold=loop_threshold)
        self.max_duration_ms = max_duration_ms if max_duration_ms is not None else float("inf")
        self.start_time = time.time()

    def start(self) -> None:
        self.start_time = time.time()

    def check_timeout(self) -> None:
        elapsed = (time.time() - self.start_time) * 1000.0
        if elapsed > self.max_duration_ms:
            raise TimeoutError(f"Execution timeout: {elapsed:.0f}ms > {self.max_duration_ms:.0f}ms")

    def record_step(self, action: str, detail: Optional[str] = None) -> None:
        self.check_timeout()
        self.loop_detector.record_action(action, detail)

    def record_tokens(self, model: str, prompt_tokens: int, completion_tokens: int) -> Dict[str, Any]:
        self.check_timeout()
        return self.budget.record_usage(model, prompt_tokens, completion_tokens)

    def get_summary(self) -> Dict[str, Any]:
        summary = self.budget.get_summary()
        summary["steps_executed"] = self.loop_detector.total_steps
        summary["elapsed_ms"] = (time.time() - self.start_time) * 1000.0
        return summary

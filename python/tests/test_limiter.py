"""
Unit tests for Spend Limiter & Loop Circuit Breaker (Python)
"""

import unittest
from agent_sandstorm.limiter import (
    BudgetTracker,
    LoopDetector,
    BudgetExceededError,
    RunawayLoopError,
)


class TestLimiter(unittest.TestCase):
    def test_budget_tracker(self):
        tracker = BudgetTracker(max_spend_usd=1.0)
        u1 = tracker.record_usage("gpt-4o", 100000, 0)
        self.assertAlmostEqual(u1["current_spend_usd"], 0.50, places=2)

        with self.assertRaises(BudgetExceededError):
            tracker.record_usage("gpt-4o", 0, 50000)

    def test_loop_detector(self):
        detector = LoopDetector(loop_threshold=3)
        detector.record_action("cat file.txt")
        detector.record_action("cat file.txt")

        with self.assertRaises(RunawayLoopError):
            detector.record_action("cat file.txt")


if __name__ == "__main__":
    unittest.main()

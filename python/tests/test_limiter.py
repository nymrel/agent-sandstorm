"""
Unit tests for Spend Limiter & Loop Circuit Breaker (Python)
"""

import unittest
from agent_sandstorm.limiter import (
    BudgetTracker,
    LoopDetector,
    BudgetExceededError,
    RunawayLoopError,
    StepLimitExceededError,
    ExecutionLimiter,
)


class TestLimiter(unittest.TestCase):
    def test_budget_tracker(self):
        tracker = BudgetTracker(max_spend_usd=1.0)
        u1 = tracker.record_usage("gpt-4o", 100000, 0)
        self.assertAlmostEqual(u1["current_spend_usd"], 0.50, places=2)

        with self.assertRaises(BudgetExceededError):
            tracker.record_usage("gpt-4o", 0, 50000)

    def test_invalid_budget_inputs_fail_closed(self):
        with self.assertRaises(ValueError):
            BudgetTracker(max_spend_usd=-1)
        with self.assertRaises(ValueError):
            BudgetTracker(custom_pricing={"unsafe": (-1.0, 0.0)})

        tracker = BudgetTracker()
        with self.assertRaises(ValueError):
            tracker.record_usage("gpt-4o", -1, 0)
        with self.assertRaises(ValueError):
            LoopDetector(loop_threshold=0)
        with self.assertRaises(ValueError):
            ExecutionLimiter(max_duration_ms=-1)

    def test_loop_detector(self):
        detector = LoopDetector(loop_threshold=3)
        detector.record_action("cat file.txt")
        detector.record_action("cat file.txt")

        with self.assertRaises(RunawayLoopError):
            detector.record_action("cat file.txt")

        opt_out = ExecutionLimiter(loop_detection=False, loop_threshold=2, max_steps=3)
        opt_out.record_step("repeat")
        opt_out.record_step("repeat")
        opt_out.record_step("repeat")
        with self.assertRaises(StepLimitExceededError):
            opt_out.record_step("repeat")
        opt_out.reset()
        self.assertEqual(opt_out.get_summary()["steps_executed"], 0)


if __name__ == "__main__":
    unittest.main()

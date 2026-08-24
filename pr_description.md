🧪 Add missing evaluator invalid JSON test

🎯 **What:** This adds the missing error path test for `json.JSONDecodeError` handling in `_evaluate_convergence`.
📊 **Coverage:** A test uses a mock `FakeRunner` returning invalid JSON strings simulating evaluator execution failure when parsing invalid JSON output.
✨ **Result:** Test coverage for `JSONDecodeError` edge-cases is correctly asserted, and `ConvergenceExecutionError` exceptions are verified.

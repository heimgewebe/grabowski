from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import grabowski_merge_authority as authority


class MergeAuthorityTests(unittest.TestCase):
    def test_direct_pr_merge_is_classified_with_global_options(self) -> None:
        self.assertEqual(
            "direct_pr_merge",
            authority.github_merge_bypass_reason([
                "-R", "heimgewebe/vibe-lab", "pr", "merge", "350"
            ]),
        )
        self.assertEqual(
            "direct_pr_merge",
            authority.direct_merge_bypass_reason([
                "/usr/bin/gh", "--hostname=github.com", "pr", "merge", "350"
            ]),
        )

    def test_rest_and_graphql_merge_endpoints_are_classified(self) -> None:
        self.assertEqual(
            "rest_pull_merge",
            authority.github_merge_bypass_reason([
                "api", "--method", "PUT",
                "repos/heimgewebe/vibe-lab/pulls/350/merge",
            ]),
        )
        self.assertEqual(
            "graphql_pull_merge",
            authority.github_merge_bypass_reason([
                "api", "graphql", "-f",
                "query=mutation { mergePullRequest(input:{}) { clientMutationId } }",
            ]),
        )

    def test_non_merge_github_commands_remain_unclassified(self) -> None:
        self.assertIsNone(authority.github_merge_bypass_reason([
            "pr", "view", "350", "--repo", "heimgewebe/vibe-lab"
        ]))
        self.assertIsNone(authority.direct_merge_bypass_reason([
            "/usr/bin/git", "merge", "topic"
        ]))
        self.assertIsNone(authority.direct_merge_bypass_reason([
            "/usr/bin/gh", "api", "repos/heimgewebe/vibe-lab/pulls/350"
        ]))


if __name__ == "__main__":
    unittest.main()

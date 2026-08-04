import unittest

import grabowski_serving_process as serving


RELEASE_A = "aaaaaaaaaaaa-srcsetaaaa-lockaaaa-contractaaaa"
HEAD_A = "a" * 40
RELEASE_B = "bbbbbbbbbbbb-srcsetbbbb-lockbbbb-contractbbbb"
HEAD_B = "b" * 40


class ServingProcessIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        serving.reset_for_tests()
        self.addCleanup(serving.reset_for_tests)

    def test_matching_release_is_not_stale(self) -> None:
        serving.freeze(RELEASE_A, HEAD_A)
        projection = serving.identity(RELEASE_A, HEAD_A)
        self.assertTrue(projection["serves_deployed_release"])
        self.assertFalse(projection["stale"])
        self.assertIs(projection["matches_deployed_manifest"], True)
        self.assertFalse(serving.is_stale(RELEASE_A, HEAD_A))

    def test_newer_manifest_marks_process_stale(self) -> None:
        serving.freeze(RELEASE_A, HEAD_A)
        projection = serving.identity(RELEASE_B, HEAD_B)
        self.assertTrue(projection["stale"])
        self.assertFalse(projection["serves_deployed_release"])
        self.assertEqual(projection["process_release_id"], RELEASE_A)
        self.assertEqual(projection["manifest_release_id"], RELEASE_B)
        self.assertTrue(serving.is_stale(RELEASE_B, HEAD_B))

    def test_repo_head_drift_alone_marks_process_stale(self) -> None:
        serving.freeze(RELEASE_A, HEAD_A)
        self.assertTrue(serving.is_stale(RELEASE_A, HEAD_B))

    def test_unknown_manifest_identity_is_never_stale(self) -> None:
        serving.freeze(RELEASE_A, HEAD_A)
        for release, head in (
            (None, None),
            (RELEASE_B, None),
            (None, HEAD_B),
            (RELEASE_B, "not-a-head"),
            ("", HEAD_B),
        ):
            with self.subTest(release=release, head=head):
                projection = serving.identity(release, head)
                self.assertIsNone(projection["matches_deployed_manifest"])
                self.assertFalse(projection["stale"])
                self.assertFalse(serving.is_stale(release, head))

    def test_unknown_process_identity_is_never_stale(self) -> None:
        projection = serving.identity(RELEASE_B, HEAD_B)
        self.assertFalse(projection["process_identity_known"])
        self.assertIsNone(projection["matches_deployed_manifest"])
        self.assertFalse(serving.is_stale(RELEASE_B, HEAD_B))

    def test_freeze_rejects_invalid_identity(self) -> None:
        serving.freeze(RELEASE_A, "not-a-head")
        self.assertFalse(serving.identity(RELEASE_A, HEAD_A)["process_identity_known"])
        serving.freeze("", HEAD_A)
        self.assertFalse(serving.identity(RELEASE_A, HEAD_A)["process_identity_known"])

    def test_first_freeze_wins(self) -> None:
        serving.freeze(RELEASE_A, HEAD_A)
        serving.freeze(RELEASE_B, HEAD_B)
        projection = serving.identity(RELEASE_B, HEAD_B)
        self.assertEqual(projection["process_release_id"], RELEASE_A)
        self.assertTrue(projection["stale"])

    def test_rejection_message_names_both_releases_and_the_remedy(self) -> None:
        serving.freeze(RELEASE_A, HEAD_A)
        message = serving.mutation_rejection_message(RELEASE_B, HEAD_B)
        self.assertIn(RELEASE_A, message)
        self.assertIn(RELEASE_B, message)
        self.assertIn("Reconnect", message)
        self.assertIn("deploying again does not repair this session", message.lower())

    def test_rule_binds_the_release_the_process_started_under(self) -> None:
        """The check is forward-acting: it fires on the next release, not this one.

        A process that starts under the release carrying this change matches
        its own manifest and is admitted. It only blocks once a later release
        is deployed underneath it. A process older than this change cannot run
        the check at all, which is why the remedy is a reconnect rather than
        another deployment.
        """
        serving.freeze(RELEASE_A, HEAD_A)
        self.assertFalse(serving.is_stale(RELEASE_A, HEAD_A))
        self.assertTrue(serving.is_stale(RELEASE_B, HEAD_B))

    def test_projection_states_its_limits(self) -> None:
        serving.freeze(RELEASE_A, HEAD_A)
        projection = serving.identity(RELEASE_A, HEAD_A)
        self.assertEqual(projection["schema_version"], serving.SCHEMA_VERSION)
        self.assertEqual(projection["kind"], serving.KIND)
        self.assertIn(
            "that the deployed release is itself correct",
            projection["does_not_establish"],
        )


if __name__ == "__main__":
    unittest.main()

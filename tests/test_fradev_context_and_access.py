import json
import tempfile
import unittest
from pathlib import Path

from core.access_policy import AccessPolicy
from memory.fradev_context import load_fradev_context
from memory.memory_manager import format_memory_for_prompt


class AccessPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.config_path = self.root / "fradev.local.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_config(self, projects):
        self.config_path.write_text(
            json.dumps({"projects": projects}),
            encoding="utf-8",
        )

    def test_missing_config_denies_by_default(self):
        policy = AccessPolicy.load(self.config_path)

        decision = policy.check(self.root / "project" / "file.py", "read")

        self.assertFalse(decision.allowed)
        self.assertIn("config", decision.reason.lower())

    def test_parses_project_permissions(self):
        project = self.root / "project"
        project.mkdir()
        self.write_config(
            [
                {
                    "path": str(project),
                    "permissions": {
                        "read": True,
                        "write": False,
                        "test": True,
                        "commit": False,
                        "remote": False,
                    },
                }
            ]
        )

        policy = AccessPolicy.load(self.config_path)

        self.assertTrue(policy.check(project / "README.md", "read").allowed)
        self.assertTrue(policy.check(project, "test").allowed)

    def test_most_specific_project_wins(self):
        parent = self.root / "project"
        child = parent / "restricted"
        child.mkdir(parents=True)
        self.write_config(
            [
                {"path": str(parent), "permissions": {"write": True}},
                {"path": str(child), "permissions": {"write": False}},
            ]
        )

        decision = AccessPolicy.load(self.config_path).check(child / "data.txt", "write")

        self.assertFalse(decision.allowed)
        self.assertEqual(decision.project_path, child.resolve())
        self.assertIn("write", decision.reason)

    def test_symlink_escape_is_denied(self):
        project = self.root / "project"
        outside = self.root / "outside"
        project.mkdir()
        outside.mkdir()
        (project / "escape").symlink_to(outside, target_is_directory=True)
        self.write_config(
            [{"path": str(project), "permissions": {"read": True}}]
        )

        decision = AccessPolicy.load(self.config_path).check(
            project / "escape" / "secret.txt", "read"
        )

        self.assertFalse(decision.allowed)
        self.assertIn("outside configured projects", decision.reason)

    def test_permission_denial_has_useful_reason(self):
        project = self.root / "project"
        project.mkdir()
        self.write_config(
            [{"path": str(project), "permissions": {"read": True, "remote": False}}]
        )

        decision = AccessPolicy.load(self.config_path).check(project, "remote")

        self.assertFalse(decision.allowed)
        self.assertIn("remote", decision.reason)
        self.assertIn(str(project.resolve()), decision.reason)


class FraDevContextTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.config_path = self.root / "fradev.local.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_config(self, sources, max_chars=10_000):
        self.config_path.write_text(
            json.dumps(
                {
                    "context_sources": sources,
                    "context_max_chars": max_chars,
                    "projects": [],
                }
            ),
            encoding="utf-8",
        )

    def test_labels_each_context_source(self):
        identity = self.root / "IDENTITY.md"
        tooling = self.root / "TOOLING.md"
        identity.write_text("Builder profile", encoding="utf-8")
        tooling.write_text("Uses Python", encoding="utf-8")
        self.write_config([str(identity), str(tooling)])

        context = load_fradev_context(self.config_path)

        self.assertIn("### IDENTITY.md\nBuilder profile", context)
        self.assertIn("### TOOLING.md\nUses Python", context)

    def test_missing_sources_are_skipped(self):
        existing = self.root / "PROJECTS.md"
        existing.write_text("Mark-L", encoding="utf-8")
        self.write_config([str(self.root / "missing.md"), str(existing)])

        context = load_fradev_context(self.config_path)

        self.assertNotIn("missing.md", context)
        self.assertIn("Mark-L", context)

    def test_context_is_truncated_to_configured_character_limit(self):
        source = self.root / "IDENTITY.md"
        source.write_text("🙂" * 100, encoding="utf-8")
        self.write_config([str(source)], max_chars=60)

        context = load_fradev_context(self.config_path)

        self.assertLessEqual(len(context), 60)
        self.assertTrue(context.endswith("…"))
        self.assertNotIn("\ufffd", context)

    def test_likely_secrets_are_redacted(self):
        source = self.root / "TOOLING.md"
        source.write_text(
            "API_KEY=sk_live_abcdefghijklmnop\n"
            "GEMINI_API_KEY=plain-but-sensitive-value\n"
            "DB_PASSWORD=database secret phrase\n"
            "password: correct horse battery staple\n"
            "token = ghp_abcdefghijklmnopqrstuvwxyz123456\n"
            "-----BEGIN PRIVATE KEY-----\nprivate material\n-----END PRIVATE KEY-----\n"
            "Safe note remains.",
            encoding="utf-8",
        )
        self.write_config([str(source)])

        context = load_fradev_context(self.config_path)

        for secret in (
            "sk_live_",
            "plain-but-sensitive-value",
            "database secret phrase",
            "correct horse battery staple",
            "horse battery",
            "ghp_",
            "private material",
        ):
            self.assertNotIn(secret, context)
        self.assertIn("[REDACTED]", context)
        self.assertIn("Safe note remains.", context)

    def test_memory_prompt_appends_context_without_changing_stored_memory(self):
        source = self.root / "IDENTITY.md"
        source.write_text("FraDev context", encoding="utf-8")
        self.write_config([str(source)])
        memory = {"identity": {"name": {"value": "Marlon"}}}
        original = json.loads(json.dumps(memory))

        prompt = format_memory_for_prompt(memory, self.config_path)

        self.assertIn("Name: Marlon", prompt)
        self.assertIn("FraDev context", prompt)
        self.assertEqual(memory, original)

    def test_no_local_config_preserves_existing_prompt(self):
        memory = {"identity": {"name": {"value": "Marlon"}}}

        prompt = format_memory_for_prompt(memory, self.root / "missing.json")

        self.assertEqual(
            prompt,
            "[WHAT YOU KNOW ABOUT THIS PERSON — use naturally, never recite like a list]\n"
            "Name: Marlon\n",
        )


if __name__ == "__main__":
    unittest.main()

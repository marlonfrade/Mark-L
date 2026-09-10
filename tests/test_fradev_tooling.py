import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.access_policy import AccessPolicy


def _completed(args, stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args, returncode, stdout, stderr)


class FraDevToolingTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.config_path = self.root / "fradev.local.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_config(self, permissions=None, pop_root=None):
        data = {
            "projects": [
                {
                    "path": str(self.project),
                    "permissions": permissions
                    or {
                        "read": True,
                        "write": True,
                        "test": True,
                        "commit": True,
                        "remote": False,
                    },
                }
            ]
        }
        if pop_root is not None:
            data["pop_root"] = str(pop_root)
        self.config_path.write_text(json.dumps(data), encoding="utf-8")

    def init_git_repo(self):
        subprocess.run(["git", "init", str(self.project)], check=True, capture_output=True)
        (self.project / "note.txt").write_text("one\n", encoding="utf-8")

    def test_lists_only_configured_projects_and_permissions(self):
        from actions.fradev_projects import fradev_projects

        self.write_config()
        result = fradev_projects({"action": "list"}, config_path=self.config_path)

        self.assertIn(str(self.project.resolve()), result)
        self.assertIn("read", result)
        self.assertIn("remote=false", result.lower())
        self.assertNotIn("context_sources", result)

    def test_project_status_denies_unauthorized_path(self):
        from actions.fradev_projects import fradev_projects

        self.write_config()
        result = fradev_projects(
            {"action": "status", "project_path": str(self.root / "other")},
            config_path=self.config_path,
        )

        self.assertIn("access denied", result.lower())

    def test_git_status_and_diff_are_local_and_read_only(self):
        from actions.git_control import git_control

        self.write_config()
        calls = []

        def runner(args, **kwargs):
            calls.append((args, kwargs))
            output = "## feat/test\n M note.txt" if "status" in args else "diff --git a/note.txt b/note.txt"
            return _completed(args, stdout=output)

        status = git_control(
            {"action": "status", "project_path": str(self.project)},
            config_path=self.config_path,
            runner=runner,
        )
        diff = git_control(
            {"action": "diff", "project_path": str(self.project)},
            config_path=self.config_path,
            runner=runner,
        )

        self.assertIn("note.txt", status)
        self.assertIn("diff --git", diff)
        self.assertEqual(calls[0][0][-2:], ["--short", "--branch"])
        self.assertEqual(
            calls[1][0][-3:],
            ["diff", "--no-ext-diff", "--no-textconv"],
        )
        self.assertTrue(all("shell" not in kwargs for _, kwargs in calls))

    def test_git_remote_operation_is_denied(self):
        from actions.git_control import git_control

        self.write_config()
        result = git_control(
            {"action": "push", "project_path": str(self.project)},
            config_path=self.config_path,
        )

        self.assertIn("denied", result.lower())
        self.assertIn("remote", result.lower())

    def test_git_commit_requires_non_empty_message(self):
        from actions.git_control import git_control

        self.write_config()
        result = git_control(
            {
                "action": "commit",
                "project_path": str(self.project),
                "message": "   ",
            },
            config_path=self.config_path,
        )

        self.assertIn("message", result.lower())

    def test_pop_status_constructs_canonical_argument_array(self):
        from actions.pop_control import pop_control

        scripts = self.root / "pop" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "pop_status.py").write_text("", encoding="utf-8")
        self.write_config(pop_root=scripts.parent)
        calls = []

        def runner(args, **kwargs):
            calls.append((args, kwargs))
            return _completed(args, stdout="healthy")

        result = pop_control(
            {"action": "status", "project": "Apps/Mark-L"},
            config_path=self.config_path,
            runner=runner,
        )

        self.assertEqual(result, "healthy")
        self.assertEqual(calls[0][0][1], str((scripts / "pop_status.py").resolve()))
        self.assertEqual(calls[0][0][2:], ["--project", "Apps/Mark-L"])
        self.assertNotIn("shell", calls[0][1])

    def test_pop_task_and_move_allow_only_structured_arguments(self):
        from actions.pop_control import pop_control

        scripts = self.root / "pop" / "scripts"
        scripts.mkdir(parents=True)
        for name in ("pop_task.py", "pop_move.py"):
            (scripts / name).write_text("", encoding="utf-8")
        self.write_config(pop_root=scripts.parent)
        calls = []

        def runner(args, **kwargs):
            calls.append(args)
            return _completed(args, stdout="ok")

        pop_control(
            {
                "action": "task",
                "project": "Apps/Mark-L",
                "task_id": "TASK-2",
                "title": "Integrate tools",
            },
            config_path=self.config_path,
            runner=runner,
        )
        pop_control(
            {
                "action": "move",
                "task_id": "TASK-2",
                "stage": "004_processing",
                "reason": "implementation started",
            },
            config_path=self.config_path,
            runner=runner,
        )

        self.assertEqual(
            calls[0][2:],
            ["Apps/Mark-L", "TASK-2", "--title", "Integrate tools"],
        )
        self.assertEqual(
            calls[1][2:],
            ["TASK-2", "004_processing", "--reason", "implementation started"],
        )
        denied = pop_control(
            {"action": "command", "command": "rm -rf /"},
            config_path=self.config_path,
            runner=runner,
        )
        self.assertIn("unsupported", denied.lower())

    def test_code_helper_maps_explicit_paths_to_permissions(self):
        from actions.code_helper import code_helper

        class RecordingPolicy:
            def __init__(self):
                self.requests = []

            def check(self, path, permission):
                self.requests.append((str(path), permission))
                return type(
                    "Decision",
                    (),
                    {"allowed": False, "reason": f"{permission} denied"},
                )()

        cases = [
            ("explain", "file_path", "read"),
            ("edit", "file_path", "write"),
            ("write", "output_path", "write"),
            ("run", "file_path", "test"),
            ("build", "output_path", "write"),
        ]
        for action, path_key, permission in cases:
            with self.subTest(action=action, permission=permission):
                policy = RecordingPolicy()
                result = code_helper(
                    {"action": action, path_key: str(self.project / "x.py")},
                    access_policy=policy,
                )
                self.assertIn("access denied", result.lower())
                self.assertIn((str(self.project / "x.py"), permission), policy.requests)

        class BuildPolicy(RecordingPolicy):
            def check(self, path, permission):
                self.requests.append((str(path), permission))
                return type(
                    "Decision",
                    (),
                    {"allowed": permission == "write", "reason": f"{permission} denied"},
                )()

        policy = BuildPolicy()
        code_helper(
            {"action": "build", "output_path": str(self.project / "x.py")},
            access_policy=policy,
        )
        self.assertIn((str(self.project / "x.py"), "test"), policy.requests)

    def test_dev_agent_denies_unauthorized_project_path_before_planning(self):
        from actions.dev_agent import dev_agent

        self.write_config()
        with patch("actions.dev_agent._plan_project") as planner:
            result = dev_agent(
                {
                    "description": "change the project",
                    "project_path": str(self.root / "outside"),
                },
                access_policy=AccessPolicy.load(self.config_path),
            )

        self.assertIn("access denied", result.lower())
        planner.assert_not_called()

    def test_dev_agent_project_path_rejects_generated_path_escape(self):
        from actions.dev_agent import dev_agent

        self.write_config()
        plan = {
            "project_name": "ignored",
            "entry_point": "../escape.py",
            "files": [{"path": "../escape.py", "description": "escape", "imports": []}],
            "run_command": "python ../escape.py",
            "dependencies": [],
        }
        model = type(
            "Model",
            (),
            {"generate_content": lambda self, prompt: type("Response", (), {"text": "x = 1"})()},
        )()
        with (
            patch("actions.dev_agent._plan_project", return_value=plan),
            patch("actions.dev_agent._get_model", return_value=model),
            patch("actions.dev_agent._open_vscode", return_value=False),
            patch("actions.dev_agent._run_project", return_value=""),
        ):
            result = dev_agent(
                {
                    "description": "change the project",
                    "project_path": str(self.project),
                },
                access_policy=AccessPolicy.load(self.config_path),
            )

        self.assertIn("unsafe", result.lower())
        self.assertFalse((self.root / "escape.py").exists())

    def test_action_loader_discovers_all_fradev_tools(self):
        from core.action_loader import discover_actions

        root = Path(__file__).resolve().parents[1]
        registry = discover_actions(
            actions_dir=root / "actions",
            reserved_names=set(),
            logger=lambda _msg: None,
        )
        declarations = {
            item["name"]: item for item in registry.get_tool_declarations()
        }

        for tool in ("fradev_projects", "pop_control", "git_control"):
            self.assertIn(tool, declarations)
            self.assertTrue(registry.has(tool))

        self.assertIn(
            "project_path",
            declarations["fradev_projects"]["parameters"]["properties"],
        )
        self.assertIn(
            "project_path",
            declarations["git_control"]["parameters"]["properties"],
        )
        self.assertIn(
            "project_path",
            declarations["dev_agent"]["parameters"]["properties"],
        )


if __name__ == "__main__":
    unittest.main()

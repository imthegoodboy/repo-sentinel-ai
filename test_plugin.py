import io
import json
import os
import unittest
import zipfile
from unittest.mock import patch

import repo_sentinel_ai_plugin as plugin


def archive(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zipped:
        for path, content in files.items():
            zipped.writestr(f"repo-main/{path}", content)
    return buffer.getvalue()


class RepoSentinelToolTests(unittest.TestCase):
    def test_parses_only_github_repository_addresses(self):
        self.assertEqual(plugin.parse_github_repository("acme/api"), ("acme", "api"))
        self.assertEqual(plugin.parse_github_repository("https://github.com/acme/api.git"), ("acme", "api"))
        with self.assertRaises(plugin.AuditError):
            plugin.parse_github_repository("https://example.com/acme/api")

    def test_scans_supported_files_without_executing_and_redacts_secrets(self):
        fake = archive({
            "src/auth.py": "import subprocess\nsubprocess.run(command, shell=True)\nDEBUG = True\n",
            "src/token.js": "const token = 'ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN';\n",
            "src/view.tsx": "return <div dangerouslySetInnerHTML={{__html: body}} />;\n",
            "package.json": '{"dependencies":{"react":"1.0.0"}}',
            "node_modules/pkg/index.js": "eval(untrusted)",
            "public/app.min.js": "eval(untrusted)",
            "image.png": b"\x89PNG\x00binary",
        })
        report = plugin.audit_archive({"owner": "acme", "name": "api", "default_branch": "main"}, fake, "main", "abc123")
        self.assertTrue(report["ok"])
        self.assertFalse(report["limits"]["repositoryCodeExecuted"])
        self.assertEqual(report["stats"]["filesDiscovered"], 7)
        self.assertIn("React", report["architecture"]["frameworkHints"])
        self.assertTrue(any(item["ruleId"] == "code.python-shell" for item in report["findings"]))
        secret = next(item for item in report["findings"] if item["ruleId"] == "secret.github-token")
        self.assertIn("[REDACTED CREDENTIAL]", secret["snippet"])
        self.assertNotIn("ghp_", secret["snippet"])
        reasons = {item["reason"]: item["count"] for item in report["coverage"]["excluded"]}
        self.assertEqual(reasons["dependency or build output"], 1)
        self.assertEqual(reasons["generated or minified"], 1)

    def test_environment_file_is_reported_without_returning_contents(self):
        fake = archive({".env": "PASSWORD=super-secret-value", "app.py": "print('safe')"})
        report = plugin.audit_archive({"owner": "acme", "name": "api"}, fake, "main")
        finding = next(item for item in report["findings"] if item["ruleId"] == "secret.env-file")
        self.assertEqual(finding["snippet"], "[contents intentionally not displayed]")

    def test_scans_additional_security_relevant_formats_and_patterns(self):
        fake = archive({
            "infra/main.tf": 'resource "aws_iam_policy" "wide" { policy = jsonencode({ Action = "*" }) }',
            "scripts/deploy.ps1": "Invoke-Expression $userInput",
            "certs/server.pem": "-----BEGIN PRIVATE KEY-----\nsecret\n",
            "service.js": "child_process.exec(command);",
        })
        report = plugin.audit_archive({"owner": "acme", "name": "infra"}, fake, "main")
        rules = {item["ruleId"] for item in report["findings"]}
        self.assertIn("cloud.iam-wildcard-action", rules)
        self.assertIn("code.powershell-expression", rules)
        self.assertIn("secret.private-key", rules)
        self.assertIn("code.node-shell", rules)

    def test_generated_bundle_occurrences_do_not_double_penalize_source_findings(self):
        fake = archive({
            "src/main.js": "root.innerHTML = renderApp(state);\nmodalRoot.innerHTML = markup;\n",
            "bundle/app.js": "// compiled output\nroot.innerHTML = renderApp(state);\nmodalRoot.innerHTML = markup;\n",
            "server/worker.js": 'const headers = {"access-control-allow-origin": "*"};\n',
        })
        report = plugin.audit_archive({"owner": "acme", "name": "app"}, fake, "main")
        self.assertEqual(report["stats"]["findingCandidates"], 3)
        self.assertEqual(report["health"]["severityCounts"]["medium"], 3)
        self.assertEqual(report["health"]["score"], 82)
        raw_html = [item for item in report["findings"] if item["ruleId"] == "web.raw-html"]
        self.assertEqual(len(raw_html), 2)
        self.assertTrue(all(item["path"].startswith("src/") for item in raw_html))
        self.assertTrue(all(item["totalOccurrences"] == 2 for item in raw_html))
        self.assertTrue(all(item["relatedLocations"][0]["path"].startswith("bundle/") for item in raw_html))

    def test_unsafe_archive_paths_are_inventory_only(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zipped:
            zipped.writestr("repo-main/../../escape.py", "eval(user_input)")
            zipped.writestr("repo-main/safe.py", "print('ok')")
        report = plugin.audit_archive({"owner": "acme", "name": "api"}, buffer.getvalue(), "main")
        self.assertEqual(report["stats"]["filesScanned"], 1)
        self.assertFalse(report["findings"])

    def test_uncompressed_limit_fails_closed(self):
        original = plugin.MAX_UNCOMPRESSED_BYTES
        plugin.MAX_UNCOMPRESSED_BYTES = 10
        try:
            with self.assertRaises(plugin.AuditError) as error:
                plugin.audit_archive({"owner": "acme", "name": "api"}, archive({"app.py": "print('more than ten')"}), "main")
            self.assertEqual(error.exception.code, "REPOSITORY_TOO_LARGE")
        finally:
            plugin.MAX_UNCOMPRESSED_BYTES = original

    def test_protocol_initialize_and_unknown_method(self):
        response = plugin.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2.0"}})
        self.assertEqual(response["result"]["protocolVersion"], "2.0")
        self.assertFalse(plugin.invoke("unknown", {})["success"])

    def test_github_connection_is_optional_and_never_returns_a_secret(self):
        described = plugin.handle_request({"jsonrpc": "2.0", "id": 2, "method": "describe"})["result"]
        github_credential = next(item for item in described["credentials"] if item["name"] == "GITHUB_TOKEN")
        self.assertFalse(github_credential["required"])
        self.assertTrue(github_credential["sensitive"])
        status = plugin.invoke(plugin.STATUS_METHOD, {})
        repositories = plugin.invoke(plugin.REPOSITORIES_METHOD, {})
        self.assertTrue(status["data"]["ok"])
        self.assertFalse(status["data"]["connected"])
        self.assertEqual(repositories["data"]["repositories"], [])
        self.assertNotIn("token", json.dumps(status).lower())

    def test_invoke_reads_credentials_from_context_without_exposing_them(self):
        response = plugin.handle_request({
            "jsonrpc": "2.0", "id": 3, "method": "invoke",
            "params": {"tool": plugin.REPOSITORIES_METHOD, "arguments": {}, "context": {"credentials": {}}},
        })
        self.assertTrue(response["result"]["success"])
        self.assertFalse(response["result"]["data"]["connected"])

    def test_connected_account_and_repository_picker_are_bounded_metadata(self):
        credential = {"GITHUB_TOKEN": "test-secret-that-must-not-be-returned"}
        user = {"login": "maintainer", "name": "Repo Maintainer", "avatar_url": "https://avatars.githubusercontent.com/u/1"}
        repositories = [{
            "id": 42, "name": "private-api", "full_name": "maintainer/private-api",
            "owner": {"login": "maintainer"}, "html_url": "https://github.com/maintainer/private-api",
            "description": "Internal API", "private": True, "archived": False,
            "default_branch": "main", "language": "Python", "updated_at": "2026-09-04T00:00:00Z",
            "stargazers_count": 0,
        }]
        with patch.object(plugin, "_request_json", side_effect=[user, repositories]):
            status = plugin.github_connection_status(credential)
            result = plugin.list_github_repositories(credential)
        self.assertTrue(status["connected"])
        self.assertEqual(status["account"]["login"], "maintainer")
        self.assertTrue(result["repositories"][0]["private"])
        combined = json.dumps({"status": status, "result": result})
        self.assertNotIn(credential["GITHUB_TOKEN"], combined)

    def test_environment_credential_is_only_a_local_development_fallback(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "local-only-secret"}):
            self.assertEqual(plugin._github_token({}), "local-only-secret")


if __name__ == "__main__":
    unittest.main()

"""Offline tests. Synthetic identities only; all socket creation is forbidden."""
import contextlib
import copy
import hashlib
import io
import json
import pathlib
import socket
import ssl
import sys
import threading
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))  # Test-only import under python -I.
import runner as r
import private_destination_digest as digest_helper

CODE = "a" * 40
OTHER = "b" * 40
PUBLIC_REPO_ID = 7654321  # Synthetic; not an existing repository.
SYNTHETIC_CHAT = -1000000000042
SYNTHETIC_BOT = 654321
SYNTHETIC_TOKEN = "654321:" + "x" * 35


def environment():
    return {
        "GITHUB_SHA": CODE, "GITHUB_WORKFLOW_SHA": CODE, "APPROVED_COMMIT_SHA": CODE,
        "REVIEWED_SHA": CODE, "GITHUB_WORKFLOW_REF": r.WORKFLOW,
        "GITHUB_REPOSITORY": r.REPOSITORY, "GITHUB_REPOSITORY_OWNER_ID": str(r.OWNER_ID),
        "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_RUN_ATTEMPT": "1", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux", "CONTROL_REVIEW_COMPLETE": "true",
        "GITHUB_SERVER_URL": "https://github.com", "GITHUB_API_URL": "https://api.github.com",
        "APPROVED_REPOSITORY_ID": str(PUBLIC_REPO_ID), "GITHUB_REPOSITORY_ID": str(PUBLIC_REPO_ID),
        "DESTINATION_PRIVATELY_CONFIRMED": "true", "TELEGRAM_CHAT_ID": str(SYNTHETIC_CHAT),
        "TELEGRAM_CHAT_SHA256": hashlib.sha256(str(SYNTHETIC_CHAT).encode()).hexdigest(),
        "TELEGRAM_BOT_TOKEN": SYNTHETIC_TOKEN, "RELEASE_ONE_TEST": "true", "GH_TOKEN": "synthetic-github-token-value",
    }


def reference(name, sha):
    return {"ref": f"refs/{name}", "object": {"type": "commit", "sha": sha}}


class FakePlatform:
    """Model documented controls, not evidence that a future repo is configured."""
    def __init__(self):
        self.lock = threading.Lock()
        self.refs = {"heads/main": CODE, f"tags/{r.ARMED}": CODE}
        self.repo = {"id": PUBLIC_REPO_ID, "full_name": r.REPOSITORY, "private": False,
                     "visibility": "public", "default_branch": "main", "archived": False,
                     "owner": {"id": r.OWNER_ID}}
        self.rules = [json.loads((ROOT / "controls" / file).read_text()) for file in (
            "main-freeze.json", "immutable-activation-tags.json",
        )]
        for index, rule in enumerate(self.rules, 1):
            rule["id"] = index
        self.env = {
            "name": r.ENVIRONMENT,
            "can_admins_bypass": False,
            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
            "protection_rules": [{"type": "required_reviewers", "prevent_self_review": False,
                                  "reviewers": [{"type": "User", "reviewer": {"id": r.OWNER_ID, "login": r.OWNER}}]}],
        }
        self.branches = {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]}
        self.old_refs = {"heads/main": r.V1_COMMIT, f"tags/{r.V1_ARMED}": r.V1_COMMIT,
                         f"tags/{r.V1_CONSUMED}": r.V1_COMMIT}
        self.old_repo = {"id": r.V1_REPOSITORY_ID, "full_name": r.V1_REPOSITORY,
                         "owner": {"id": r.OWNER_ID}, "private": False,
                         "visibility": "public", "default_branch": "main", "archived": False}
        self.old_rules = copy.deepcopy(self.rules)
        self.old_rules[1]["conditions"]["ref_name"]["include"] = [
            f"refs/tags/{r.V1_ARMED}", f"refs/tags/{r.V1_CONSUMED}"]
        self.old_workflow = {"path": ".github/workflows/connection-test.yml", "state": "disabled_manually"}
        self.old_runs = {"total_count": len(r.V1_RUNS), "workflow_runs": [
            {"id": run_id, "event": event, "path": path, "conclusion": conclusion,
             "head_sha": r.V1_COMMIT, "head_branch": "main", "run_attempt": 1, "status": "completed"}
            for run_id, (event, path, conclusion) in r.V1_RUNS.items()]}
        self.old_jobs = {"total_count": 2, "jobs": [
            {"name": name, "run_id": r.V1_TEST_RUN, "run_attempt": 1,
             "head_sha": r.V1_COMMIT, "status": "completed", "conclusion": conclusion,
             "steps": [] if name == "test" else [{"name": "Read public protection metadata only", "conclusion": "failure"}]}
            for name, conclusion in [("audit", "failure"), ("test", "skipped")]]}
        self.legacy_calls = []
        self.calls = []
        self.claims = 0
        self.claim_barrier = None
        self.uncertain_claim = False

    def platform_release(self, ref, executing_sha, approved_by=None):
        # Only frozen main's existing code can execute with this environment.
        return ref == "refs/heads/main" and executing_sha == self.refs["heads/main"] and approved_by == r.OWNER

    def change_ref(self, name, value):
        with self.lock:
            if name == "heads/main" or name in {f"tags/{r.ARMED}", f"tags/{r.CONSUMED}"}:
                raise r.Blocked()  # No bypass; update/deletion forbidden.
            self.refs[name] = value

    def request(self, host, method, path, headers, body=None):
        if host != "api.github.com":
            raise AssertionError("Fake GitHub used for Telegram")
        old_prefix = f"/repos/{r.V1_REPOSITORY}"
        if path == old_prefix or path.startswith(old_prefix + "/"):
            assert method == "GET" and body is None and "Authorization" not in headers
            suffix = path[len(old_prefix):]
            with self.lock:
                self.legacy_calls.append((method, suffix))
                if suffix == "":
                    return 200, copy.deepcopy(self.old_repo)
                if suffix == "/rulesets?per_page=100":
                    return 200, [{"id": rule["id"], "name": rule["name"]} for rule in self.old_rules]
                if suffix.startswith("/rulesets/"):
                    return 200, copy.deepcopy(next(rule for rule in self.old_rules if rule["id"] == int(suffix.rsplit("/", 1)[1])))
                if suffix == "/actions/workflows/connection-test.yml":
                    return 200, copy.deepcopy(self.old_workflow)
                if suffix == "/actions/runs?per_page=100":
                    return 200, copy.deepcopy(self.old_runs)
                if suffix == f"/actions/runs/{r.V1_TEST_RUN}/attempts/1/jobs?per_page=100":
                    return 200, copy.deepcopy(self.old_jobs)
                if suffix.startswith("/git/ref/"):
                    name = suffix[len("/git/ref/"):]
                    if name not in self.old_refs:
                        return 404, {"message": "Not Found"}
                    return 200, reference(name, self.old_refs[name])
            raise AssertionError("Unexpected historical API operation")
        prefix = f"/repos/{r.REPOSITORY}"
        assert path.startswith(prefix)
        suffix = path[len(prefix):]
        with self.lock:
            self.calls.append((method, suffix))
        if method == "POST":
            payload = json.loads(body)
            assert suffix == "/git/refs"
            if self.claim_barrier:
                self.claim_barrier.wait(timeout=5)
            with self.lock:
                name = payload["ref"][5:]
                if name in self.refs:
                    return 422, {"message": "Reference already exists"}
                self.refs[name] = payload["sha"]
                self.claims += 1
                if self.uncertain_claim:
                    raise r.Blocked()
                return 201, reference(name, payload["sha"])
        with self.lock:
            if suffix == "":
                return 200, copy.deepcopy(self.repo)
            if suffix == "/rulesets?per_page=100":
                return 200, [{"id": rule["id"], "name": rule["name"]} for rule in self.rules]
            if suffix.startswith("/rulesets/"):
                return 200, copy.deepcopy(next(rule for rule in self.rules if rule["id"] == int(suffix.split("/")[-1])))
            if suffix == f"/environments/{r.ENVIRONMENT}":
                return 200, copy.deepcopy(self.env)
            if suffix.endswith("/deployment-branch-policies?per_page=100"):
                return 200, copy.deepcopy(self.branches)
            if suffix.startswith("/git/ref/"):
                name = suffix[len("/git/ref/"):]
                if name not in self.refs:
                    return 404, {"message": "Not Found"}
                return 200, reference(name, self.refs[name])
        raise AssertionError("Unexpected API operation")


class FakeTelegram:
    def __init__(self, platform, *, fail=None):
        self.platform, self.fail = platform, fail
        self.methods = []
        self.bodies = []
        self.chat = {"id": SYNTHETIC_CHAT, "type": "supergroup", "permissions": {"can_send_messages": True}}
        self.member = {"user": {"id": SYNTHETIC_BOT}, "status": "member"}

    def request(self, host, method, path, headers, body=None):
        assert host == "api.telegram.org" and method == "POST"
        assert self.platform.refs.get(f"tags/{r.CONSUMED}") == CODE
        assert self.platform.old_refs.get(f"tags/{r.V1_ARMED}") == r.V1_COMMIT
        assert self.platform.old_refs.get(f"tags/{r.V1_CONSUMED}") == r.V1_COMMIT
        assert path.startswith(f"/bot{SYNTHETIC_TOKEN}/")
        operation = path.rsplit("/", 1)[-1]
        self.methods.append(operation)
        self.bodies.append(json.loads(body))
        if self.fail == operation:
            raise r.Blocked()
        values = {
            "getMe": {"id": SYNTHETIC_BOT, "is_bot": True},
            "getChat": copy.deepcopy(self.chat), "getChatMember": copy.deepcopy(self.member),
            "sendMessage": {"message_id": 3, "text": r.MESSAGE, "chat": copy.deepcopy(self.chat)},
        }
        return 200, {"ok": True, "result": values[operation]}


class Offline(unittest.TestCase):
    def setUp(self):
        self.no_socket = mock.patch.object(socket, "socket", side_effect=AssertionError("NETWORK_FORBIDDEN"))
        self.no_socket.start()
        self.addCleanup(self.no_socket.stop)
        self.platform = FakePlatform()
        self.ctx = r.Context.validate(environment(), CODE)

    def attempt(self, fake=None):
        fake = fake or FakeTelegram(self.platform)
        github = r.GitHub(self.platform, "synthetic-github-token-value")
        telegram = r.Telegram(fake, r.Destination.private_values(environment()))
        r.connection_test(github, self.ctx, telegram)
        return fake

    def test_success_exact_text_and_claim_precedes_every_telegram_request(self):
        fake = self.attempt()
        self.assertEqual(fake.methods, ["getMe", "getChat", "getChatMember", "sendMessage"])
        self.assertEqual(fake.bodies[-1], {"chat_id": SYNTHETIC_CHAT, "text": r.MESSAGE,
                                        "link_preview_options": {"is_disabled": True}, "allow_paid_broadcast": False})
        self.assertEqual(self.platform.claims, 1)

    def test_restart_after_confirmed_send_and_unrelated_branch_restoration(self):
        first = self.attempt()
        self.platform.change_ref("heads/delivery-history", OTHER)
        self.platform.change_ref("heads/delivery-history", CODE)
        second = FakeTelegram(self.platform)
        with self.assertRaises(r.Blocked):
            self.attempt(second)
        self.assertEqual(first.methods.count("sendMessage"), 1)
        self.assertEqual(second.methods, [])

    def test_unknown_send_outcome_remains_consumed(self):
        first = FakeTelegram(self.platform, fail="sendMessage")
        with self.assertRaises(r.Blocked):
            self.attempt(first)
        second = FakeTelegram(self.platform)
        with self.assertRaises(r.Blocked):
            self.attempt(second)
        self.assertEqual(first.methods.count("sendMessage"), 1)
        self.assertEqual(second.methods, [])

    def test_malformed_success_receipt_never_triggers_resend(self):
        fake = FakeTelegram(self.platform)
        original = fake.request
        def bad_receipt(host, method, path, headers, body=None):
            status, value = original(host, method, path, headers, body)
            if path.endswith("/sendMessage"):
                value["result"]["text"] = "unexpected text"
            return status, value
        with mock.patch.object(fake, "request", side_effect=bad_receipt), self.assertRaises(r.Blocked):
            self.attempt(fake)
        second = FakeTelegram(self.platform)
        with self.assertRaises(r.Blocked):
            self.attempt(second)
        self.assertEqual(fake.methods.count("sendMessage"), 1)
        self.assertEqual(second.methods, [])

    def test_interrupted_attempts_never_rearm(self):
        for method in ("getMe", "getChat", "getChatMember"):
            with self.subTest(method=method):
                self.platform = FakePlatform()
                with self.assertRaises(r.Blocked):
                    self.attempt(FakeTelegram(self.platform, fail=method))
                self.platform.change_ref("heads/history", CODE)
                second = FakeTelegram(self.platform)
                with self.assertRaises(r.Blocked):
                    self.attempt(second)
                self.assertEqual(second.methods, [])

    def test_crash_immediately_after_durable_claim(self):
        github = r.GitHub(self.platform, "synthetic-github-token-value")
        github.audit(self.ctx)
        github.consume(self.ctx)
        fake = FakeTelegram(self.platform)
        with self.assertRaises(r.Blocked):
            self.attempt(fake)
        self.assertEqual(fake.methods, [])

    def test_uncertain_claim_write_is_not_retried(self):
        self.platform.uncertain_claim = True
        fake = FakeTelegram(self.platform)
        with self.assertRaises(r.Blocked):
            self.attempt(fake)
        with self.assertRaises(r.Blocked):
            self.attempt(fake)
        self.assertEqual(self.platform.claims, 1)
        self.assertEqual(fake.methods, [])

    def test_separate_runners_concurrent_claim_only_one_telegram_attempt(self):
        self.platform.claim_barrier = threading.Barrier(2)
        transports = [FakeTelegram(self.platform), FakeTelegram(self.platform)]
        results = []
        def run(fake):
            try:
                self.attempt(fake)
                results.append("sent")
            except r.Blocked:
                results.append("blocked")
        threads = [threading.Thread(target=run, args=(fake,)) for fake in transports]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=7)
            self.assertFalse(thread.is_alive())
        self.assertEqual(sorted(results), ["blocked", "sent"])
        self.assertEqual(sum(fake.methods.count("sendMessage") for fake in transports), 1)
        self.assertEqual(self.platform.claims, 1)

    def test_missing_or_conflicting_arm_blocks(self):
        for value in (None, OTHER):
            with self.subTest(value=value):
                self.platform = FakePlatform()
                if value is None:
                    self.platform.refs.pop(f"tags/{r.ARMED}")
                else:
                    self.platform.refs[f"tags/{r.ARMED}"] = value
                fake = FakeTelegram(self.platform)
                with self.assertRaises(r.Blocked):
                    self.attempt(fake)
                self.assertEqual(fake.methods, [])

    def test_any_existing_consumption_blocks_even_conflicting_commit(self):
        for value in (CODE, OTHER):
            self.platform = FakePlatform()
            self.platform.refs[f"tags/{r.CONSUMED}"] = value
            fake = FakeTelegram(self.platform)
            with self.assertRaises(r.Blocked):
                self.attempt(fake)
            self.assertEqual(fake.methods, [])

    def test_unavailable_or_corrupt_consumption_evidence_blocks(self):
        original = self.platform.request
        for failure in ("unavailable", "corrupt", "wrong-ref", "annotated"):
            self.platform = FakePlatform()
            original = self.platform.request
            def request(host, method, path, headers, body=None):
                if path.endswith(f"/git/ref/tags/{r.CONSUMED}"):
                    if failure == "unavailable":
                        raise r.Blocked()
                    if failure == "corrupt":
                        return 404, {"unexpected": True}
                    value = reference(f"tags/{r.CONSUMED}", CODE)
                    if failure == "wrong-ref":
                        value["ref"] = "refs/tags/other"
                    else:
                        value["object"]["type"] = "tag"
                    return 200, value
                return original(host, method, path, headers, body)
            fake = FakeTelegram(self.platform)
            with self.subTest(failure=failure), mock.patch.object(self.platform, "request", side_effect=request), self.assertRaises(r.Blocked):
                self.attempt(fake)
            self.assertEqual(fake.methods, [])

    def test_private_repo_or_recreated_repository_id_blocks(self):
        for update in ({"private": True, "visibility": "private"}, {"id": PUBLIC_REPO_ID + 1}, {"default_branch": "other"}):
            self.platform = FakePlatform()
            self.platform.repo.update(update)
            with self.assertRaises(r.Blocked):
                self.attempt()

    def test_platform_rejects_update_delete_and_main_restore(self):
        self.attempt()
        for name in ("heads/main", f"tags/{r.ARMED}", f"tags/{r.CONSUMED}"):
            for value in (None, OTHER, CODE):
                with self.subTest(name=name, value=value), self.assertRaises(r.Blocked):
                    self.platform.change_ref(name, value)

    def test_disabled_rules_or_bypass_actor_blocks(self):
        for index in (0, 1):
            for change in ({"enforcement": "disabled"}, {"bypass_actors": [{"actor_type": "RepositoryRole", "actor_id": 5}]}):
                self.platform = FakePlatform()
                self.platform.rules[index].update(change)
                with self.assertRaises(r.Blocked):
                    self.attempt()

    def test_missing_or_extra_required_rule_blocks(self):
        self.platform.rules[1]["rules"].pop()
        with self.assertRaises(r.Blocked):
            self.attempt()
        self.platform = FakePlatform()
        self.platform.rules[1]["rules"].append({"type": "creation"})
        with self.assertRaises(r.Blocked):
            self.attempt()

    def test_hidden_bypass_list_is_distinct_from_verified_empty_list(self):
        # Read-only API cannot attest this property. Owner UI/full privileged
        # metadata verification is mandatory before environment job approval.
        for policy in self.platform.rules:
            policy.pop("bypass_actors")
        r.GitHub(self.platform, "synthetic-github-token-value").audit(self.ctx)
        self.assertNotIn("bypass_actors", self.platform.rules[0])
        self.assertEqual(self.platform.claims, 0)

    def test_missing_or_enabled_admin_bypass_blocks(self):
        for value in (None, True):
            self.platform = FakePlatform()
            if value is None:
                self.platform.env.pop("can_admins_bypass")
            else:
                self.platform.env["can_admins_bypass"] = value
            with self.assertRaises(r.Blocked):
                self.attempt()

    def test_environment_missing_reviewer_or_extra_reviewer_blocks(self):
        for reviewers in ([], [{"type": "User", "reviewer": {"id": 9, "login": "someone"}}],
                          self.platform.env["protection_rules"][0]["reviewers"] * 2):
            self.platform = FakePlatform()
            self.platform.env["protection_rules"][0]["reviewers"] = reviewers
            with self.assertRaises(r.Blocked):
                self.attempt()

    def test_wildcard_tag_or_extra_branch_policy_blocks(self):
        for policies in ([{"name": "*", "type": "branch"}], [{"name": "main", "type": "tag"}],
                         [{"name": "main", "type": "branch"}, {"name": "feature", "type": "branch"}]):
            self.platform = FakePlatform()
            self.platform.branches = {"total_count": len(policies), "branch_policies": policies}
            with self.assertRaises(r.Blocked):
                self.attempt()

    def test_platform_review_withholds_secrets_for_unreviewed_code(self):
        self.assertFalse(self.platform.platform_release("refs/heads/main", CODE))
        self.assertFalse(self.platform.platform_release("refs/heads/main", CODE, "someone"))
        self.assertFalse(self.platform.platform_release("refs/heads/feature", OTHER, r.OWNER))
        self.assertFalse(self.platform.platform_release("refs/heads/main", OTHER, r.OWNER))
        self.assertFalse(self.platform.platform_release("refs/tags/main", CODE, r.OWNER))
        self.assertTrue(self.platform.platform_release("refs/heads/main", CODE, r.OWNER))

    def test_runtime_context_mutations_block_before_network(self):
        changes = {
            "GITHUB_EVENT_NAME": "pull_request_target", "GITHUB_REF": "refs/heads/feature",
            "GITHUB_RUN_ATTEMPT": "2", "GITHUB_REPOSITORY": "other/repo",
            "GITHUB_WORKFLOW_SHA": OTHER, "APPROVED_COMMIT_SHA": OTHER, "REVIEWED_SHA": OTHER,
            "GITHUB_WORKFLOW_REF": r.WORKFLOW.replace("connection-test", "unreviewed"),
            "APPROVED_REPOSITORY_ID": "1", "RUNNER_ENVIRONMENT": "self-hosted",
            "CONTROL_REVIEW_COMPLETE": "false", "RUNNER_DEBUG": "1", "SSLKEYLOGFILE": "keylog",
        }
        for key, value in changes.items():
            env = environment()
            env[key] = value
            with self.subTest(key=key), self.assertRaises(r.Blocked):
                r.Context.validate(env, CODE)

    def test_destination_confirmation_digest_and_token_validation(self):
        for key, value in (("DESTINATION_PRIVATELY_CONFIRMED", "false"), ("TELEGRAM_CHAT_ID", "@public"),
                           ("TELEGRAM_CHAT_ID", "42"), ("TELEGRAM_CHAT_SHA256", "f" * 64),
                           ("TELEGRAM_BOT_TOKEN", SYNTHETIC_TOKEN + "\n")):
            env = environment()
            env[key] = value
            with self.subTest(key=key), self.assertRaises(r.Blocked):
                r.Destination.private_values(env)

    def test_digest_helper_requires_private_terminal_and_hidden_input(self):
        with mock.patch.object(digest_helper.sys.stdin, "isatty", return_value=False), \
             mock.patch.object(digest_helper.getpass, "getpass", side_effect=AssertionError("must not read")), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(digest_helper.main(), 1)
        self.assertEqual(output.getvalue().strip(), "PRIVATE_TERMINAL_REQUIRED")
        with mock.patch.object(digest_helper.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(digest_helper.sys.stderr, "isatty", return_value=True), \
             mock.patch.object(digest_helper.getpass, "getpass", return_value=str(SYNTHETIC_CHAT)), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(digest_helper.main(), 0)
        self.assertEqual(output.getvalue().strip(), hashlib.sha256(str(SYNTHETIC_CHAT).encode()).hexdigest())
        self.assertNotIn(str(SYNTHETIC_CHAT), output.getvalue())

    def test_public_group_or_forum_or_linked_channel_blocks(self):
        for key, value in (("id", -42), ("type", "channel"), ("username", "public"),
                           ("active_usernames", ["public"]), ("linked_chat_id", -42), ("is_forum", True)):
            self.platform = FakePlatform()
            fake = FakeTelegram(self.platform)
            fake.chat[key] = value
            with self.subTest(key=key), self.assertRaises(r.Blocked):
                self.attempt(fake)
            self.assertNotIn("sendMessage", fake.methods)

    def test_banned_or_restricted_bot_blocks(self):
        for status in ("left", "kicked", "restricted"):
            self.platform = FakePlatform()
            fake = FakeTelegram(self.platform)
            fake.member["status"] = status
            with self.assertRaises(r.Blocked):
                self.attempt(fake)
            self.assertNotIn("sendMessage", fake.methods)

    def test_json_corruption_or_duplicate_fields_blocks(self):
        for raw in (b"not-json", b'{"ok":true,"ok":false}', b'{"x":NaN}', b"\xff"):
            with self.subTest(raw=raw), self.assertRaises(r.Blocked):
                r.decode_json(raw)

    def test_default_or_unknown_cli_is_offline_without_reading_secrets(self):
        with mock.patch.object(r, "HTTPS", side_effect=AssertionError("network")):
            for args in ([], ["--news"], ["--message", "arbitrary"]):
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    r.main(args, {})
                self.assertEqual(output.getvalue().strip(), "OFFLINE_ONLY")

    def test_release_disabled_does_not_read_private_values_or_send(self):
        env = environment()
        env["RELEASE_ONE_TEST"] = "false"
        process = mock.Mock(stdout=CODE + "\n")
        with mock.patch.object(r.subprocess, "run", return_value=process), \
             mock.patch.object(r, "HTTPS", return_value=mock.Mock()), \
             mock.patch.object(r.Destination, "private_values", side_effect=AssertionError("secret read")), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(r.main(["--one-test"], env), 1)
        self.assertEqual(output.getvalue().strip(), "BLOCKED_OR_UNCERTAIN_DO_NOT_RETRY")

    def test_exception_does_not_disclose_token_group_or_url(self):
        process = mock.Mock(stdout=CODE + "\n")
        with mock.patch.object(r.subprocess, "run", return_value=process), \
             mock.patch.object(r, "HTTPS", side_effect=RuntimeError(SYNTHETIC_TOKEN + str(SYNTHETIC_CHAT))), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(r.main(["--one-test"], environment()), 1)
        self.assertNotIn(SYNTHETIC_TOKEN, output.getvalue())
        self.assertNotIn(str(SYNTHETIC_CHAT), output.getvalue())
        self.assertNotIn(SYNTHETIC_TOKEN, repr(r.Destination.private_values(environment())))

    def test_git_client_cannot_mutate_other_state_or_pass_force(self):
        github = r.GitHub(self.platform, "synthetic-github-token-value")
        for method, path, body in (("DELETE", f"/git/refs/tags/{r.CONSUMED}", None),
                                   ("PATCH", "/git/refs/heads/main", {"sha": OTHER, "force": True}),
                                   ("POST", "/git/refs", {"ref": "refs/tags/another", "sha": CODE}),
                                   ("POST", "/git/refs", {"ref": f"refs/tags/{r.CONSUMED}", "sha": CODE, "force": True})):
            with self.assertRaises(r.Blocked):
                github.call(method, path, body)

    def test_github_credentials_are_opaque_and_accept_current_lengths(self):
        for length in (1, 40, 256, 520, 1040, r.MAX_GITHUB_TOKEN_BYTES):
            token = ("synthetic_opaque.header-payload.signature" + "X" * length)[:length]
            with self.subTest(length=length), mock.patch.object(self.platform, "request", wraps=self.platform.request) as request:
                client = r.GitHub(self.platform, token)
                client.get("")
                header = request.call_args.args[3]["Authorization"]
                self.assertTrue(header == "Bearer " + token, "Opaque credential was altered")
                self.assertTrue(token not in repr(client), "Credential leaked through repr")

    def test_v2_binding_cannot_use_v1_repository_workflow_or_arm(self):
        for key, value in (("GITHUB_REPOSITORY", r.V1_REPOSITORY),
                           ("GITHUB_WORKFLOW_REF", r.WORKFLOW.replace(r.REPOSITORY, r.V1_REPOSITORY)),
                           ("APPROVED_COMMIT_SHA", r.V1_COMMIT)):
            env = environment()
            env[key] = value
            with self.subTest(key=key), self.assertRaises(r.Blocked):
                r.Context.validate(env, CODE)
        self.platform.refs[f"tags/{r.ARMED}"] = r.V1_COMMIT
        with self.assertRaises(r.Blocked):
            self.attempt()
        self.assertEqual(self.platform.claims, 0)

    def test_missing_or_conflicting_v1_retirement_blocks_without_consuming_v2(self):
        for name in (r.V1_ARMED, r.V1_CONSUMED):
            for value in (None, CODE, OTHER):
                self.platform = FakePlatform()
                if value is None:
                    self.platform.old_refs.pop(f"tags/{name}")
                else:
                    self.platform.old_refs[f"tags/{name}"] = value
                fake = FakeTelegram(self.platform)
                with self.subTest(name=name, value=value), self.assertRaises(r.Blocked):
                    self.attempt(fake)
                self.assertEqual(fake.methods, [])
                self.assertEqual(self.platform.claims, 0)

    def test_unavailable_malformed_or_annotated_v1_evidence_blocks(self):
        for alteration in ("unavailable", "corrupt", "annotated", "wrong-ref"):
            self.platform = FakePlatform()
            original = self.platform.request
            def bad(host, method, path, headers, body=None):
                if path == f"/repos/{r.V1_REPOSITORY}/git/ref/tags/{r.V1_CONSUMED}":
                    if alteration == "unavailable":
                        raise r.Blocked()
                    if alteration == "corrupt":
                        return 200, {"missing": True}
                    value = reference(f"tags/{r.V1_CONSUMED}", r.V1_COMMIT)
                    if alteration == "annotated":
                        value["object"]["type"] = "tag"
                    else:
                        value["ref"] = "refs/tags/other"
                    return 200, value
                return original(host, method, path, headers, body)
            fake = FakeTelegram(self.platform)
            with self.subTest(alteration=alteration), mock.patch.object(self.platform, "request", side_effect=bad), self.assertRaises(r.Blocked):
                self.attempt(fake)
            self.assertEqual(fake.methods, [])
            self.assertEqual(self.platform.claims, 0)

    def test_v1_recreated_repository_or_restored_main_blocks(self):
        for mutation in ("identity", "main"):
            self.platform = FakePlatform()
            if mutation == "identity":
                self.platform.old_repo["id"] += 1
            else:
                self.platform.old_refs["heads/main"] = OTHER
            with self.subTest(mutation=mutation), self.assertRaises(r.Blocked):
                self.attempt()
            self.assertEqual(self.platform.claims, 0)

    def test_v1_workflow_must_remain_disabled(self):
        for state in (None, "active", "disabled_inactivity"):
            self.platform = FakePlatform()
            self.platform.old_workflow["state"] = state
            with self.subTest(state=state), self.assertRaises(r.Blocked):
                self.attempt()
            self.assertEqual(self.platform.claims, 0)

    def test_v1_old_run_ids_attempts_and_jobs_are_pinned(self):
        for mutation in ("same-count-new-id", "attempt", "sha", "new-run", "missing-run", "started-test", "missing-jobs"):
            self.platform = FakePlatform()
            history = self.platform.old_runs
            if mutation == "same-count-new-id":
                history["workflow_runs"][0]["id"] += 1
            elif mutation == "attempt":
                history["workflow_runs"][1]["run_attempt"] = 2
            elif mutation == "sha":
                history["workflow_runs"][1]["head_sha"] = OTHER
            elif mutation == "new-run":
                history["workflow_runs"].append(copy.deepcopy(history["workflow_runs"][0]))
                history["total_count"] += 1
            elif mutation == "missing-run":
                history["workflow_runs"].pop()
                history["total_count"] -= 1
            elif mutation == "started-test":
                self.platform.old_jobs["jobs"][1]["steps"] = [{"name": "Set up job"}]
            else:
                self.platform.old_jobs["jobs"].pop()
            with self.subTest(mutation=mutation), self.assertRaises(r.Blocked):
                self.attempt()
            self.assertEqual(self.platform.claims, 0)

    def test_v1_immutable_protections_cannot_be_weakened(self):
        for mutation in ("inactive", "bypass", "wrong-refs", "missing-rule"):
            self.platform = FakePlatform()
            policy = self.platform.old_rules[1]
            if mutation == "inactive":
                policy["enforcement"] = "disabled"
            elif mutation == "bypass":
                policy["bypass_actors"] = [{"actor_id": 5}]
            elif mutation == "wrong-refs":
                policy["conditions"]["ref_name"]["include"] = ["refs/tags/*"]
            else:
                policy["rules"].pop()
            with self.subTest(mutation=mutation), self.assertRaises(r.Blocked):
                self.attempt()

    def test_v1_requests_are_read_only_and_receive_no_v2_token(self):
        self.attempt()
        self.assertTrue(self.platform.legacy_calls)
        self.assertTrue(all(method == "GET" for method, _ in self.platform.legacy_calls))
        client = r.GitHub(self.platform, "synthetic-github-token-value")
        for suffix in ("/git/refs", "/actions/workflows/connection-test.yml/disable", "/git/ref/tags/other"):
            with self.subTest(suffix=suffix), self.assertRaises(r.Blocked):
                client.legacy_get(suffix)

    def test_v1_evidence_is_rechecked_after_v2_consumption_before_telegram(self):
        github = r.GitHub(self.platform, "synthetic-github-token-value")
        original = github.consume
        def consume_then_corrupt(ctx):
            original(ctx)
            self.platform.old_refs.pop(f"tags/{r.V1_CONSUMED}")
        fake = FakeTelegram(self.platform)
        with mock.patch.object(github, "consume", side_effect=consume_then_corrupt), self.assertRaises(r.Blocked):
            r.connection_test(github, self.ctx, r.Telegram(fake, r.Destination.private_values(environment())))
        self.assertEqual(self.platform.claims, 1)
        self.assertEqual(fake.methods, [])

    def test_v1_evidence_loss_after_preflight_blocks_send_and_never_retries(self):
        fake = FakeTelegram(self.platform)
        sender = r.Telegram(fake, r.Destination.private_values(environment()))
        original = sender.preflight
        def preflight_then_corrupt():
            original()
            self.platform.old_refs.pop(f"tags/{r.V1_CONSUMED}")
        github = r.GitHub(self.platform, "synthetic-github-token-value")
        with mock.patch.object(sender, "preflight", side_effect=preflight_then_corrupt), self.assertRaises(r.Blocked):
            r.connection_test(github, self.ctx, sender)
        self.assertNotIn("sendMessage", fake.methods)
        second = FakeTelegram(self.platform)
        with self.assertRaises(r.Blocked):
            self.attempt(second)
        self.assertEqual(second.methods, [])

    def test_concurrent_uncertain_claim_all_runners_block_without_telegram(self):
        self.platform.claim_barrier = threading.Barrier(2)
        self.platform.uncertain_claim = True
        transports = [FakeTelegram(self.platform), FakeTelegram(self.platform)]
        results = []
        def run(fake):
            try:
                self.attempt(fake)
                results.append("unexpected-success")
            except r.Blocked:
                results.append("blocked")
        threads = [threading.Thread(target=run, args=(fake,)) for fake in transports]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=7)
            self.assertFalse(thread.is_alive())
        self.assertEqual(results, ["blocked", "blocked"])
        self.assertEqual(self.platform.claims, 1)
        self.assertTrue(all(not fake.methods for fake in transports))

    def test_github_credential_whitespace_controls_and_wrong_types_block(self):
        malformed = [None, 1, True, b"not-a-string", [], {}, ""]
        for character in (" ", "\t", "\r", "\n", "\v", "\f", "\x00", "\x1f", "\x7f", "\u0085", "\u00a0", "\u2028"):
            malformed.append("synthetic" + character + "opaque")
        for index, token in enumerate(malformed):
            with self.subTest(case=index), self.assertRaises(r.Blocked) as caught:
                r.GitHub(self.platform, token)
            self.assertEqual(str(caught.exception), "")
        self.assertEqual(self.platform.calls, [])

    def test_github_oversized_credentials_block_before_request(self):
        for length in (r.MAX_GITHUB_TOKEN_BYTES + 1, 65536):
            token = "X" * length
            with self.subTest(length=length), self.assertRaises(r.Blocked) as caught:
                r.GitHub(self.platform, token)
            self.assertEqual(str(caught.exception), "")
        self.assertEqual(self.platform.calls, [])

    def test_current_length_github_credential_completes_mocked_audit(self):
        env = environment()
        token = "synthetic_opaque." + "X" * (520 - len("synthetic_opaque."))
        env["GH_TOKEN"] = token
        process = mock.Mock(stdout=CODE + "\n")
        with mock.patch.object(r.subprocess, "run", return_value=process), \
             mock.patch.object(r, "HTTPS", return_value=self.platform), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(r.main(["--audit-controls"], env), 0)
        self.assertEqual(output.getvalue().strip(), "PUBLIC_METADATA_PASS_OWNER_FULL_POLICY_REVIEW_REQUIRED")
        self.assertTrue(token not in output.getvalue(), "Credential leaked into output")
        self.assertTrue(all(method == "GET" for method, _ in self.platform.calls))
        self.assertEqual(self.platform.claims, 0)

    def test_long_github_credential_never_leaks_in_failure_output(self):
        env = environment()
        token = "synthetic_secret_marker." + "X" * (520 - len("synthetic_secret_marker."))
        env["GH_TOKEN"] = token
        process = mock.Mock(stdout=CODE + "\n")
        transport = mock.Mock()
        transport.request.side_effect = RuntimeError(token)
        with mock.patch.object(r.subprocess, "run", return_value=process), \
             mock.patch.object(r, "HTTPS", return_value=transport), \
             contextlib.redirect_stdout(io.StringIO()) as output, \
             contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(r.main(["--audit-controls"], env), 1)
        self.assertEqual(output.getvalue().strip(), "BLOCKED_OR_UNCERTAIN_DO_NOT_RETRY")
        self.assertEqual(errors.getvalue(), "")
        self.assertTrue(token not in output.getvalue() + errors.getvalue(), "Credential leaked into failure output")
        self.assertEqual(transport.request.call_count, 1)

    def test_sender_rejects_arbitrary_text_or_paid_options(self):
        fake = FakeTelegram(self.platform)
        sender = r.Telegram(fake, r.Destination.private_values(environment()))
        for payload in ({"chat_id": SYNTHETIC_CHAT, "text": "arbitrary"},
                        {"chat_id": SYNTHETIC_CHAT, "text": r.MESSAGE,
                         "link_preview_options": {"is_disabled": True}, "allow_paid_broadcast": True}):
            with self.assertRaises(r.Blocked):
                sender.call("sendMessage", payload)
        self.assertEqual(fake.methods, [])

    def test_workflow_permissions_and_immutable_checkout_contract(self):
        # JSON is a YAML subset, allowing exact dependency-free offline inspection.
        workflow = json.loads((ROOT / ".github/workflows/connection-test.yml").read_text())
        self.assertEqual(set(workflow["on"]), {"workflow_dispatch"})
        self.assertEqual(set(workflow["on"]["workflow_dispatch"]["inputs"]), {"reviewed_sha"})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        audit, send = workflow["jobs"]["audit"], workflow["jobs"]["test"]
        self.assertNotIn("environment", audit)
        self.assertNotIn("secrets.", json.dumps(audit))
        self.assertEqual(send["needs"], "audit")
        self.assertEqual(send["environment"]["name"], r.ENVIRONMENT)
        self.assertEqual(audit["permissions"], {"contents": "read", "actions": "read"})
        self.assertEqual(send["permissions"], {"contents": "write", "actions": "read"})
        for job in (audit, send):
            self.assertEqual(job["runs-on"], "ubuntu-24.04")
            self.assertEqual(job["timeout-minutes"], 3)
            self.assertIn("github.workflow_sha == github.sha", job["if"])
            self.assertIn("github.ref == 'refs/heads/main'", job["if"])
            self.assertIn("github.run_attempt == 1", job["if"])
            self.assertEqual(job["steps"][0], {"uses": r.CHECKOUT, "with": {"ref": "${{ github.sha }}", "persist-credentials": False}})
        self.assertEqual(send["steps"][1]["run"], "python3 -I runner.py --one-test")
        self.assertEqual(sum("secrets." in json.dumps(step) for step in send["steps"]), 1)
        offline = json.loads((ROOT / ".github/workflows/offline-tests.yml").read_text())
        self.assertEqual(offline["on"], {"push": {"branches": ["main"]}})
        self.assertNotIn("secrets.", json.dumps(offline))
        self.assertNotIn("environment", json.dumps(offline))
        combined = json.dumps([workflow, offline])
        for forbidden in ("schedule", "workflow_call", "pull_request_target", "upload-artifact", "actions/cache", "id-token"):
            self.assertNotIn(forbidden, combined)

    def test_tls_strict_defaults_and_fixed_host_only(self):
        transport = r.HTTPS()
        self.assertTrue(transport.context.check_hostname)
        self.assertEqual(transport.context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(transport.context.minimum_version, ssl.TLSVersion.TLSv1_2)
        with self.assertRaises(r.Blocked):
            transport.request("other.example", "GET", "/", {})

    def test_transport_no_redirect_size_limits_and_redacted_failures(self):
        cases = [
            (302, {"Content-Type": "application/json"}, b"{}"),
            (200, {"Content-Type": "application/json", "Content-Length": str(r.MAX_RESPONSE + 1)}, b"{}"),
            (200, {"Content-Type": "application/json"}, b"x" * (r.MAX_RESPONSE + 1)),
            (200, {"Content-Type": "application/json", "Content-Encoding": "gzip"}, b"{}"),
            (200, {"Content-Type": "text/html"}, b"{}"),
        ]
        for status, headers, body in cases:
            response = mock.Mock(status=status)
            response.getheader.side_effect = lambda key, default=None: headers.get(key, default)
            response.read.return_value = body
            connection = mock.Mock()
            connection.getresponse.return_value = response
            with mock.patch.object(r.http.client, "HTTPSConnection", return_value=connection) as factory:
                with self.assertRaises(r.Blocked):
                    r.HTTPS().request("api.github.com", "GET", "/", {})
                self.assertEqual(factory.call_count, 1)
                self.assertEqual(connection.request.call_count, 1)
                connection.close.assert_called_once()

    def test_transport_success_and_timeout_has_no_retry(self):
        response = mock.Mock(status=200)
        response.getheader.side_effect = lambda key, default=None: {"Content-Type": "application/json"}.get(key, default)
        response.read.return_value = b'{"ok":true}'
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch.object(r.http.client, "HTTPSConnection", return_value=connection) as factory:
            self.assertEqual(r.HTTPS().request("api.github.com", "GET", "/", {}), (200, {"ok": True}))
            self.assertLessEqual(factory.call_args.kwargs["timeout"], r.TIMEOUT)
            response.read.assert_called_once_with(r.MAX_RESPONSE + 1)
        connection = mock.Mock()
        connection.request.side_effect = TimeoutError(SYNTHETIC_TOKEN)
        with mock.patch.object(r.http.client, "HTTPSConnection", return_value=connection) as factory:
            with self.assertRaises(r.Blocked) as caught:
                r.HTTPS().request("api.github.com", "GET", "/", {})
            self.assertEqual(str(caught.exception), "")
            self.assertEqual(factory.call_count, 1)
            self.assertEqual(connection.request.call_count, 1)
            connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)

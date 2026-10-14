"""Fresh, standalone, one-use connection test. No news or project imports."""
from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import hmac
import http.client
import json
import os
import re
import signal
import ssl
import subprocess
import sys
import time
from collections.abc import Mapping

REPOSITORY = "aliakrammarufi/gsl-connection-test-runner-v2"
V1_REPOSITORY = "aliakrammarufi/gsl-connection-test-runner"
V1_REPOSITORY_ID = 1418486617
V1_COMMIT = "ced5e2983aad6093261fa862f1d3757f74f8dc5b"
V1_ARMED = "activation-armed-v1"
V1_CONSUMED = "activation-consumed-v1"
V1_RUNS = {
    38523683737: ("push", ".github/workflows/offline-tests.yml", "success"),
    38535703298: ("workflow_dispatch", ".github/workflows/connection-test.yml", "failure"),
}
V1_TEST_RUN = 38535703298
OWNER = "aliakrammarufi"
OWNER_ID = 107786534  # Public GitHub identity; not a Telegram identity.
ENVIRONMENT = "connection-test"
WORKFLOW = f"{REPOSITORY}/.github/workflows/connection-test.yml@refs/heads/main"
ARMED = "activation-armed-v2"
CONSUMED = "activation-consumed-v2"
MESSAGE = (
    "Gold Signal Lab — cloud connection test.\n"
    "News delivery is not active yet. This is not a trading signal."
)
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
MAX_RESPONSE = 131072
MAX_GITHUB_TOKEN_BYTES = 4096  # Resource bound; the bearer value remains opaque.
TIMEOUT = 8
DEADLINE = 120
SHA = re.compile(r"[0-9a-f]{40}\Z")


class Blocked(Exception):
    """Never carries server content, URLs, credentials or destination details."""


def require(condition: bool) -> None:
    if not condition:
        raise Blocked()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def decode_json(raw: bytes):
    try:
        return json.loads(
            raw.decode("utf-8"), object_pairs_hook=unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(Blocked()),
        )
    except Exception:
        raise Blocked() from None


class HTTPS:
    """Direct TLS, no proxies, redirects or retries; response and total bounds."""

    def __init__(self):
        self.context = ssl.create_default_context()
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ends = time.monotonic() + DEADLINE

    def request(self, host, method, path, headers, body=None):
        require(host in {"api.github.com", "api.telegram.org"})
        require(method in {"GET", "POST"} and path.startswith("/") and "\n" not in path)
        require(time.monotonic() < self.ends)
        require(body is None or len(body) <= 4096)
        connection = None
        try:
            connection = http.client.HTTPSConnection(
                host, 443, timeout=min(TIMEOUT, self.ends - time.monotonic()),
                context=self.context,
            )
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            require(response.status not in range(300, 400))
            require(response.getheader("Content-Encoding", "identity") == "identity")
            require(response.getheader("Content-Type", "").split(";")[0] == "application/json")
            length = response.getheader("Content-Length")
            if length is not None:
                require(length.isdecimal() and int(length) <= MAX_RESPONSE)
            raw = response.read(MAX_RESPONSE + 1)
            require(len(raw) <= MAX_RESPONSE and time.monotonic() < self.ends)
            return response.status, decode_json(raw)
        except Exception:
            raise Blocked() from None
        finally:
            if connection is not None:
                connection.close()


@dataclasses.dataclass(frozen=True)
class Context:
    commit: str
    repository_id: int

    @classmethod
    def validate(cls, env: Mapping[str, str], checkout_head: str):
        commit = env.get("GITHUB_SHA", "")
        require(bool(SHA.fullmatch(commit)))
        require(env.get("APPROVED_COMMIT_SHA") == commit == checkout_head)
        require(env.get("GITHUB_WORKFLOW_SHA") == commit)
        require(env.get("REVIEWED_SHA") == commit)
        require(env.get("GITHUB_WORKFLOW_REF") == WORKFLOW)
        require(env.get("GITHUB_REPOSITORY") == REPOSITORY)
        require(env.get("GITHUB_REPOSITORY_OWNER_ID") == str(OWNER_ID))
        require(env.get("GITHUB_REF") == "refs/heads/main")
        require(env.get("GITHUB_EVENT_NAME") == "workflow_dispatch")
        require(env.get("GITHUB_RUN_ATTEMPT") == "1")
        require(env.get("GITHUB_ACTIONS") == "true")
        require(env.get("RUNNER_ENVIRONMENT") == "github-hosted" and env.get("RUNNER_OS") == "Linux")
        require(env.get("CONTROL_REVIEW_COMPLETE") == "true")
        require(env.get("GITHUB_SERVER_URL") == "https://github.com")
        require(env.get("GITHUB_API_URL") == "https://api.github.com")
        require(not any(env.get(key) for key in (
            "ACTIONS_RUNNER_DEBUG", "ACTIONS_STEP_DEBUG", "RUNNER_DEBUG",
            "SSLKEYLOGFILE", "PYTHONINSPECT", "PYTHONSTARTUP",
        )))
        identity = env.get("APPROVED_REPOSITORY_ID", "")
        require(identity.isdecimal() and int(identity) > 0)
        require(env.get("GITHUB_REPOSITORY_ID") == identity)
        return cls(commit, int(identity))


class GitHub:
    def __init__(self, transport, token):
        require(isinstance(token, str) and 0 < len(token) <= MAX_GITHUB_TOKEN_BYTES)
        # Printable non-whitespace ASCII only: characters equal bytes, and no
        # header controls can enter the request. Do not parse prefixes or JWTs.
        require(all(33 <= ord(character) <= 126 for character in token))
        self.transport = transport
        self._token = token

    def call(self, method, suffix, payload=None):
        allowed = suffix in {
            "", "/rulesets?per_page=100", f"/environments/{ENVIRONMENT}",
            f"/environments/{ENVIRONMENT}/deployment-branch-policies?per_page=100",
            "/git/ref/heads/main", f"/git/ref/tags/{ARMED}", f"/git/ref/tags/{CONSUMED}",
        } or bool(re.fullmatch(r"/rulesets/[1-9][0-9]*", suffix))
        if method == "POST":
            require(suffix == "/git/refs" and isinstance(payload, dict))
            require(set(payload) == {"ref", "sha"})
            require(payload["ref"] == f"refs/tags/{CONSUMED}" and bool(SHA.fullmatch(payload["sha"])))
        else:
            require(method == "GET" and allowed and payload is None)
        body = None if payload is None else json.dumps(payload).encode()
        return self.transport.request("api.github.com", method, f"/repos/{REPOSITORY}{suffix}", {
            "Authorization": f"Bearer {self._token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "standalone-one-use-test",
            "Content-Type": "application/json", "Accept-Encoding": "identity",
        }, body)

    def get(self, suffix):
        status, value = self.call("GET", suffix)
        require(status == 200)
        return value

    def ref(self, name, *, absent_allowed=False):
        status, value = self.call("GET", f"/git/ref/{name}")
        if status == 404 and absent_allowed:
            # Only GitHub's explicit absence is accepted, never network/JSON failures.
            require(isinstance(value, dict) and value.get("message") == "Not Found")
            return None
        require(status == 200 and isinstance(value, dict))
        require(value.get("ref") == f"refs/{name}")
        obj = value.get("object", {})
        require(obj.get("type") == "commit" and bool(SHA.fullmatch(obj.get("sha", ""))))
        return obj["sha"]

    def legacy_get(self, suffix):
        # Public, read-only cross-repository evidence. Never release the v2
        # GITHUB_TOKEN to v1, and never allow a write to historical fences.
        allowed = suffix in {
            "", "/git/ref/heads/main", f"/git/ref/tags/{V1_ARMED}",
            f"/git/ref/tags/{V1_CONSUMED}", "/rulesets?per_page=100",
            "/actions/workflows/connection-test.yml", "/actions/runs?per_page=100",
            f"/actions/runs/{V1_TEST_RUN}/attempts/1/jobs?per_page=100",
        } or bool(re.fullmatch(r"/rulesets/[1-9][0-9]*", suffix))
        require(allowed)
        status, value = self.transport.request(
            "api.github.com", "GET", f"/repos/{V1_REPOSITORY}{suffix}", {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "standalone-one-use-test-v2",
                "Accept-Encoding": "identity",
            },
        )
        require(status == 200)
        return value

    def legacy_ref(self, name):
        value = self.legacy_get(f"/git/ref/{name}")
        require(isinstance(value, dict) and value.get("ref") == f"refs/{name}")
        obj = value.get("object", {})
        require(isinstance(obj, dict) and obj.get("type") == "commit")
        require(obj.get("sha") == V1_COMMIT)

    def require_v1_fences(self):
        # Missing, annotated, restored-to-another-SHA or unavailable evidence
        # blocks. There is no absent-allowed path for either historical ref.
        self.legacy_ref(f"tags/{V1_ARMED}")
        self.legacy_ref(f"tags/{V1_CONSUMED}")

    def audit_v1_retirement(self):
        repo = self.legacy_get("")
        require(repo.get("id") == V1_REPOSITORY_ID and repo.get("full_name") == V1_REPOSITORY)
        require(repo.get("owner", {}).get("id") == OWNER_ID)
        require(repo.get("private") is False and repo.get("visibility") == "public")
        require(repo.get("default_branch") == "main" and repo.get("archived") is False)
        self.legacy_ref("heads/main")
        self.require_v1_fences()
        summaries = self.legacy_get("/rulesets?per_page=100")
        require(isinstance(summaries, list) and len(summaries) < 100)
        required = {
            "one-test-frozen-main": ("branch", ["refs/heads/main"], {"creation", "update", "deletion"}),
            "one-test-immutable-fence": ("tag", [f"refs/tags/{V1_ARMED}", f"refs/tags/{V1_CONSUMED}"], {"update", "deletion"}),
        }
        for name, (target, refs, rules) in required.items():
            matches = [policy for policy in summaries if policy.get("name") == name]
            require(len(matches) == 1 and type(matches[0].get("id")) is int)
            policy = self.legacy_get(f"/rulesets/{matches[0]['id']}")
            require(policy.get("name") == name and policy.get("target") == target)
            require(policy.get("enforcement") == "active")
            require(policy.get("conditions") == {"ref_name": {"include": refs, "exclude": []}})
            require(sorted(policy.get("rules", []), key=lambda rule: rule.get("type", "")) ==
                    [{"type": kind} for kind in sorted(rules)])
            if "bypass_actors" in policy:
                require(policy["bypass_actors"] == [])
        workflow = self.legacy_get("/actions/workflows/connection-test.yml")
        require(workflow.get("path") == ".github/workflows/connection-test.yml")
        require(workflow.get("state") == "disabled_manually")
        self.audit_v1_history()

    def audit_v1_history(self):
        history = self.legacy_get("/actions/runs?per_page=100")
        runs = history.get("workflow_runs", [])
        require(history.get("total_count") == len(V1_RUNS) and len(runs) == len(V1_RUNS))
        require({run.get("id") for run in runs} == set(V1_RUNS))
        for run in runs:
            event, path, conclusion = V1_RUNS[run["id"]]
            require(run.get("head_sha") == V1_COMMIT and run.get("head_branch") == "main")
            require(run.get("run_attempt") == 1 and run.get("status") == "completed")
            require(run.get("event") == event and run.get("path") == path)
            require(run.get("conclusion") == conclusion)
        jobs = self.legacy_get(f"/actions/runs/{V1_TEST_RUN}/attempts/1/jobs?per_page=100")
        entries = jobs.get("jobs", [])
        require(jobs.get("total_count") == 2 and len(entries) == 2)
        require({job.get("name") for job in entries} == {"audit", "test"})
        for job in entries:
            require(job.get("run_id") == V1_TEST_RUN)
            # The endpoint is explicitly attempt 1. The job schema does not
            # promise a run_attempt field; if supplied, it must agree.
            if "run_attempt" in job:
                require(job["run_attempt"] == 1)
            require(job.get("head_sha") == V1_COMMIT and job.get("status") == "completed")
            if job["name"] == "test":
                require(job.get("conclusion") == "skipped" and job.get("steps") == [])
            else:
                require(job.get("conclusion") == "failure")

    def audit(self, ctx):
        repo = self.get("")
        require(repo.get("id") == ctx.repository_id and repo.get("full_name") == REPOSITORY)
        require(repo.get("private") is False and repo.get("visibility") == "public")
        require(repo.get("default_branch") == "main" and repo.get("archived") is False)
        require(repo.get("owner", {}).get("id") == OWNER_ID)
        summaries = self.get("/rulesets?per_page=100")
        require(isinstance(summaries, list) and len(summaries) < 100)
        required = {
            "one-test-frozen-main": ("branch", ["refs/heads/main"], {"creation", "update", "deletion"}),
            "one-test-immutable-fence": ("tag", [f"refs/tags/{ARMED}", f"refs/tags/{CONSUMED}"], {"update", "deletion"}),
        }
        for name, (target, refs, rules) in required.items():
            matches = [r for r in summaries if r.get("name") == name]
            require(len(matches) == 1 and type(matches[0].get("id")) is int)
            policy = self.get(f"/rulesets/{matches[0]['id']}")
            require(policy.get("name") == name and policy.get("target") == target)
            require(policy.get("enforcement") == "active")
            # GitHub may hide this field from non-administrative tokens. Absence
            # is NOT proof of no bypass. The owner must inspect full live rules
            # before secret entry and again before platform job approval.
            if "bypass_actors" in policy:
                require(policy["bypass_actors"] == [])
            require(policy.get("conditions") == {"ref_name": {"include": refs, "exclude": []}})
            require(policy.get("rules") == [{"type": t} for t in sorted(rules)] or
                    sorted(policy.get("rules", []), key=lambda r: r.get("type", "")) == [{"type": t} for t in sorted(rules)])
        environment = self.get(f"/environments/{ENVIRONMENT}")
        require(environment.get("name") == ENVIRONMENT)
        require(environment.get("can_admins_bypass") is False)
        require(environment.get("deployment_branch_policy") == {
            "protected_branches": False, "custom_branch_policies": True,
        })
        review = [r for r in environment.get("protection_rules", []) if r.get("type") == "required_reviewers"]
        require(len(review) == 1 and review[0].get("prevent_self_review") is False)
        reviewers = review[0].get("reviewers", [])
        require(len(reviewers) == 1 and reviewers[0].get("type") == "User")
        require(reviewers[0].get("reviewer", {}).get("id") == OWNER_ID)
        require(reviewers[0].get("reviewer", {}).get("login") == OWNER)
        branches = self.get(f"/environments/{ENVIRONMENT}/deployment-branch-policies?per_page=100")
        require(branches.get("total_count") == 1)
        entries = branches.get("branch_policies", [])
        require(len(entries) == 1 and entries[0].get("name") == "main" and entries[0].get("type") == "branch")
        self.audit_v1_retirement()
        require(self.ref("heads/main") == ctx.commit)
        require(self.ref(f"tags/{ARMED}") == ctx.commit)
        require(self.ref(f"tags/{CONSUMED}", absent_allowed=True) is None)

    def consume(self, ctx):
        # Atomic create-only name; concurrent requests cannot both return success.
        # Any uncertain write aborts. Never delete, update, retry or replace this ref.
        status, _ = self.call("POST", "/git/refs", {
            "ref": f"refs/tags/{CONSUMED}", "sha": ctx.commit,
        })
        require(status == 201)
        require(self.ref(f"tags/{CONSUMED}") == ctx.commit)


@dataclasses.dataclass(frozen=True, repr=False)
class Destination:
    token: str
    chat: int
    bot: int

    @classmethod
    def private_values(cls, env):
        require(env.get("DESTINATION_PRIVATELY_CONFIRMED") == "true")
        raw = env.get("TELEGRAM_CHAT_ID", "")
        require(bool(re.fullmatch(r"-[1-9][0-9]{0,15}", raw)))
        chat = int(raw)
        require(-(2**52) < chat < 0)
        digest = env.get("TELEGRAM_CHAT_SHA256", "")
        require(bool(re.fullmatch(r"[0-9a-f]{64}", digest)))
        require(hmac.compare_digest(hashlib.sha256(raw.encode()).hexdigest(), digest))
        token = env.get("TELEGRAM_BOT_TOKEN", "")
        require(bool(re.fullmatch(r"[1-9][0-9]{4,15}:[A-Za-z0-9_-]{35}", token)))
        return cls(token, chat, int(token.split(":")[0]))


def private_group(chat, destination):
    require(type(chat.get("id")) is int and chat["id"] == destination.chat)
    require(chat.get("type") in {"group", "supergroup"})
    require(not any(chat.get(field) for field in (
        "username", "active_usernames", "linked_chat_id", "is_forum", "is_direct_messages", "is_paid_media",
    )))


class Telegram:
    def __init__(self, transport, destination):
        self.transport, self.destination = transport, destination

    def call(self, method, payload):
        require(method in {"getMe", "getChat", "getChatMember", "sendMessage"})
        if method == "sendMessage":
            require(payload == {
                "chat_id": self.destination.chat, "text": MESSAGE,
                "link_preview_options": {"is_disabled": True}, "allow_paid_broadcast": False,
            })
        # The token appears only in the TLS request path in memory, never an argument/log.
        status, value = self.transport.request(
            "api.telegram.org", "POST", f"/bot{self.destination.token}/{method}",
            {"Content-Type": "application/json", "Accept-Encoding": "identity"},
            json.dumps(payload, ensure_ascii=False).encode(),
        )
        require(status == 200 and isinstance(value, dict) and value.get("ok") is True)
        require(isinstance(value.get("result"), dict))
        return value["result"]

    def preflight(self):
        identity = self.call("getMe", {})
        require(identity.get("is_bot") is True and identity.get("id") == self.destination.bot)
        chat = self.call("getChat", {"chat_id": self.destination.chat})
        private_group(chat, self.destination)
        membership = self.call("getChatMember", {"chat_id": self.destination.chat, "user_id": self.destination.bot})
        require(membership.get("user", {}).get("id") == self.destination.bot)
        require(membership.get("status") in {"creator", "administrator", "member", "restricted"})
        if membership["status"] == "restricted":
            require(membership.get("is_member") is True and membership.get("can_send_messages") is True)
        if membership["status"] == "member":
            require(chat.get("permissions", {}).get("can_send_messages") is True)

    def send(self):
        result = self.call("sendMessage", {
            "chat_id": self.destination.chat, "text": MESSAGE,
            "link_preview_options": {"is_disabled": True}, "allow_paid_broadcast": False,
        })
        require(type(result.get("message_id")) is int and result["message_id"] > 0)
        require(result.get("text") == MESSAGE)
        private_group(result.get("chat", {}), self.destination)


def connection_test(github, ctx, telegram):
    github.audit(ctx)
    github.consume(ctx)  # Before ALL Telegram I/O, including read-only preflight.
    github.require_v1_fences()
    telegram.preflight()
    require(github.ref(f"tags/{ARMED}") == ctx.commit)
    require(github.ref(f"tags/{CONSUMED}") == ctx.commit)
    github.require_v1_fences()
    telegram.send()  # One call only; no automatic resend for any outcome.


@contextlib.contextmanager
def wall_clock_limit():
    def stop(_signum, _frame):
        raise Blocked()
    previous = signal.signal(signal.SIGALRM, stop)
    signal.alarm(DEADLINE)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def main(args=None, env=None):
    args = sys.argv[1:] if args is None else args
    if args not in (["--audit-controls"], ["--one-test"]):
        print("OFFLINE_ONLY")
        return 0 if not args else 2
    try:
        env = os.environ if env is None else env
        head = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True, timeout=3).stdout.strip()
        ctx = Context.validate(env, head)
        with wall_clock_limit():
            transport = HTTPS()
            github = GitHub(transport, env.get("GH_TOKEN", ""))
            if args == ["--audit-controls"]:
                github.audit(ctx)
                print("PUBLIC_METADATA_PASS_OWNER_FULL_POLICY_REVIEW_REQUIRED")
            else:
                require(env.get("RELEASE_ONE_TEST") == "true")
                destination = Destination.private_values(env)
                connection_test(github, ctx, Telegram(transport, destination))
                print("TEST_RESPONSE_CONFIRMED_NO_RETRY")
        return 0
    except BaseException:
        # Even malformed settings, TLS/network errors and interrupts are redacted.
        print("BLOCKED_OR_UNCERTAIN_DO_NOT_RETRY")
        return 1


if __name__ == "__main__":
    sys.exit(main())

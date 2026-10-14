# One-use connection-test runner v2

Local candidate for `aliakrammarufi/gsl-connection-test-runner-v2`, a fresh
public repository. Nothing has been published or activated. No private
project imports, news ingestion, schedules, trading or broker connections.
Default invocation is `OFFLINE_ONLY`, with no requests or secret access.

The sole compiled message is:

```text
Gold Signal Lab — cloud connection test.
News delivery is not active yet. This is not a trading signal.
```

Requires Python 3.10+ and no external dependencies:

```sh
python3 -I test_runner.py
python3 -I runner.py
```

Tests use synthetic values and mocked transports, with sockets forbidden.
`PUBLIC_FILES.sha256` lists the other eleven public files. Its own digest
is retained outside the bundle. Workflows use JSON, a YAML subset.

## Binding and delivery boundary

The repository name, owner ID, workflow path and `refs/heads/main` are exact
code constants. The run SHA, workflow SHA, checked-out HEAD, independently
reviewed input and owner-held approved SHA must all agree. The repository
ID must agree with the independently retained publication record and pin.
The eventual SHA/ID do not exist until separately authorized publication;
they are never guessed or copied from v1. A commit cannot embed its own SHA
without a circular dependency.

Before credentials, freeze reviewed main with no bypass actors. The
`connection-test` environment must accept only branch main, require owner
review, and disable administrator bypass. Freeze plus exact checkout binds
approval to reviewed code. An environment or branch allowlist alone does
not exclude an unreviewed workflow. Repository-level secrets are forbidden.

Protected lightweight tags `activation-armed-v2` and `activation-consumed-v2`
bind v2's sole opportunity to reviewed v2 code. Consumption is atomically
created and reread before **all** Telegram I/O. Existing or uncertain
consumption blocks. Concurrent runners cannot both reserve. Crashes can
forfeit delivery; no retry, reset, deletion or replacement activation exists.

## Mandatory v1 retirement

V2 reads only the exact public old repository
`aliakrammarufi/gsl-connection-test-runner`, numeric ID `1418486617`.
Its main and **both** lightweight historical tags `activation-armed-v1`
and `activation-consumed-v1` must directly reference:

```text
ced5e2983aad6093261fa862f1d3757f74f8dc5b
```

V1's frozen-main and immutable-fence policies must stay active; visible
bypass lists must be empty. Its connection-test workflow must be
`disabled_manually`. Historical runs are pinned by ID, SHA, main branch,
event, workflow path, attempt 1 and outcome:

| Run ID | Event / workflow | Outcome |
| --- | --- | --- |
| 38523683737 | push / offline-tests.yml | success |
| 38535703298 | workflow_dispatch / connection-test.yml | failure; audit failed, test skipped with zero steps |

Missing history, a new run, changed attempt or started test job blocks,
even if the run count is unchanged. The attempt-scoped jobs endpoint proves
attempt 1; optional job `run_attempt` must agree if present. Old evidence
requests are GET-only and unauthenticated; v2's scoped token never reaches
v1. Rate limits, errors and malformed responses block. Historical fences
are reread after v2 consumption before preflight and again before sending.

Creating consumed-v1 is **retirement without send**, not evidence of a
delivered message. The original run/job proof and separate owner retirement
record establish why v2 may be reviewed. V2 never writes v1 refs. This
bundle does not perform retirement. See [SETTINGS.md](SETTINGS.md).

## Credentials, transport and trust

Private secrets enter only the final approved step's environment, never
chat, Git, arguments, logs or artifacts. GitHub tokens are opaque, nonempty,
printable non-whitespace ASCII bounded to 4,096 bytes; no prefix/JWT parsing
or legacy length assumption. Telegram validates private confirmation, group
ID/digest, bot identity/membership and privacy. Paid broadcasts are false.

TLS validates certificates/hostnames, requires TLS 1.2+, uses fixed hosts
`api.github.com` / `api.telegram.org`, eight-second timeouts, 128 KiB response
bounds and a 120-second process deadline. No redirects, proxies or retries;
job deadlines are three minutes. Failures print only
`BLOCKED_OR_UNCERTAIN_DO_NOT_RETRY`, never exceptions or responses.

GitHub can hide bypass lists from runtime tokens. Their omission is not
proof: owner review of full privileged live metadata and disabled-bypass
UI is mandatory before secret entry and pending-job approval. The runtime
audit says `PUBLIC_METADATA_PASS_OWNER_FULL_POLICY_REVIEW_REQUIRED`.

GitHub, its managed OS/Python image, pinned checkout action and owner remain
trusted. Frozen refs are not administrator-proof WORM: an administrator can
change policy or delete/recreate a repository. Never restore snapshots over
fences, remove protections or create another epoch after a possible send.
Keep all historical fences indefinitely. If malicious administrator/platform
resistance is required, this design is insufficient.

Public files reveal generic code, public owner identity, public v1 repo/
commit/run pins and one-bit fence state. No private project content, bot
credential, group details or receipt is included.

## Cost

Only standard public-repository GitHub-hosted `ubuntu-24.04` runners; no
larger runners, artifacts, caches, paid integrations or broadcasts. These
runners are documented as free, but current account $0 budgets and Stop
usage must be checked privately before activation. No billing change or
purchase may overcome a missing control. Offline tests prove no hosted result.

Primary sources: [opaque token guidance](https://github.blog/changelog/2026-10-02-stateless-github-app-installation-tokens-rolled-out/),
[environment protection](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments),
[ruleset visibility](https://docs.github.com/en/rest/repos/rules#get-a-repository-ruleset),
[create reference](https://docs.github.com/en/rest/git/refs#create-a-reference),
[attempt-scoped jobs](https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run-attempt),
[disable workflow](https://docs.github.com/en/rest/actions/workflows#disable-a-workflow),
[public runner billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

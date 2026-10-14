# Exact v2 continuation and activation procedure

Proposal for independent review. Local preparation authorizes no publication,
retirement, settings changes, secret entry, dispatch or deployment approval.
Stop on missing, uncertain or conflicting evidence. Never weaken protection,
reset history or silently retry. The fixed text has conditional owner
authorization; each operational stage still needs its execution authorization.
The assistant must never approve the owner's pending deployment.

## 0. Independent review

Verify the externally recorded SHA-256 of `PUBLIC_FILES.sha256`, every file
and no extras. Review the exact diff against the original frozen published
v1 bundle, including token compatibility, v2 binding and mandatory retirement.
Run offline tests and review the outside-bundle retirement operation and
evidence gate tools. No v2 commit, ID or hosted CI exists yet. Historical
snapshots are not current evidence; re-read owner live metadata before any
continuation, without accessing secret values. Failure to obtain it blocks.

## 1. Separately authorize and perform v1 retirement without send

Target only `aliakrammarufi/gsl-connection-test-runner`, ID `1418486617`.
Preserve main and armed-v1 at `ced5e2983aad6093261fa862f1d3757f74f8dc5b`,
and all native protections. Verify original manifest digest
`0c8126a75ce80bca55faf8a314b2b7887282c990fc6a4a89b2c62f5fdfe3e437`
and every remote byte. Require zero repo/env secrets, release absent,
unchanged full no-bypass rules, sole owner reviewer, main-only environment,
disabled administrator bypass, owner-only admin and privately verified $0
hard stops. Repository variables must still be exactly the original three
SHA/ID/control pins; environment variables must be absent.

Require **exactly** run IDs `38523683737` and `38535703298`, both original
SHA/main/attempt 1, completed with recorded events, workflow paths and
success/failure outcomes. The manual run's attempt-1 jobs must show audit
failure and test skipped with an explicit empty steps array. Both pending
deployment lists must be empty. No new/deleted run, rerun or started test
is acceptable. Run count alone is insufficient.

Consumed-v1 must genuinely return authenticated HTTP 404 / Not Found,
alongside a positive armed-v1 read under the same owner access. An existing
consumed ref blocks the create operation pending independent investigation.

After those gates and separate authorization:

1. Persist a private, create-only journal before the request: target,
   original SHA, current proof and one planned POST.
2. **Once only**, create `refs/tags/activation-consumed-v1` at the original
   SHA using the Git create-reference API; require HTTP 201. No force,
   update/delete, retry or branch mutation.
3. Reread both tags as lightweight commit objects at the original SHA;
   recheck pinned runs/jobs, absent credentials and protections.
4. Disable only `connection-test.yml` using the Actions disable API;
   require HTTP 204, then GET it and require `disabled_manually`.
5. Recheck the retired phase and persist **“retired without send”** with
   response/reread/disable results and exact run/job proof. Retain this
   journal privately outside both repositories; retain both tags forever.

The separate operation document contains exact endpoints and commands.
No Telegram request is part of retirement. An uncertain response stops:
never repeat the create. Fresh independent read-only reconciliation and
explicit owner authorization may complete remaining disable/record steps
after proving the tag correct and no Telegram job started. Never delete or
reset consumption to recover an opportunity.

## 2. Separately publish only reviewed v2 bytes

After verified retirement and publication authorization, check
`aliakrammarufi/gsl-connection-test-runner-v2` does not exist; otherwise stop.
Create a fresh public owner-only repo with no templates/imports/forks.
Publish only the twelve approved files as a fresh root commit on default
main. No private project content/history; original repo remains untouched.

Read back the entire tree, every byte/hash and external manifest digest.
Record the resulting full commit as `CODE_SHA`, numeric ID as `REPO_ID`,
and the exact automatically created offline CI run as `OFFLINE_RUN_ID`.
Require that run's exact SHA, `offline-tests.yml` path, push event, main,
attempt 1 and success. These owner-held pins are not guessed now. Publication
does not authorize credentials or execution. Any byte change needs fresh review.

## 3. Platform protections before credentials

Only under separate settings-stage authorization:

| Control | Required value |
| --- | --- |
| Repository | Public, `aliakrammarufi`, `REPO_ID`, owner-only administration |
| Default main | Exactly reviewed `CODE_SHA` |
| Main ruleset | `controls/main-freeze.json`; active creation/update/deletion restrictions; no bypass actors |
| Fence ruleset | `controls/immutable-activation-tags.json`; active v2 tag update/deletion restrictions; no bypass; creation allowed |
| Default workflow permissions | Read-only contents; PR creation/approval disabled |
| Allowed actions | Selected only, SHA pinning required, sole pinned checkout revision; broad GitHub-owned/verified allowlists false |
| Outside contributors | `all_external_contributors`; never approve external PR workflows |
| Environment | Exactly `connection-test` |
| Reviewer | Sole owner `aliakrammarufi`, ID `107786534` |
| Self-review | Allowed for owner dispatch/approval; independent code review remains separate |
| Administrator bypass | Explicit false in privileged API and unchecked in owner UI |
| Deployment policy | Exactly branch main, no wildcard/tag/extra policy |
| Secrets before entry | Zero repository/environment secrets; no organization inheritance (personal User owner) |
| Runtime | Standard GitHub-hosted `ubuntu-24.04`, no self-hosted/larger runners |
| Storage / debug | No artifacts, caches, paid services, debug settings or TLS logging |
| Budget | Existing $0 and Stop usage unchanged, privately verified |

Full owner live ruleset metadata must explicitly show `bypass_actors=[]`,
`current_user_can_bypass=never`, exact conditions/type-only rules, no extra
or inherited policy. Server ordering may differ. Missing bypass fields
are not attestation. Required reviewers and disabled administrator bypass
must be available at $0; if unavailable, stop rather than buy or bypass.

Freeze main before secrets. Do not thaw it for repairs. No unreviewed code
can land on the sole environment-eligible branch. Freeze plus native
environment approval plus exact checkout enforces reviewed credential release;
Python checks supplement the boundary after injection. Environment/branch
policy alone is insufficient. Runtime uses only workflow-scoped contents/
Actions permissions, no PAT, admin token, OIDC broker or write access to v1.

At **protected** phase, v2 has zero secrets, zero repo/env variables, no
armed/consumed refs and only pinned `OFFLINE_RUN_ID`. V1 is fully retired,
with zero secrets/release and exact historical runs.

## 4. Bind v2's sole opportunity

After protected-phase review, under separate setup authorization, set
exactly these repository Actions variables:

```text
APPROVED_COMMIT_SHA=CODE_SHA
APPROVED_REPOSITORY_ID=REPO_ID
CONTROL_REVIEW_COMPLETE=true
```

The third records complete policy/UI/budget review; it creates no protection.
Create lightweight `activation-armed-v2` at `CODE_SHA` once with tag rules
already active. Reread main/armed-v2 directly at that SHA; consumed-v2 must
genuinely be absent. Never point armed-v1 at v2 or reuse it as v2 authority.

At **armed** phase, all secrets remain zero, release absent, repo variables
exactly these three pins, and v2 history exactly `OFFLINE_RUN_ID`. V1 fences
stay at old SHA, workflow disabled, historical IDs/attempts unchanged.

## 5. Private secret entry and release

Privately confirm existing bot, stable negative group ID, permission to post
and continued privacy: no public username, linked channel or forum. This
procedure does not authorize Telegram discovery calls. Local preparation
does not read or modify the existing private configuration.

Owner enters values directly in authenticated GitHub UI:
`Settings → Environments → connection-test → Environment secrets`.

| Secret name | Private value |
| --- | --- |
| `TELEGRAM_BOT_TOKEN` | Existing token directly from private storage |
| `TELEGRAM_CHAT_ID` | Privately confirmed canonical negative group ID |
| `TELEGRAM_CHAT_SHA256` | Digest of that exact string, including minus sign |
| `DESTINATION_PRIVATELY_CONFIRMED` | Literal `true` after private confirmation |

Use `python3 -I private_destination_digest.py` privately: hidden terminal
input, digest only output. Keep even the digest private. Never put these
values in chat, source, Git, inputs, arguments, logs or artifacts, or send
them to the assistant. No real secret is needed for offline testing.
Old repository secrets stay absent forever.

At **secrets** phase, require those exact four environment names by metadata
only, zero repository secrets, release still absent, all pins/refs/protections
unchanged and exact expected run IDs. Do not require zero environment secrets
after entry. No secret values may enter evidence captures.

Only under bounded activation authorization, set environment variable
`RELEASE_ONE_TEST=true` after all gates and private confirmation. At
**released** phase, four expected names remain, repo secrets remain zero,
exactly that environment variable exists and no dispatch exists yet;
history is still exactly `OFFLINE_RUN_ID`.

## 6. One dispatch and owner approval

Under explicit one-continuation authorization, persist a private create-only
dispatch journal before dispatch. Dispatch `connection-test.yml` once on
main with sole input `reviewed_sha=CODE_SHA`; capture its exact returned ID
as `TEST_RUN_ID`. No POST retry or fallback second dispatch. Uncertain
acceptance stops and requires read-only reconciliation.

The secret-free audit must pass offline checks and live retirement/control
checks. Audit failure stops, without retry permission. Test must await
owner environment review, no started steps or earlier approval. At
**pending** phase, v2 has exactly pinned `OFFLINE_RUN_ID` and specific
`TEST_RUN_ID`, both main/`CODE_SHA`/attempt 1, with correct push/manual paths.
Verify successful audit, test not started and exactly the pending
`connection-test` deployment. Recheck remote hashes, full native controls,
disabled-bypass UI, v1 retirement/history, private confirmation and fixed text.

Give the pending run link to the owner. Only the owner uses **Review
deployments → connection-test → Approve and deploy**, for that exact run
and commit. Assistant approval is prohibited. Reject any SHA, ref, event,
attempt or policy mismatch. Frozen reviewed main, pinned checkout and
exact run/workflow SHA binding exclude unreviewed branch/workflow inputs.

V2 audits, atomically creates/rereads consumed-v2, rechecks v1 fences,
preflights bot/group and attempts the fixed message once. It rechecks v1/v2
fences before sending. All Telegram requests are after durable consumption;
concurrent losers make none. No schedule or live-news activation exists.

## 7. Evidence retention and cleanup

Inspect only exact `TEST_RUN_ID` and attempt-1 jobs. Privately verify group
result; never export a Telegram receipt. Record public status/refs privately.
Consumed-v2 permanently spends the opportunity for success, failure,
cancellation or uncertainty. Redacted failure does not prove non-delivery.
Failure before consumption also grants no automatic rerun/dispatch.

Remove v2's four secrets, unset release and disable connection-test workflow.
Verify zero secrets/release after cleanup, both v2 refs at `CODE_SHA`, main
frozen, exact known run IDs/attempts unchanged and v1 evidence intact.
Keep all four tags indefinitely. Never delete/repoint fences, restore an
omitted fence, rename consumption, recreate repos or create v3 to retry a
possible send. Missing history blocks. No news, schedule or trading activation.

## Evidence tool and response format

Outside-bundle `verify_evidence.py` never makes network requests/mutations.
It verifies operator-collected privileged live JSON: `responses` maps full
`/repos/OWNER/REPO/...` endpoint to actual `status` and parsed `value`.
`captured_at_utc` is an aware UTC timestamp from actual collection, at most
ten minutes old. Never relabel stale content with a new timestamp. Re-read
immediately before authorized mutation/approval. No tokens, logs, secret
values or private group information in snapshots.

```sh
python3 -I verify_evidence.py pre-retirement PRIVATE_SNAPSHOT.json
python3 -I verify_evidence.py retirement-created PRIVATE_SNAPSHOT.json
python3 -I verify_evidence.py retired PRIVATE_SNAPSHOT.json
python3 -I verify_evidence.py protected PRIVATE_SNAPSHOT.json CODE_SHA REPO_ID OFFLINE_RUN_ID
python3 -I verify_evidence.py armed PRIVATE_SNAPSHOT.json CODE_SHA REPO_ID OFFLINE_RUN_ID
python3 -I verify_evidence.py secrets PRIVATE_SNAPSHOT.json CODE_SHA REPO_ID OFFLINE_RUN_ID
python3 -I verify_evidence.py released PRIVATE_SNAPSHOT.json CODE_SHA REPO_ID OFFLINE_RUN_ID
python3 -I verify_evidence.py pending PRIVATE_SNAPSHOT.json CODE_SHA REPO_ID OFFLINE_RUN_ID TEST_RUN_ID
```

Arguments are public pins/files, never credentials. This tool checks
consistency under trusted-owner collection; it cannot prove snapshot
authenticity or replace live hash/UI/budget checks and private confirmation.
Missing/unsupported fields block. Job schema does not promise `run_attempt`:
attempt-scoped endpoint plus run-level pin supplies that proof.

Primary sources: [workflow disable/dispatch](https://docs.github.com/en/rest/actions/workflows),
[runs/attempts](https://docs.github.com/en/rest/actions/workflow-runs),
[attempt-scoped jobs](https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run-attempt),
[create-reference API](https://docs.github.com/en/rest/git/refs#create-a-reference),
[owner environment approval](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/review-deployments),
[budget hard stops](https://docs.github.com/en/billing/how-tos/set-up-budgets).

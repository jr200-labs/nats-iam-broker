# User projection work tracker

Task: T-20261110-WZZB1F4PPZHMW34D. Source: [transcribed draft spec](user-projection-spec.md).

## Initial implementation decisions (historical; follow-up changes below)

- Initially keep the existing behavior when projection is absent. Superseded for required UserInfo, subject validation and expiry by the security adjustments below.
- Use a pure compiled projection before request-specific config rendering and binding selection.
- Refuse braces as well as subject separators/wildcards in projected values: sequential NATS substitution must never reinterpret an inserted value.
- Keep the conservative namespace freshness model: reading `id_token.sub` includes ID-token `iat`. An ID token 12 minutes old under a 15-minute age bound allows at most three more minutes, even with fresh UserInfo. Correct the worked-example expectation in implementation documentation; preserve the original source spec.
- Require a positive explicit `max_claims_age` in the initial implementation, removing the unspecified no-bound `fresh_until` case.
- Initially restrict name rules to identity-preserving forms, rather than accepting any expression that merely mentions `sub`. Preserve signed `sub`, `iat`, `exp` independently of custom mapping.
- Compute conservative namespace dependencies at load; conditional branches count even if not evaluated. Reject dynamic root access and unrestricted functions.
- Fetch required UserInfo with the existing bounded request timeout, without a cache or fallback; validate exact subject equality. Initially retain the existing mandatory `at_hash` provider restriction and document it.
- Validate scoped-account configuration conservatively across all IdPs and bindings. Do not infer reachability from arbitrary match expressions.

## Review fixes

- [x] F1: Prevent template syntax inside projected tokens and tag keys; regression test inserted mustaches.
- [x] F2: Make freshness examples agree with namespace reads; clamp expiry, refuse stale/exactly-expired results, specify future `iat` handling.
- [x] F3: Enforce stable identity construction and preserve signed registered claims from custom mapping.
- [x] F4: Determine dependencies statically, including conditional branches; deny dynamic namespace selection.
- [x] F5: Bound expression source, claim input, regex patterns, tag output, aggregate input-by-AST work and evaluation; compile regexes at load. Measure normal and work-refusal costs without claiming memory limits establish a wall-clock SLA.
- [x] F6: Specify missing `max_claims_age`, UserInfo timeout/cache behavior and exact expiry semantics.
- [x] F7: Keep mandatory `at_hash` by default; implement explicit `user_info.require_at_hash: false` interoperability, always verifying present hashes and exact subjects. Document the token-pair binding tradeoff.

## Implementation and acceptance

- [x] Compiled projection, capture/digest helpers, typed refusal kinds, sorted/deduplicated tags.
- [x] Global and per-IdP configuration, load/reload validation, literal projection config protected from per-request rendering.
- [x] Auth callback integration, separate ID-token/UserInfo claims, reserved `user` binding/template data, projected minting and audit.
- [x] Scoped issuance with empty `UserPermissionLimits` and load-time refusals.
- [x] Projection refusal metrics and redacted logs/client errors.
- [x] Unit/security tests, end-to-end embedded-server integration, legacy compatibility checks.
- [x] Complete local shared lint checks and inspect root checkpoint declaration (absent). Initial PR head passed all 11 CI checks; the follow-up head requires a fresh CI result.
- [x] Prepare the draft PR with limitations and follow-up work stated explicitly; publication is recorded in the task conversation.

## Follow-up implementation on PR #140

- [x] Apply UserInfo subject matching to legacy non-projection behavior (now included on this PR, with missing credentials/fetch errors also refusing enabled UserInfo).
- [x] Validate legacy rendered subject permissions. Handle null identity group/role lists as missing claims without reflection panics.
- [x] Reconcile expiry skew documentation with actual OIDC verification behavior.
- [x] Seeded property/fuzz coverage and JetStream consumer authorization acceptance (bounded fuzz run; no claim of exhaustive exploration).
- [x] Review consumer ownership, shared inbox isolation, acknowledgement permissions and cross-user consumer mutation in the illustrative JetStream template.

## Verification and remaining draft work

The implementation retains conservative namespace freshness. Follow-up changes add explicit optional-hash interoperability, aggregate work admission, measured large-input behavior and bounded encoded UserInfo responses. Security tightening applies to legacy UserInfo and expiry as well as the opt-in projection.

- Unit suite: `make test` passed, including the existing legacy auth tests and new projection refusal/configuration/minting tests.
- Integration suite: `make test-integration` passed, including real scoped-account permission expansion, author/table/role refusals, fresh UserInfo on reconnect, missing access token, subject mismatch, outage, stale token and unsafe subject cases.
- Race checks: `go test -race ./internal/broker ./internal/metrics -timeout=3m` and `go test -race -tags=integration ./tests/integration -timeout=3m` passed.
- Static/build checks: `go vet ./...`, direct build, and `make build` passed. Incidental `go mod tidy` normalization was restored; dependency versions are unchanged.
- Checkpoint: inspected repository root; `preview-checkpoint.json` is absent, so no checkpoint command is declared.
- Shared lint: installed the exact CI tool (`golangci-lint v2.15.0`) and copied the canonical config from the attached, unchanged `github-action-templates` repository into ignored `.shared/`; local run reports zero issues. No shared files or workflows were changed.

Completed follow-up acceptance:

- [x] Run local shared lint; initial-head CI is green. Follow-up-head CI is recorded separately after publication.
- [x] Bound aggregate expression work and encoded UserInfo before decoding, including chunked bodies and redirect refusal. Preserve the 30-second/caller OIDC deadline. Measured a near-limit 3,000-group projection at approximately 0.91 ms/op (330 KiB allocation) and oversized aggregate-work refusal at approximately 0.041 ms/op (64 KiB allocation) on this worker; measurements are observations, not wall-clock guarantees.
- [x] Add deterministic output, safe-subject, lowercasing, deduplication and freshness fuzz properties. Two bounded runs exercised 18,467 and 10,758 cases without failure. Exercise actual reload rejection/atomic state retention and a successful new snapshot while proving the previous snapshot remains usable.
- [x] Add structured namespace/as-of, reason, found-type, count/max details without claim values; count final issuance freshness refusals too. Test exact counter labels/count and redacted logs with an isolated registry.
- [x] Require `account_jwt` and an independently pinned `operator_public_key`; verify signature, validity, account identity and actual signing-key user scope. Reject missing, unscoped, expired or mismatched artifacts.
- [x] Add an owned-consumer/inbox template and embedded-server acceptance for both granted streams, delivery/acknowledgement, cross-user creation/update/delete/pull/ack/inbox refusals, ungranted-table refusal and subject/payload consumer mismatch. The source draft remains unchanged.

## Compatibility and deployment contract

- `user_info.enabled: true` now requires an access token and successful matching UserInfo; missing credentials or provider outages no longer fall back to old ID-token claims.
- `clock_skew` does not extend `exp`, including exact expiry. Minted expiry preserves the original signed value across mappings and UserInfo.
- Scoped accounts require the verified signed account artifact and independent operator signer pin. Deploy the **same artifact** to the server resolver. This PR does not roll out infrastructure or attest a remote resolver's current state.
- Rendered-subject syntax validation preserves intentional wildcard permissions. A syntactically valid legacy wildcard from a raw claim is still possible; use projection `.user` fields for the stronger no-widening guarantee.
- The strict `at_hash` default is preserved. Optional-hash providers require explicit policy configuration and exact subject matching; that choice does not verify the exact token pair without the hash.

Latest publication and fresh CI results are recorded on PR #140 and in the task conversation. Long-running fuzz campaigns and deployment-specific topology/ack-format testing remain operational acceptance rather than claims made by this bounded run.

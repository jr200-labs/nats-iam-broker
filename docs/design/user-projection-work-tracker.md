# User projection work tracker

Task: T-20261110-WZZB1F4PPZHMW34D. Source: [transcribed draft spec](user-projection-spec.md).

## Initial implementation decisions

- Keep the existing behavior when projection is absent.
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
- [x] F5: Bound expression source, claim input, regex patterns, tag output and evaluation; avoid claiming memory limits alone bound CPU.
- [x] F6: Specify missing `max_claims_age`, UserInfo timeout/cache behavior and exact expiry semantics.
- [x] F7: Document mandatory `at_hash` as a provider restriction; consider optional-hash interoperability separately.

## Implementation and acceptance

- [x] Compiled projection, capture/digest helpers, typed refusal kinds, sorted/deduplicated tags.
- [x] Global and per-IdP configuration, load/reload validation, literal projection config protected from per-request rendering.
- [x] Auth callback integration, separate ID-token/UserInfo claims, reserved `user` binding/template data, projected minting and audit.
- [x] Scoped issuance with empty `UserPermissionLimits` and load-time refusals.
- [x] Projection refusal metrics and redacted logs/client errors.
- [x] Unit/security tests, end-to-end embedded-server integration, legacy compatibility checks.
- [ ] Complete shared lint/CI checks (local tests/build pass); root checkpoint manifest inspected and absent.
- [x] Prepare the draft PR with limitations and follow-up work stated explicitly; publication is recorded in the task conversation.

## Separate follow-ups

- [ ] Apply UserInfo subject matching to legacy non-projection behavior (separate compatibility/security fix).
- [ ] Validate legacy rendered subject permissions.
- [ ] Reconcile expiry skew documentation with actual OIDC verification behavior.
- [ ] Full property/fuzz coverage and JetStream consumer authorization acceptance.
- [ ] Review consumer ownership, shared inbox isolation, acknowledgement permissions and cross-user consumer mutation in the illustrative JetStream template.

## Verification and remaining draft work

The first implementation includes the F1–F7 resolutions above, using conservative freshness and mandatory `at_hash` rather than adding a new identity/grant age policy or broadening provider interoperability. Expression limits are structural; adversarial runtime measurements remain follow-up work.

- Unit suite: `make test` passed, including the existing legacy auth tests and new projection refusal/configuration/minting tests.
- Integration suite: `make test-integration` passed, including real scoped-account permission expansion, author/table/role refusals, fresh UserInfo on reconnect, missing access token, subject mismatch, outage, stale token and unsafe subject cases.
- Race checks: `go test -race ./internal/broker ./internal/metrics -timeout=3m` passed.
- Static/build checks: `go vet ./...`, direct build, and `make build` passed. Incidental `go mod tidy` normalization was restored; dependency versions are unchanged.
- Checkpoint: inspected repository root; `preview-checkpoint.json` is absent, so no checkpoint command is declared.
- Lint limitation: `golangci-lint` is not installed and the ignored shared `.shared/.golangci.yml` is absent in this checkout. Full shared lint has not been verified locally; CI remains required.

Before production acceptance:

- [ ] Run the complete shared lint/CI checks and fix any findings.
- [ ] Measure adversarial expression/regex execution and OIDC response input costs; establish operational deadlines without claiming the VM memory budget bounds CPU.
- [ ] Add full property/fuzz coverage and hot-reload acceptance (load-time validation is implemented and exercised, but not a new complete reload journey).
- [ ] Review/extend typed error details while preserving client/log redaction; test the new metric with an isolated registry.
- [ ] Validate the operator-managed account JWT scope during deployment. `scoped: true` is currently an explicit trusted declaration; an unscoped signer mislabeled scoped can issue unrestricted users.
- [ ] Complete JetStream consumer ownership, inbox isolation and acknowledgement acceptance independently of the command-subject example.

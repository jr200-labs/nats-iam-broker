# User projection and scoped issuance (initial implementation)

This opt-in feature projects verified identity into a NATS username and tags before request-specific rendering and role binding. Without `user_projection`, the existing username, audit tag, claim merging and permission behavior are preserved.

## Configuration

```yaml
idp:
  - key: kitchen
    description: Kitchen identity
    issuer_url: https://id.example.com
    client_id: nats-client
rbac:
  token_max_expiration: 15m
  user_projection:
    name: id_token.sub
    max_claims_age: 15m
    max_tags: 128
    tags:
      - key: read
        values: 'capture(userinfo.groups, "^read:([a-z0-9_]+)$")'
      - key: write
        values: 'capture(userinfo.groups, "^write:([a-z0-9_]+)$")'
      - key: role
        values: 'capture(userinfo.groups, "^role:([a-z0-9_]+)$")'
        max_values: 16
```

An `idp[].user_projection` replaces the global projection for that provider. Every IdP needs a unique lowercase `key` without `:` when any projection is configured. Rules are literal configuration, excluded from Go-template rendering and compiled on load/reload. Invalid rules reject the load/reload.

For one provider, `name` supports `id_token.sub` and `digest(id_token.sub)`. For multiple providers, use `idp.key + ":" + id_token.sub` or `digest(idp.key + ":" + id_token.sub)`. These identity-preserving forms replace the draft's syntactic reference check. They forbid truncation, constants and expressions which mention an identity without preserving it. Provider key changes require an identity migration. The broker protects the signed `sub`, `iat` and `exp` from custom claim mapping.

Tag rules yield a string or a list of strings. Missing optional claims yield no values. `min_values` and `max_values` apply after deduplication. Duplicate tag keys are refused. Values are emitted sorted by key then value. Names preserve case; tag keys and values must already be lowercase.

Tokens contain 1–256 bytes of printable ASCII excluding whitespace, `.`, `*`, `>`, `{` and `}`. Keys additionally exclude `:`. Braces are excluded because NATS performs sequential template substitutions: inserted values must not contain template syntax. Invalid values refuse the complete projection rather than being sanitized. `capture` ignores nonmatching claims; consequently a nonmatching group is no grant, not an error.

## Trusted inputs and expression limits

Expressions can access `id_token` (mapped claims with protected signed registered fields), `userinfo` (separate, unmapped response), `idp` (`key`, `description`, `issuer_url`, `client_id`), `connection` (`host`, `type`, `kind`, `tls_verified`), and `server` (`name`, `cluster`, `tags`). `tls_verified` means the callout contains a nonempty verified client-certificate chain; it does not merely mean TLS was used. No CONNECT options, client name, client tags, IO functions or clock functions are exposed.

The initial expression subset supports literal member access, arrays, conditionals, comparisons, membership, logical operators, coalescing, concatenation, and two pure helpers:

- `capture(values, pattern)`: whole-string RE2 match, exactly one capture group, literal pattern only. Accepts a string, string list or missing claim.
- `digest(value)`: lowercase hex SHA-256 of a string. Hashing does not make a mutable identifier safe.

All syntactically referenced namespaces count, including untaken conditional branches. Dynamic member selection, slicing, ranges, comprehensions, method calls and other functions are rejected. This deliberately bounded subset has no user-defined iteration or recursion. Maximum expression length is 2,048 bytes, AST size 256 nodes, pattern length 256 bytes, serialized identity input 64 KiB, and VM allocation budget 4,096 units per rule. `max_tags` defaults to 128 and is capped at 1,024, including a bound on rule count. These are structural limits, not a promised wall-clock deadline. Tighten or extend them only with adversarial measurements.

## Freshness and UserInfo

`max_claims_age` is required and positive in this implementation. Freshness is conservative: any read of `id_token`, including `id_token.sub` for the name, includes its original signed `iat`. The result expires by the oldest referenced namespace's as-of time plus this age, the signed ID token's expiry, and the existing configured credential limits. Config metadata has no age; connection/server/UserInfo facts use the supplied verification timestamp. Future ID-token `iat` and a freshness deadline at or before that timestamp are refused. Final issuance also refuses an expiry at or before the minting clock's current whole second.

**Correction to the draft example:** with an ID token already 12 minutes old and a 15-minute age limit, fresh UserInfo still produces a credential lasting at most three more minutes. A token 15 minutes old is refused. Clients must refresh ID tokens accordingly. This version does not separate immutable identity age from mutable grant age.

UserInfo is fetched on every connection if any rule references it, regardless of the legacy `user_info.enabled` setting. There is no cache, and no fallback to ID-token claims. An access token, a successful response and exact equality to the original signed subject are required. The existing 30-second OIDC request timeout also respects any earlier caller deadline. The initial version retains the existing requirement for `at_hash`; providers omitting that optional authorization-code-flow claim are not supported for UserInfo projection yet. Existing legacy UserInfo behavior is unchanged.

The projector returns typed `Missing`, `WrongType`, `NotAToken`, `TooMany`, `Stale`, `Unavailable` or `Evaluation` refusals. Logs contain kind/output only, and clients receive generic authorization failure. `nats_iam_broker_user_projection_errors_total{idp,kind}` counts refusals during projection. Additional detailed error payloads from the draft remain follow-up work.

## Bindings, templates and issuance

Role expressions see `user`, for example `'"waiter" in user.tags.role'`. Go templates see `.user`, for example `cmd.*.{{ .user.name }}.*`. A raw claim named `user` cannot shadow the projection in either context. It remains available to projection expressions under its input namespace. Projected issuance removes the old free-text audit tag; the audit event includes `authorized_user` in addition to existing fields.

Add `scoped: true` under a `rbac.user_accounts` entry to emit zero `UserPermissionLimits`. The actual signing key **must already be scoped in the operator-managed account JWT**; the broker does not create or discover that scope. Mislabeling an unscoped signing key as scoped can produce unrestricted permissions, so this declaration must match the deployed account JWT. Expiry remains outside the permission-limit object.

Scoped configurations require `service.account.xkey_seed` to be a curve key, a projection for every configured IdP, and no `skip_audience_validation`. All bindings to scoped accounts are checked; referenced roles must exist and must not set permissions or limits. Reachability is conservative: arbitrary match expressions are not used to excuse an IdP from these requirements.

The embedded-server integration test exercises real scoped issuance, projected matching, forged author/table/role refusals, signed subject protection from mapping, and removal of a current UserInfo grant on reconnect with the same tokens. The original draft's JetStream consumer sketch is not production acceptance for consumer ownership, shared inboxes or acknowledgement permissions. See the [work tracker](user-projection-work-tracker.md) for remaining acceptance and separate legacy fixes.

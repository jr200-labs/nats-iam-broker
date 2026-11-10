# User projection and scoped issuance

This opt-in feature projects verified identity into a NATS username and tags before request-specific rendering and role binding. Without `user_projection`, the existing username and audit tag remain. Security adjustments described below also apply to legacy configurations: required UserInfo, strict token expiry and rendered-subject validation.

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

For one provider, `name` supports `id_token.sub` and `digest(id_token.sub)`. For multiple providers, use `idp.key + ":" + id_token.sub` or `digest(idp.key + ":" + id_token.sub)`. These identity-preserving forms replace the draft's syntactic reference check. They forbid truncation, constants and expressions which mention an identity without preserving it. Provider key changes require an identity migration. The broker protects the signed `sub`, `iat` and `exp` from custom claim mapping. Mappings targeting these three names are ignored, retaining the source custom claim under its original name. UserInfo cannot replace these fields in the role-binding or template context, and server metadata is added directly without applying mappings a second time.

Tag rules yield a string or a list of strings. Missing optional claims yield no values. `min_values` and `max_values` apply after deduplication. Duplicate tag keys are refused. Values are emitted sorted by key then value. Names preserve case; tag keys and values must already be lowercase.

Tokens contain 1–256 bytes of printable ASCII excluding whitespace, `.`, `*`, `>`, `{` and `}`. Keys additionally exclude `:`. Braces are excluded because NATS performs sequential template substitutions: inserted values must not contain template syntax. Invalid values refuse the complete projection rather than being sanitized. `capture` ignores nonmatching claims; consequently a nonmatching group is no grant, not an error.

## Trusted inputs and expression limits

Expressions can access `id_token` (mapped claims with protected signed registered fields), `userinfo` (separate, unmapped response), `idp` (`key`, `description`, `issuer_url`, `client_id`), `connection` (`host`, `type`, `kind`, `tls_verified`), and `server` (`name`, `cluster`, `tags`). `tls_verified` means the callout contains a nonempty verified client-certificate chain; it does not merely mean TLS was used. No CONNECT options, client name, client tags, IO functions or clock functions are exposed.

The initial expression subset supports literal member access, arrays, conditionals, comparisons, membership, logical operators, coalescing, concatenation, and two pure helpers:

- `capture(values, pattern)`: whole-string RE2 match, exactly one capture group, literal pattern only. Accepts a string, string list or missing claim.
- `digest(value)`: lowercase hex SHA-256 of a string. Hashing does not make a mutable identifier safe.

All syntactically referenced namespaces count, including untaken conditional branches. Dynamic member selection, slicing, ranges, comprehensions, method calls and other functions are rejected. This deliberately bounded subset has no user-defined iteration or recursion. Maximum expression length is 2,048 bytes, AST size 256 nodes, pattern length 256 bytes, serialized identity input 64 KiB, and VM allocation budget 4,096 units per rule. Encoded ID tokens are also capped at 64 KiB before verification. Aggregate work is limited to 8,388,608 units, estimated conservatively as serialized identity bytes multiplied by total AST nodes across all rules; requests exceeding it are refused before evaluation. Capture regexes are compiled once at load. `max_tags` defaults to 128 and is capped at 1,024, including a bound on rule count. These are structural limits, not a promised wall-clock deadline. Tighten or extend them only with adversarial measurements.

## Freshness and UserInfo

`max_claims_age` is required and positive in this implementation. Freshness is conservative: any read of `id_token`, including `id_token.sub` for the name, includes its original signed `iat`. The result expires by the oldest referenced namespace's as-of time plus this age, the signed ID token's expiry, and the existing configured credential limits. Config metadata has no age; connection/server/UserInfo facts use the supplied verification timestamp. Future ID-token `iat` and a freshness deadline at or before that timestamp are refused. Final issuance also refuses an expiry at or before the minting clock's current whole second.

**Correction to the draft example:** with an ID token already 12 minutes old and a 15-minute age limit, fresh UserInfo still produces a credential lasting at most three more minutes. A token 15 minutes old is refused. Clients must refresh ID tokens accordingly. This version does not separate immutable identity age from mutable grant age.

UserInfo is fetched on every connection if any rule references it, regardless of the legacy `user_info.enabled` setting. There is no cache, and no fallback to ID-token claims. An access token, a successful response and exact equality to the original signed subject are required. The existing 30-second OIDC request timeout also respects any earlier caller deadline. A present `at_hash` must always validate. The default also requires its presence, preserving the original strict binding policy. For a provider omitting this optional authorization-code-flow claim, explicitly set `idp[].user_info.require_at_hash: false`; the verified provider endpoint and exact subject match remain mandatory. Only opt out when that provider's UserInfo claims are appropriate for the broker's client: subject equality binds identity, while the omitted hash no longer binds the exact access-token/ID-token pair. Encoded UserInfo responses are limited to 64 KiB before decoding, including streaming/chunked responses. Redirects are refused rather than forwarding access tokens. The same protections apply when legacy `user_info.enabled` is true; enabling it now requires a successful current response and never falls back after missing credentials, an outage or a mismatch. This is a deliberate security-related behavior change.

The projector returns typed `Missing`, `WrongType`, `NotAToken`, `TooMany`, `Stale`, `Unavailable` or `Evaluation` refusals. Logs contain bounded kind/output/type/reason metadata, counts/limits, namespace and as-of time; claim values and evaluator messages are excluded. Clients receive generic authorization failure. `nats_iam_broker_user_projection_errors_total{idp,kind}` counts refusals during projection. `ProjectionError` supplies structured namespace/as-of, count/max, reason and found-type fields without embedding claim values. Metrics may be registered with `metrics.NewWithRegisterer` for isolated broker instances.

## Bindings, templates and issuance

Role expressions see `user`, for example `'"waiter" in user.tags.role'`. Go templates see `.user`, for example `cmd.*.{{ .user.name }}.*`. A raw claim named `user` cannot populate or shadow this reserved name in either context, including on providers without an active projection. Those providers can still use legacy bindings on other claim names; a raw `user` object never satisfies a projection-based binding or template. It remains available to projection expressions under its input namespace. Projected issuance removes the old free-text audit tag; the audit event includes `authorized_user` in addition to existing fields.

Add `scoped: true` under a `rbac.user_accounts` entry to emit zero `UserPermissionLimits`. Also provide `account_jwt` (the signed account JWT, optionally loaded with the existing `readFile` config function) and `operator_public_key` (the independently pinned operator signer). The broker verifies the artifact's signature, validity, account identity and operator signer, and requires an actual user scope for the configured signing key. An unscoped signer, absent artifact or mismatched pin refuses configuration. Do not derive the trusted pin from the untrusted JWT. Deploy this same account artifact to the NATS resolver; the broker cannot attest a remote resolver's current state. Expiry remains outside the permission-limit object.

Scoped configurations require `service.account.xkey_seed` to be a curve key, a projection for every configured IdP, and no `skip_audience_validation`. All bindings to scoped accounts are checked; referenced roles must exist and must not set permissions or limits. Reachability is conservative: arbitrary match expressions are not used to excuse an IdP from these requirements.

The embedded-server integration tests exercise real scoped issuance, projected matching, forged author/table/role refusals, signed subject protection from mapping, current UserInfo on reconnect and the consumer isolation policy below. See the [work tracker](user-projection-work-tracker.md) for the verification record and deployment assumptions.

## Consumer ownership and inbox isolation

The source draft's JetStream sketch is intentionally preserved, but its arbitrary consumer names and shared `_INBOX.>` subscription should not be deployed as an isolation policy. A stricter pull-consumer template ties every API and acknowledgement to the projected name:

```text
pub.allow  $JS.API.CONSUMER.CREATE.{{tag(read)}}.{{name()}}.{{tag(read)}}.>
           $JS.API.CONSUMER.INFO.{{tag(read)}}.{{name()}}
           $JS.API.CONSUMER.MSG.NEXT.{{tag(read)}}.{{name()}}
           $JS.API.CONSUMER.DELETE.{{tag(read)}}.{{name()}}
           $JS.ACK.{{tag(read)}}.{{name()}}.>
           $JS.ACK.*.*.{{tag(read)}}.{{name()}}.>
sub.allow  _INBOX.{{name()}}.>
```

This example assumes each table's stream and subject prefix are named after that table. Configure the client inbox prefix as `_INBOX.<projected-name>` (for Go, `nats.CustomInboxPrefix`) and the consumer name as the projected name. Multiple connections for the same identity intentionally share that identity's consumer. The two acknowledgement rules accommodate the standard and domain/account-prefixed formats; deployment acceptance must use the server's actual format and topology.

The integration test creates and reads both granted streams and acknowledges deliveries. It refuses cross-user consumer creation, updates, deletion and pulls, another user's acknowledgement subject and inbox subscription, and an ungranted table. It also verifies that the server rejects an allowed API subject whose payload names a different consumer. No permission to create an unfiltered consumer is granted.

## Legacy migration and compatibility

`user_info.enabled: true` now means required current claims. Clients that previously omitted the access token must send it; provider outages refuse new connections. Disable this setting only if using the older ID-token snapshot is an intentional policy. Projection rules referencing UserInfo require it independently of this setting.

`clock_skew` tolerates future issuance within the configured allowance. It never extends `exp`: exact expiry and already-expired tokens are refused. Minted expiry uses the original signed ID-token expiry even if mapping or UserInfo supplies another `exp`.

Rendered permissions are validated before minting, including queue-subscription syntax, empty tokens, whitespace, unresolved templates and misplaced wildcards. Intentional valid wildcard grants are preserved. Consequently this syntax check alone cannot prevent a raw claim equal to `>` from widening a syntactically valid legacy permission; migrate permission templates to `.user` fields for that guarantee.

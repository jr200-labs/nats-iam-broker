# A user projection for `nats-iam-broker`

> Transcribed from the 11 supplied photos. Overlapping passages have been included once; code, tables and OCR errors have been corrected against the images. Source images and raw per-image OCR are retained in task T-20261110-WZZB1F4PPZHMW34D, under `attachments/` and `artifacts/ocr/`. This is a transcription of the draft, not an independent verification of its technical claims.

Draft spec, 2026-11-10, for changes proposed upstream to `jr200-labs/nats-iam-broker` (MIT). Written while building M3's authorization gates, when it turned out the broker cannot express what ticket 15 decided [the handwritten prefix before “ticket 15” is unclear], although decision 7 there expected "configuration rather than code".

Read at: broker `v1.7.7` (commit `ec93cb3`, 2026-11-05); `nats-server v2.15.1` (`b2fd3ef`), the version the platform's tests run; `nats-io/jwt v2` (`629763d`); `pocket-id` at `8b57842` (2026-11-09), and `ory/fosite`'s defaults, which it uses. Line numbers below are at those commits.

## Summary

Two changes, both opt-in:

1. **A user projection.** A new stage between verifying the IdP token and choosing a role binding: a pure, typed function from the verified identity to the NATS user's name, tags and how long they hold, or an error that refuses the connection. Every value it emits is a single subject token, the name comes from an identifier the user cannot change, and no claim older than a configured age is used.
2. **Scoped issuance.** For an account whose signing key is scoped, the broker leaves the user's permissions and limits empty, so the server applies the scope's permission template.

Together they let NATS compute permissions from claims with its own permission templates, which can take the product of several lists where the broker's templates cannot. They also close three gaps in the broker today:

- the user is named by whatever the client sends;
- a claim value is copied into a subject permission unchecked;
- the grants a connection gets are as old as the token it presents, which can be an hour or more, so taking a person out of a group does not take effect when their credential expires, nor when their connection is killed.

The third gap, freshness, matters most. Without it, a 15-minute credential lifetime bounds nothing.

## The case that prompted it

Authorization is per table, grants are independent, roles belong to a person, and the author is part of the subject so a payload cannot forge it. A kitchen's example: Alice may read `menu_prices` and `staff_rotas`, may write `menu_prices`, and holds the roles `head_chef` and `waiter`. `pocket-id` holds these as her groups:

```json
{ "sub": "6f1c0e2a-…", "groups": ["read:menu_prices", "read:staff_rotas",
  "write:menu_prices",
  "role:head_chef", "role:waiter"] }
```

Her NATS credential must allow exactly:

```text
publish    cmd.menu_prices.6f1c0e2a-….head_chef
publish    cmd.menu_prices.6f1c0e2a-….waiter
subscribe  the streams of menu_prices and staff_rotas
```

Bob, a waiter who may also write `menu_prices`, must be refused on `cmd.menu_prices.<alice>.…` (a forged author) and on `cmd.menu_prices.<bob>.head_chef` (a forged role). When Alice leaves the kitchen and is taken out of `write:menu_prices`, she must lose that grant within the credential's 15 minutes, and at once if her connection is killed.

## What the broker does today

1. **One role binding per user.** `lookupUserAccount` (`internal/broker/config_rbac.go:292`) keeps the best match, or under `strict` the first full match, and collates only that binding's roles (`collateRoles`, line 447). Independent grants need a binding for every combination a person can hold.
2. **Templates cannot iterate over a claim.** Each `{{ ... }}` is compiled and rendered on its own (`newTemplateCache`, `internal/broker/template_fns.go:110`, pattern `{{[^\n]*?}}`), inside one YAML scalar (`renderYAML`, line 165). A `range` cannot span expressions, and one scalar cannot become a list.
3. **The user JWT is named by the client.** `claims.Name = request.ConnectOptions.Username` (`internal/broker/auth_callback.go:251`). The server's `{{name()}}` permission template therefore names whoever the client says it is, and so does the connection's `authorized_user`, which the server takes from that name (`nats-server/server/auth_callout.go:326`).
4. **The only tag is fixed free text.** `claims.Tags.Add(fmt.Sprintf("email: %s, name: %s, idp: %s, expires: %s", ...))` (line 261). No claim reaches a tag. Since this tag begins `email:`, it is also what a template's `{{tag(email)}}` would read.
5. **Permissions and limits are always set** (lines 259–260), from `collateRoles`, which starts from a non-nil `Resp` and `NoLimit` limits.
6. **Claim values enter subject permissions unchecked.** `collatePermissions` (`config_rbac.go:502`) adds rendered subjects as they are, and nothing in the broker validates them as subjects. The documented example `basic.{{ .preferred_username }}` (`compose/nats-iam/rbac.yaml`) becomes `basic.>` for a user whose `preferred_username` is `>`. How far that reaches depends on whether the IdP lets users choose the value.
7. **A token's age is not bounded, and it can be presented again and again.** `ValidateTimes` (`internal/broker/idp_jwt_verifier.go:163`) refuses a token issued in the future, one expiring more than `max_token_lifetime` ahead (default 24 hours), and one presented more than `clock_skew` after its expiry (default 5 minutes, so a token is accepted for 5 minutes after it expires). Nothing bounds how long ago it was issued, and nothing stops it being presented for one connection after another. Each connection gets the groups the token held when it was issued. `pocket-id`'s ID tokens last an hour: it sets no lifespan (`backend/internal/oidc/provider.go:45`), and `fosite` defaults to `time.Hour` (`GetIDTokenLifespan`, `config_default.go`).
8. **UserInfo is the client's choice.** With `user_info.enabled`, the broker fetches UserInfo only if the client sent an access token, and otherwise uses the ID token's claims (`auth_callback.go:200`). If the fetch fails it logs a warning and does the same (line 191). A client that wants the older claims leaves the access token out.

Items 7 and 8 together mean that, with `pocket-id`, a person taken out of a group keeps it in NATS for up to about 65 minutes. The minted credential expires after 15, but the client reconnects with the same ID token and gets the old groups again. Killing the connection only forces that reconnect sooner.

## What NATS already provides

A scoped signing key carries a permission template in the account JWT, and the server expands it for each user that key signs (`nats-server/server/auth_callout.go:236–249`, calling `ProcessUserPermissionsTemplate`, `server/auth.go:479`). `{{name()}}` stands for the user JWT's name, `{{tag(k)}}` for the value of every user tag `k:<value>`, and several tokens in one subject expand to their cartesian product, capped at 4,096 subjects (`maxPermTemplateSubjectExpansions`, `auth.go:475`). A subject naming a tag the user lacks is dropped from an allow list.

The server accepts a scoped key's user only if `UserClaims.HasEmptyPermissions()` holds (`jwt/v2/signingkeys.go:102`), a deep comparison with the zero `UserPermissionLimits` (`jwt/v2/user_claims.go:90`). By item 5, every user the broker mints fails it today.

So what is missing is a name the user cannot choose, tags taken from claims, a bound on how old those claims are, and an empty permission set under a scoped key. The design below supplies the first three as one abstraction. They are the same operation, turning verified identity into NATS user fields, and they need the same checks.

## Design: the user projection

### Contract

```text
project(identity: VerifiedIdentity, rules: UserProjection) -> Result<NatsUser, ProjectionError>
```

- **Pure.** It does no IO and reads no clock. The broker fetches and verifies everything first, and reads its clock once, into `identity.verified_at`. The same input always gives the same output, in the same order.
- **Total or refused.** It yields a whole `NatsUser` or an error, never a partial user. An error refuses the connection.
- **Compiled and checked at load.** Its expressions are compiled when the config loads, so a syntax error fails the load and never a request. The checks on the name rule (below) also run then.

### Input, by who vouches for it, and as of when

| namespace | what | vouched for by | as of |
| --- | --- | --- | --- |
| `id_token` | the ID token's claims, after `custom_mapping` | the IdP's signature | its `iat` |
| `userinfo` | the UserInfo response, fetched with the access token the client sends | the IdP, over TLS; the access token bound to the ID token by `at_hash`; its `sub` equal to the ID token's | `verified_at` |
| `idp` | the matched IdP's `key` (a new, required field when a projection is configured), `description`, `issuer_url` and `client_id` | the broker's config | — |
| `connection` | `host`, `type` (`nats`, `websocket`, `mqtt`, `leafnode`), `kind`, and whether TLS verified a client certificate | the server, in the request it signs (`fillClientInfo`, `auth_callout.go:471`, and the request's `TLS`) | `verified_at` |
| `server` | the asking server's `name`, `cluster` and `tags` | the server | `verified_at` |

- **The two kinds of claims are kept apart, not merged.** They differ in freshness, which a rule must be able to choose between. Merging them is also what lets a UserInfo `sub` replace the ID token's today.
- **`userinfo` is fetched if, and only if, some rule reads it.** Then it is required: no access token, a failed fetch, or a `sub` different from the ID token's (OpenID Connect Core §5.3.2) refuses the connection. The client cannot choose the older claims by leaving the access token out.
- **Nothing the client asserts is in scope.** No `ConnectOptions` field (username, password, name, language, version), and not `ClientInformation.Name`, which copies the client's CONNECT name.
- **`connection.host` is the address the server saw.** Behind a proxy that is the proxy's, so it identifies a person only where the server sees clients directly.

### Output, and what makes it valid

```text
NatsUser { name: Token, tags: Map<TagKey, Set<Token>>, fresh_until: Time }
```

- A **`Token`** is 1 to 256 bytes of printable ASCII, excluding space, `.`, `*` and `>`. That is what can stand as one token of a subject, so a projected value can never widen a subject it is put into. Restricting it to ASCII also keeps out lookalike characters, and the lowercasing below, which in Unicode can change a value's bytes and length.
- A **`TagKey`** is a lowercase `Token` without `:`. It is written to the JWT as the tag `key:value`, which is the form the server's `{{tag(key)}}` reads.
- **Tag values must already be lowercase.** The JWT library lowercases every tag (`jwt/v2/types.go:440`), so a value with capitals cannot be carried faithfully. It is refused rather than lowercased, so a group `write:Menu_Prices` does not silently become a grant on `menu_prices`.
- **The name keeps its case**, because the server compares names exactly.
- **The name comes from an identifier that never changes and is never reassigned.** It is the author in every subject it is put into, so a name a user can edit, or one passed to someone else, lets one person write as another. Email and `preferred_username` are both, in many IdPs. At load the broker checks that the name rule reads `id_token.sub` and, with more than one IdP configured, `idp.key`, and that each IdP's `key` is a unique `Token`; `sub` is unique only within its issuer. The check is syntactic. It catches the usual mistakes, not every rule that could map two people to one name.
- **`fresh_until`** is when the oldest claim the rules read stops being fresh (see "Freshness"). The minted credential expires no later.
- **Bounded:** at most `max_tags` tags in all (default 128), and each rule may set `max_values`.
- **Deterministic:** tags are deduplicated and emitted sorted by key, then by value.

### Freshness

```yaml
rbac:
  user_projection:
    max_claims_age: 15m
```

Each namespace a rule reads has an as-of time, from the table above. With `max_claims_age` set:

- A connection is refused if any namespace its rules read is older than `max_claims_age` at `verified_at`.
- `fresh_until` is the earliest as-of time among the namespaces read, plus `max_claims_age`, and the minted credential's expiry is clamped to it, as it is already clamped to the IdP token's expiry. A credential therefore never outlives the freshness of the claims it was projected from.

What a grant change in the IdP then takes, given a 15-minute credential:

| where grants are read | with no connection kill | with a connection kill |
| --- | --- | --- |
| `id_token`, no `max_claims_age` (today) | up to the token's lifetime plus `clock_skew`: about 65 minutes with `pocket-id` | the same, as the client reconnects with the same token |
| `id_token`, `max_claims_age: 15m` | up to 15 minutes, and the client must refresh its ID token at least that often | up to 15 minutes, for the same reason |
| `userinfo` | up to 15 minutes | at once: the reconnect reads current claims |

Only claims read at connection time make a connection kill effective. That is the configuration a platform that revokes by killing connections must use, and the worked case below uses it. `pocket-id` supports it, because its UserInfo endpoint rebuilds claims from the user's current state on every call (`backend/internal/oidc/userinfo_handler.go:67`: "Disabling a user or removing them from the client's groups does not revoke the tokens already issued, so the user is re-checked like on the token endpoint"). A disabled user is therefore refused too. The price is that while the IdP is unreachable no new connection is admitted. Established connections keep working until their credentials expire.

### Configuration

Rules are `expr-lang` expressions, which the broker already uses for `match.expr`. What each yields is checked: one string for the name, and a string or a list of strings for a tag rule. The rules are read from the config as loaded, and are not themselves rendered per request. A hot reload recompiles them, and an invalid rule rejects the reload as any invalid config does now.

```yaml
rbac:
  user_projection:                     # idp[].user_projection overrides this for one IdP
    max_claims_age: 15m
    name: 'id_token.sub'
    tags:
      - key: read
        values: 'capture(userinfo.groups, "^read:([a-z0-9_]+)$")'
      - key: write
        values: 'capture(userinfo.groups, "^write:([a-z0-9_]+)$")'
      - key: role
        values: 'capture(userinfo.groups, "^role:([a-z0-9_]+)$")'
        max_values: 16
```

A tag rule may set `min_values`, refusing a person for whom it yields fewer, and `max_values`. Here no rule needs `min_values`, because a person with no `write:` group or no `role:` group is still a reader.

Helpers added to the expression environment:

- **`capture(values, pattern)`** takes a string or list of strings and returns, for each value the regular expression matches as a whole, its first capture group. A missing claim gives an empty list, so an optional claim does not need a guard, and a missing grant is no grant.
- **`digest(value)`** returns the lowercase hex SHA-256 of a string, to make a token of an identifier that is not one. It does not make a changeable identifier safe to use as a name.

The config-rendering functions (`env`, `readFile`, `expandEnv`, ...) are not available to projection expressions, so a projection cannot read anything outside `identity`. Patterns are Go's RE2, which runs in time linear in its input, and expressions run under `expr-lang`'s memory budget, so a large claim cannot make a projection slow.

### Errors

| error | when |
| --- | --- |
| `Missing { output }` | the name, or a tag rule with `min_values`, yields nothing |
| `WrongType { output, found }` | an expression yields the wrong type, such as a list for the name |
| `NotAToken { output, value, reason }` | a value breaks the `Token` rule or the lowercase rule, naming which |
| `TooMany { output, count, max }` | a rule passes `max_values`, or all rules pass `max_tags` |
| `Stale { namespace, as_of }` | a namespace a rule reads is older than `max_claims_age` |
| `Unavailable { namespace, reason }` | `userinfo` is read but there is no access token, the fetch failed, or its `sub` differs |
| `Evaluation { output, message }` | an expression fails at run time |

Each refusal is logged with its kind and output, and with values only under `log_sensitive`. It is counted in `user_projection_errors_total{idp, kind}`. The client is told only that authorization failed, so a refusal reveals nothing about a person's claims to whoever presents their token.

### Where it sits

```text
verify token → fetch UserInfo if read → project user → render the config for this request
  → choose role binding → mint
```

The projection runs before the per-request rendering (`GetConfig`, `config.go:210`), so that rendering and binding can both read its result.

- **Minting** takes the name and tags from the projection, and clamps the expiry to `fresh_until`. When a projection is configured, the free-text audit tag is not written. Everything it held is in the audit event the broker already publishes.
- **Role bindings** can match on the projection, as `user` in `match.expr` (for example `'"head_chef" in user.tags.role'`), so a binding can rest on validated values rather than raw claims.
- **Templates** see the projection as `.user`, for example `cmd.*.{{ .user.name }}.*`. A deployment without scoped keys then puts validated tokens into its subjects instead of raw claims, which closes item 6 for any permission written that way.

In both, `user` is a reserved name, so a claim called `user` is not visible there. The projection can still read it, as `id_token.user` or `userinfo.user`.

### Compatibility

Without `user_projection`, nothing changes: the name is the client's username, the audit tag is written, and claims are merged and unbounded in age as now. The documentation should say the default name is client-chosen and must not appear in a permission template, should show the documented example rewritten with `.user.name`, and should say that revocation takes as long as the IdP token's lifetime unless `max_claims_age` or `userinfo` is used.

## Scoped issuance

```yaml
rbac:
  user_accounts:
    - name: APP
      public_key: '…'
      signing_nkey: '…'  # a signing key the account JWT scopes with a user template
      scoped: true
```

- For a binding to a scoped account, the broker sets the user's `UserPermissionLimits` to the zero value, so the server applies the scope's template and limits. Expiry is unaffected, because `exp` is not part of `UserPermissionLimits`.
- Bindings to a scoped account still choose the account and the expiry, and can still refuse a token no binding matches.
- A scoped account's permissions are only as good as the projection, so at config load the broker refuses:
  - a binding to a scoped account whose roles set permissions or limits, because they would be silently ignored;
  - a scoped account with no `user_projection` for an IdP that can bind to it, because the name would be the client's;
  - such an IdP with `validation.skip_audience_validation`, because then an ID token any other application obtained from the same IdP would mint a credential here;
  - a broker with scoped accounts and no `service_account.xkey_seed`, because the callout request carries the client's tokens and must be encrypted between server and broker.

## The case, worked

The account `APP` is created with a scoped signing key whose template is the whole permission rule (a sketch, taking each table's stream to be named after the table):

```text
pub.allow  cmd.{{tag(write)}}.{{name()}}.{{tag(role)}}
           $JS.API.CONSUMER.CREATE.{{tag(read)}}.*.{{tag(read)}}.>
           $JS.API.CONSUMER.MSG.NEXT.{{tag(read)}}.*
sub.allow  _INBOX.>
```

The broker config adds the projection above, a 15-minute `token_max_expiration`, an xkey, the scoped account, and one fallback binding (`{ user_account: APP, roles: [] }`), since the scope decides the rest. The client connects with both its tokens, as the broker already accepts them (`{"id_token": "…", "access_token": "…"}` in the CONNECT token).

Alice's connection reads her current groups from UserInfo and projects to the name `6f1c0e2a-…`, the tags `read:menu_prices`, `read:staff_rotas`, `role:head_chef`, `role:waiter` and `write:menu_prices`, and `fresh_until` 15 minutes ahead. The server expands the template into her two `cmd` subjects and the consumer subjects for her two streams. The same token twice in a subject (`{{tag(read)}}`) is replaced consistently, because the server substitutes every occurrence of a token's text at once (the `strings.Replace(…, -1)` in `applyTemplate`, `auth.go`); the mismatched pairs come out as duplicates and count against the cap.

Bob's credential has no subject naming Alice and none naming `head_chef`. A person with no `write:` group, or no `role:` group, gets no `cmd` subject at all, and can still read. When Alice is taken out of `write:menu_prices` and her connection is killed, her client reconnects, UserInfo no longer lists the group, and her new credential has no `cmd` subject.

## What else it serves

The projection separates the shape of an IdP's claims from the shape of NATS permissions, which is useful well beyond this case:

- **Several IdPs, one rule.** Keycloak's `realm_access.roles`, Entra's `roles` and `pocket-id`'s `groups` each project to the same tag keys, so one scope template serves all of them, with names kept apart by `idp.key`.
- **Tenants.** A restaurant group gives each site a subtree: `{{tag(site)}}.orders.>` from a `site` claim, with no binding per site.
- **Connection type.** `connection.type` can become a tag, so a template can give browser connections (`websocket`) narrower subjects than services, using a fact the server vouches for.
- **Machine identities.** Where the IdP issues a service a token the broker accepts, it projects by the same rules as a person, so a nightly supplier feed is named and tagged like anyone else.
- **Operations.** The connection's `authorized_user` is the projected name (item 3), which connection listings report and filter on (`ConnzOptions.User`, `monitor.go:93`). Taken from `sub`, it names the person, so tooling that disconnects someone after a permission change can find their connections.

## Alternatives considered

- **Copying prefixed groups into tags, with a separate setting for the name.** It ties tag keys to how an IdP names its groups, cannot read nested or non-group claims, has nowhere to say how old the claims may be, and writes the same checks twice.
- **Go templates with `range`.** They produce text, so the output has no type and no single place to validate it, and they would need item 2 rewritten.
- **A `union` binding strategy that collates every matching binding.** It helps deployments without scoped keys, but a binding per table can only grant `cmd.menu_prices.{{ .user.name }}.*`, and the last token then accepts any role. Restricting it needs the product of tables and roles, which only the server's templates compute.
- **Projecting permissions directly, with the projection emitting subjects.** That moves the authorization rule into the broker and duplicates role bindings, and gives up the server's expansion and its cap.
- **Bounding freshness by credential lifetime alone.** It is what the current design assumes, and items 7 and 8 show it bounds nothing while a client can present the same ID token again.

## Security considerations not solved here

- **A stolen token is a credential.** Whoever holds Alice's ID token, or both her tokens, can connect as her until they go stale. Freshness bounds that window, and nothing here binds a token to the connection that presents it.
- **The tokens travel in CONNECT.** Client connections must use TLS (`wss` for browsers), or the tokens can be read in transit. The `xkey_seed` requirement covers only the hop from server to broker.
- **The IdP's groups are the authority.** Whoever administers them grants access, and the `Token` and lowercase rules only stop a badly named group from granting more than it says.

## Tests to add upstream

- **Unit tests of `project`**, which can be table-driven because it is pure: each error kind; `capture` over a string, a list and a missing claim; uppercase and non-ASCII values refused; `fresh_until` taken from the oldest namespace read; ordering.
- **Property tests:**
  - every emitted value satisfies the `Token` rule, for any claims;
  - changing any `ConnectOptions` field never changes the output;
  - the same input always gives the same output;
  - `fresh_until` is never later than any read namespace's as-of time plus `max_claims_age`.
- **Load-time tests:**
  - a name rule that does not read `id_token.sub` is refused, as is one that does not read `idp.key` with two IdPs, and two IdPs sharing a `key`;
  - each refusal listed under "Scoped issuance".
- **Integration tests** against an embedded `nats-server` with a mock OIDC issuer, as `tests/integration` already does:
  - the worked case: Alice may publish her two `cmd` subjects, and is refused on a table she lacks, a role she lacks and Bob's name;
  - a `sub` of `>` is refused at connection;
  - an ID token issued longer ago than `max_claims_age` is refused, and a minted credential expires by `fresh_until`;
  - with rules reading `userinfo`: a connection without an access token is refused, as is one whose fetch fails or whose UserInfo `sub` differs; and a group removed at the mock issuer is gone from the next connection's tags while the ID token is still valid;
  - without `user_projection`, a minted user JWT has the same name, tags, permissions, limits and expiry as `v1.7.7` mints for the same token and config.

## Related findings, to file separately

These hold for configurations that do not use the projection, and are worth fixing on their own:

- **UserInfo's `sub` is not compared with the ID token's.** `GetUserInfo` (`internal/broker/idp_jwt_verifier.go:217`) checks `at_hash`, then the claims are merged with UserInfo's winning (`auth_callback.go`, `claims[k] = v`), including `sub`. OpenID Connect Core §5.3.2 requires the two to match exactly, and the UserInfo response to be discarded if they do not.
- **Item 6:** a claim templated into a subject is not checked. Rendered subjects could be validated as subjects before they are added, whatever their source.
- **Item 8:** with `user_info.enabled`, a missing access token or a failed fetch falls back to the ID token's claims, so the client decides whether its claims are current.
- **Item 7:** a token is accepted for `clock_skew` after it expires. A skew allowance should widen the window only for clocks that disagree, not extend a token's life.

package broker

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func projectionFixture(t *testing.T) (*UserProjection, VerifiedIdentity) {
	t.Helper()
	rules := &UserProjection{Name: "id_token.sub", MaxClaimsAge: Duration{15 * time.Minute}, Tags: []ProjectionTagRule{
		{Key: "write", Values: `capture(userinfo.groups, "^write:([a-z0-9_]+)$")`},
		{Key: "role", Values: `capture(userinfo.groups, "^role:([a-z0-9_]+)$")`, MaxValues: 16},
	}}
	require.NoError(t, rules.compile(false))
	now := time.Unix(1800000000, 0)
	identity := VerifiedIdentity{IDToken: map[string]interface{}{"sub": "alice"}, UserInfo: map[string]interface{}{
		"groups": []interface{}{"role:waiter", "write:menu_prices", "role:head_chef", "role:waiter"},
	}, IDP: map[string]interface{}{"key": "kitchen"}, IssuedAt: now.Add(-12 * time.Minute), VerifiedAt: now}
	return rules, identity
}

func TestUserProjectionWorkedCase(t *testing.T) {
	rules, identity := projectionFixture(t)
	user, err := rules.Project(identity)
	require.NoError(t, err)
	assert.Equal(t, "alice", user.Name)
	assert.Equal(t, []string{"role:head_chef", "role:waiter", "write:menu_prices"}, user.jwtTags())
	assert.Equal(t, identity.VerifiedAt.Add(3*time.Minute), user.FreshUntil)
	again, err := rules.Project(identity)
	require.NoError(t, err)
	assert.Equal(t, user, again)
	// No grant is the empty set, including a missing optional claim.
	identity.UserInfo = map[string]interface{}{}
	user, err = rules.Project(identity)
	require.NoError(t, err)
	assert.Empty(t, user.jwtTags())
	identity.UserInfo["groups"] = "write:menu_prices"
	user, err = rules.Project(identity)
	require.NoError(t, err)
	assert.Equal(t, []string{"write:menu_prices"}, user.jwtTags())
}

func TestUserProjectionRefusals(t *testing.T) {
	tests := []struct {
		name, kind string
		change     func(*UserProjection, *VerifiedIdentity)
	}{
		{"mustache name", "NotAToken", func(_ *UserProjection, i *VerifiedIdentity) { i.IDToken["sub"] = "{{tag(role)}}" }},
		{"wildcard name", "NotAToken", func(_ *UserProjection, i *VerifiedIdentity) { i.IDToken["sub"] = ">" }},
		{"dotted name", "NotAToken", func(_ *UserProjection, i *VerifiedIdentity) { i.IDToken["sub"] = "alice.example" }},
		{"unicode name", "NotAToken", func(_ *UserProjection, i *VerifiedIdentity) { i.IDToken["sub"] = "аlice" }},
		{"missing name", "Missing", func(_ *UserProjection, i *VerifiedIdentity) { i.IDToken["sub"] = "" }},
		{"wrong type name", "WrongType", func(_ *UserProjection, i *VerifiedIdentity) { i.IDToken["sub"] = []string{"alice"} }},
		{"missing userinfo", "Unavailable", func(_ *UserProjection, i *VerifiedIdentity) { i.UserInfo = nil }},
		{"stale", "Stale", func(_ *UserProjection, i *VerifiedIdentity) { i.IssuedAt = i.VerifiedAt.Add(-16 * time.Minute) }},
		{"exact expiry", "Stale", func(_ *UserProjection, i *VerifiedIdentity) { i.IssuedAt = i.VerifiedAt.Add(-15 * time.Minute) }},
		{"future iat", "Stale", func(_ *UserProjection, i *VerifiedIdentity) { i.IssuedAt = i.VerifiedAt.Add(time.Second) }},
		{"missing timestamp", "Missing", func(_ *UserProjection, i *VerifiedIdentity) { i.IssuedAt = time.Time{} }},
		{"uppercase tag", "NotAToken", func(r *UserProjection, _ *VerifiedIdentity) {
			r.Tags[0].Values = `"Menu_Prices"`
			require.NoError(t, r.compile(false))
		}},
		{"mustache tag", "NotAToken", func(r *UserProjection, _ *VerifiedIdentity) {
			r.Tags[0].Values = `"{{name()}}"`
			require.NoError(t, r.compile(false))
		}},
		{"wrong type tag", "WrongType", func(r *UserProjection, _ *VerifiedIdentity) {
			r.Tags[0].Values = `42`
			require.NoError(t, r.compile(false))
		}},
		{"minimum values", "Missing", func(r *UserProjection, i *VerifiedIdentity) {
			r.Tags[0].MinValues = 1
			i.UserInfo = map[string]interface{}{}
		}},
		{"maximum values", "TooMany", func(r *UserProjection, _ *VerifiedIdentity) { r.Tags[1].MaxValues = 1 }},
		{"total tags", "TooMany", func(r *UserProjection, _ *VerifiedIdentity) { r.MaxTags = 2 }},
		{"oversized input", "TooMany", func(_ *UserProjection, i *VerifiedIdentity) {
			i.IDToken["other"] = strings.Repeat("x", projectionMaxInputBytes)
		}},
		{"runtime evaluation", "Evaluation", func(r *UserProjection, _ *VerifiedIdentity) {
			r.Tags[0].Values = `digest(userinfo.groups)`
			require.NoError(t, r.compile(false))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, identity := projectionFixture(t)
			tt.change(rules, &identity)
			user, err := rules.Project(identity)
			require.Error(t, err)
			assert.Nil(t, user)
			var refusal *ProjectionError
			require.True(t, errors.As(err, &refusal))
			assert.Equal(t, tt.kind, refusal.Kind)
			assert.NotContains(t, err.Error(), "alice")
		})
	}
}

func TestUserProjectionCompileRestrictions(t *testing.T) {
	for _, source := range []string{
		`env("SECRET")`, `readFile("/etc/passwd")`, `now()`, `map(userinfo.groups, #)`,
		`userinfo[id_token.sub]`, `capture(userinfo.groups, id_token.pattern)`,
		`capture(userinfo.groups, "no-group")`, `capture(userinfo.groups, "(")`,
		`id_token.sub matches "(a+)"`, `1..999999`, `userinfo.groups[0:2]`,
	} {
		t.Run(source, func(t *testing.T) {
			rules, _ := projectionFixture(t)
			rules.Tags[0].Values = source
			require.Error(t, rules.compile(false))
		})
	}
	for _, name := range []string{`"alice"`, `id_token.sub[:1]`, `id_token.sub == "x" ? "alice" : "bob"`, `idp.key + id_token.sub`} {
		rules, _ := projectionFixture(t)
		rules.Name = name
		require.Error(t, rules.compile(false))
	}
	rules, _ := projectionFixture(t)
	require.Error(t, rules.compile(true))
	rules.Name = `idp.key + ":" + id_token.sub`
	require.NoError(t, rules.compile(true))
	rules.Name = `digest(idp.key + ":" + id_token.sub)`
	require.NoError(t, rules.compile(true))
	rules.MaxClaimsAge.Duration = 0
	require.Error(t, rules.compile(false))
	rules, _ = projectionFixture(t)
	rules.Tags[0].Key = "read:bad"
	require.Error(t, rules.compile(false))
}

func TestUserProjectionConservativeDependencies(t *testing.T) {
	rules, identity := projectionFixture(t)
	rules.Tags = []ProjectionTagRule{{Key: "role", Values: `true ? "reader" : userinfo.role`}}
	require.NoError(t, rules.compile(false))
	assert.True(t, rules.compiled.reads["userinfo"])
	identity.UserInfo = nil
	_, err := rules.Project(identity)
	require.Error(t, err)
}

func TestProjectedMinting(t *testing.T) {
	f := newTestFixture(t)
	rules, identity := projectionFixture(t)
	identity.VerifiedAt = time.Now()
	identity.IssuedAt = identity.VerifiedAt.Add(-12 * time.Minute)
	user, err := rules.Project(identity)
	require.NoError(t, err)
	idpClaims := &IdpJwtClaims{Subject: "untrusted-mapped-sub", Expiry: time.Now().Add(time.Hour).Unix(), signedExpiry: time.Now().Add(time.Hour).Unix(), projected: user}
	request := &jwt.AuthorizationRequestClaims{}
	request.UserNkey = f.userPub
	request.ConnectOptions.Username = "bob"
	result, _, _, _, err := buildUserClaims(f.ctx, f.config, f.configMgr, idpClaims, fakeIdpVerifier(), request)
	require.NoError(t, err)
	assert.Equal(t, "alice", result.Name)
	assert.Equal(t, user.jwtTags(), []string(result.Tags))
	assert.Equal(t, user.FreshUntil.Unix(), result.Expires)
	request.ConnectOptions.Username = "mallory"
	request.ConnectOptions.Name = "arbitrary client name"
	again, _, _, _, err := buildUserClaims(f.ctx, f.config, f.configMgr, idpClaims, fakeIdpVerifier(), request)
	require.NoError(t, err)
	assert.Equal(t, result.Name, again.Name)
	assert.Equal(t, result.Tags, again.Tags)
	f.config.Rbac.Accounts[0].Scoped = true
	result, _, _, _, err = buildUserClaims(f.ctx, f.config, f.configMgr, idpClaims, fakeIdpVerifier(), request)
	require.NoError(t, err)
	assert.True(t, result.HasEmptyPermissions())
	assert.Equal(t, user.FreshUntil.Unix(), result.Expires)

	// Mapped exp cannot extend the original signed token, including when the
	// configured minimum credential lifetime would otherwise be longer.
	idpClaims.Expiry = time.Now().Add(24 * time.Hour).Unix()
	idpClaims.signedExpiry = time.Now().Add(30 * time.Second).Unix()
	result, _, _, _, err = buildUserClaims(f.ctx, f.config, f.configMgr, idpClaims, fakeIdpVerifier(), request)
	require.NoError(t, err)
	assert.Equal(t, idpClaims.signedExpiry, result.Expires)
	idpClaims.signedExpiry = time.Now().Add(-time.Second).Unix()
	_, _, _, _, err = buildUserClaims(f.ctx, f.config, f.configMgr, idpClaims, fakeIdpVerifier(), request)
	require.Error(t, err)
}

func TestProjectionConfiguration(t *testing.T) {
	f := newTestFixture(t)
	content, err := os.ReadFile(f.tmpFile)
	require.NoError(t, err)
	content = []byte(strings.Replace(string(content), "- description: \"Test IDP\"", "- key: kitchen\n    description: \"Test IDP\"", 1))
	content = []byte(strings.Replace(string(content), "rbac:", `rbac:
  user_projection:
    name: id_token.sub
    max_claims_age: 15m
    tags:
      - key: example
        values: '"{{ .injected }}"'`, 1))
	require.NoError(t, os.WriteFile(f.tmpFile, content, 0o600))
	cm, err := NewConfigManager([]string{f.tmpFile})
	require.NoError(t, err)
	cfg, err := cm.GetConfig(map[string]interface{}{"injected": "reader"})
	require.NoError(t, err)
	assert.Equal(t, `"{{ .injected }}"`, cfg.Rbac.UserProjection.Tags[0].Values)
	assert.NotNil(t, cfg.Rbac.UserProjection.compiled)
	// Invalid rules fail load (and hence reject a hot reload).
	content = []byte(strings.Replace(string(content), "name: id_token.sub", "name: id_token.sub[:1]", 1))
	require.NoError(t, os.WriteFile(f.tmpFile, content, 0o600))
	_, err = NewConfigManager([]string{f.tmpFile})
	require.Error(t, err)
}

func TestScopedConfigurationRefusals(t *testing.T) {
	rules, _ := projectionFixture(t)
	xkey, err := nkeys.CreateCurveKeys()
	require.NoError(t, err)
	cfg := Config{Service: Service{Account: ServiceAccount{XKeySeed: NKey{KeyPair: xkey}}}, Idp: []Idp{{UserProjection: rules}}, Rbac: Rbac{
		Accounts: []UserAccountInfo{{Name: "APP", Scoped: true}}, RoleBinding: []RoleBinding{{Account: "APP"}},
	}}

	operator, err := nkeys.CreateOperator()
	require.NoError(t, err)
	operatorPub, err := operator.PublicKey()
	require.NoError(t, err)
	accountKey, err := nkeys.CreateAccount()
	require.NoError(t, err)
	accountPub, err := accountKey.PublicKey()
	require.NoError(t, err)
	signingKey, err := nkeys.CreateAccount()
	require.NoError(t, err)
	signingPub, err := signingKey.PublicKey()
	require.NoError(t, err)
	accountClaims := jwt.NewAccountClaims(accountPub)
	scope := jwt.NewUserScope()
	scope.Key = signingPub
	accountClaims.SigningKeys.AddScopedSigner(scope)
	accountJWT, err := accountClaims.Encode(operator)
	require.NoError(t, err)
	cfg.Rbac.Accounts[0].PublicKey = accountPub
	cfg.Rbac.Accounts[0].SigningNKey = NKey{KeyPair: signingKey}
	cfg.Rbac.Accounts[0].AccountJWT = accountJWT
	cfg.Rbac.Accounts[0].OperatorPublicKey = operatorPub
	require.NoError(t, cfg.validateScopedAccounts())
	cfg.Service.Account.XKeySeed = NKey{}
	require.Error(t, cfg.validateScopedAccounts())
	cfg.Service.Account.XKeySeed = NKey{KeyPair: xkey}
	cfg.Idp[0].UserProjection = nil
	require.Error(t, cfg.validateScopedAccounts())
	cfg.Idp[0].UserProjection = rules
	cfg.Idp[0].ValidationSpec.SkipAudienceValidation = true
	require.Error(t, cfg.validateScopedAccounts())
	cfg.Idp[0].ValidationSpec.SkipAudienceValidation = false
	cfg.Rbac.RoleBinding[0].Roles = []string{"role"}
	cfg.Rbac.Roles = []Role{{Name: "role", Permissions: Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"test.>"}}}}}
	require.Error(t, cfg.validateScopedAccounts())
	cfg.Rbac.Roles[0].Permissions = Permissions{}
	cfg.Rbac.Roles[0].Limits.NatsLimits.Payload = 1
	require.Error(t, cfg.validateScopedAccounts())
}

func TestProjectionDigestRequiresSubject(t *testing.T) {
	rules, identity := projectionFixture(t)
	rules.Name = "digest(id_token.sub)"
	require.NoError(t, rules.compile(false))
	identity.IDToken["sub"] = ""
	_, err := rules.Project(identity)
	require.Error(t, err)
}

func TestProjectionProviderOverrides(t *testing.T) {
	global, _ := projectionFixture(t)
	global.Name = `idp.key + ":" + id_token.sub`
	local, _ := projectionFixture(t)
	local.Name = `digest(idp.key + ":" + id_token.sub)`
	cfg := Config{Idp: []Idp{{Key: "first", UserProjection: local}, {Key: "second"}}, Rbac: Rbac{UserProjection: global}}
	require.NoError(t, cfg.compileProjections())
	cm := ConfigManager{baseConfig: cfg}
	assert.Same(t, local, cm.projection(&cfg.Idp[0]))
	assert.Same(t, global, cm.projection(&cfg.Idp[1]))
	cfg.Idp[1].Key = "first"
	require.Error(t, cfg.compileProjections())
	cfg.Idp[1].Key = ""
	require.Error(t, cfg.compileProjections())
}

func TestProjectedTemplateAndReservedClaim(t *testing.T) {
	f := newTestFixture(t)
	source, err := os.ReadFile(f.tmpFile)
	require.NoError(t, err)
	source = []byte(strings.ReplaceAll(string(source), `allow: ["test.>"]`, `allow: ["cmd.*.{{ .user.name }}.*"]`))
	source = []byte(strings.Replace(string(source), `roles: ["basic-role"]`, `roles: ["basic-role"]
      match:
        - expr: '"head_chef" in user.tags.role'`, 1))
	require.NoError(t, os.WriteFile(f.tmpFile, source, 0o600))
	cm, err := NewConfigManager([]string{f.tmpFile})
	require.NoError(t, err)
	rules, identity := projectionFixture(t)
	identity.VerifiedAt = time.Now()
	identity.IssuedAt = identity.VerifiedAt
	user, err := rules.Project(identity)
	require.NoError(t, err)
	claims := &IdpJwtClaims{Expiry: time.Now().Add(time.Hour).Unix(), signedExpiry: time.Now().Add(time.Hour).Unix(), projected: user,
		CustomClaims: map[string]interface{}{"user": map[string]interface{}{"name": "bob"}},
	}
	request := &jwt.AuthorizationRequestClaims{}
	request.UserNkey = f.userPub
	result, _, _, _, err := buildUserClaims(f.ctx, f.config, cm, claims, fakeIdpVerifier(), request)
	require.NoError(t, err)
	assert.Equal(t, jwt.StringList{"cmd.*.alice.*"}, result.Permissions.Pub.Allow)
}

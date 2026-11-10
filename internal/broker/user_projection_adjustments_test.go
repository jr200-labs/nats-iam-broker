package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jr200-labs/nats-iam-broker/internal/metrics"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func userInfoTestVerifier(t *testing.T, handler http.HandlerFunc) *IdpJwtVerifier {
	t.Helper()
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{"issuer": issuer, "jwks_uri": issuer + "/keys", "userinfo_endpoint": issuer + "/userinfo"}); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc("/userinfo", handler)
	server := httptest.NewServer(mux)
	issuer = server.URL
	t.Cleanup(server.Close)
	verifier, err := NewJwtVerifier(NewServerContext(&Options{}), "client", issuer, time.Hour, time.Minute)
	require.NoError(t, err)
	// Test the explicit optional-hash policy; the production constructor defaults strict.
	verifier.RequireAccessTokenHash = false
	return verifier
}

func TestUserInfoValidationAndBounds(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		status    int
		wantError bool
	}{
		{"optional at_hash", `{"sub":"alice","groups":["read:menu_prices"]}`, http.StatusOK, false},
		{"different subject", `{"sub":"bob","secret":"sensitive-marker"}`, http.StatusOK, true},
		{"missing subject", `{"groups":["admin"]}`, http.StatusOK, true},
		{"provider failure", `sensitive-marker`, http.StatusServiceUnavailable, true},
		{"oversized", strings.Repeat("x", projectionMaxInputBytes+1), http.StatusOK, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			v := userInfoTestVerifier(t, func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "Bearer alice-access", r.Header.Get("Authorization"))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, err := io.WriteString(w, tt.body)
				if err != nil {
					t.Error(err)
				}
			})
			info, err := v.GetUserInfo(context.Background(), "alice-access", &oidc.IDToken{Subject: "alice"})
			if tt.wantError {
				require.Error(t, err)
				assert.Nil(t, info)
				assert.NotContains(t, err.Error(), "sensitive-marker")
			} else {
				require.NoError(t, err)
				assert.Equal(t, "alice", info["sub"])
			}
		})
	}
	v := userInfoTestVerifier(t, func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := v.GetUserInfo(ctx, "alice-access", &oidc.IDToken{Subject: "alice"})
	require.Error(t, err)
	_, err = v.GetUserInfo(context.Background(), "", &oidc.IDToken{Subject: "alice"})
	require.Error(t, err)
	_, err = v.GetUserInfo(context.Background(), "access", nil)
	require.Error(t, err)
}

func TestUserInfoBodyLimitExactAndStreaming(t *testing.T) {
	for _, size := range []int{projectionMaxInputBytes, projectionMaxInputBytes + 1} {
		body := &limitedUserInfoBody{ReadCloser: io.NopCloser(strings.NewReader(strings.Repeat("x", size))), remaining: projectionMaxInputBytes}
		data, err := io.ReadAll(body)
		assert.LessOrEqual(t, len(data), projectionMaxInputBytes)
		if size == projectionMaxInputBytes {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
	v := userInfoTestVerifier(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.(http.Flusher).Flush() // chunked response has no trusted Content-Length
		_, _ = io.WriteString(w, strings.Repeat("x", projectionMaxInputBytes+1))
	})
	_, err := v.GetUserInfo(context.Background(), "access", &oidc.IDToken{Subject: "alice"})
	require.Error(t, err)
}

func TestRenderedPermissionValidation(t *testing.T) {
	for _, subject := range []string{"cmd.*.alice.*", "_INBOX.>", "events.> workers", "events.* worker.*"} {
		permissions := jwt.Permissions{Sub: jwt.Permission{Allow: jwt.StringList{subject}}}
		require.NoError(t, validateRenderedPermissions(&permissions), subject)
	}
	for _, subject := range []string{"", "a..b", ".a", "a.", "a.>.b", "a.*tail", "a.>\n", "a.\x00", "a.{{.name}}", "events.> workers extra"} {
		permissions := jwt.Permissions{Sub: jwt.Permission{Allow: jwt.StringList{subject}}}
		require.Error(t, validateRenderedPermissions(&permissions), subject)
	}
	permissions := jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{"events.> workers"}}}
	require.Error(t, validateRenderedPermissions(&permissions))
}

func TestProjectionReloadRetainsValidSnapshots(t *testing.T) {
	v := userInfoTestVerifier(t, func(http.ResponseWriter, *http.Request) {})
	f := newTestFixture(t)
	source, err := os.ReadFile(f.tmpFile)
	require.NoError(t, err)
	base := strings.Replace(string(source), `https://test.idp`, v.issuerURL, 1)
	base = strings.Replace(base, `- description: "Test IDP"`, `- key: kitchen
    description: "Test IDP"`, 1)
	base = strings.Replace(base, "rbac:", `rbac:
  user_projection:
    name: id_token.sub
    max_claims_age: 15m`, 1)
	require.NoError(t, os.WriteFile(f.tmpFile, []byte(base), 0o600))
	initial := newTestLiveState(t, f.tmpFile)
	watcher := NewConfigWatcher(f.ctx, []string{f.tmpFile}, initial)
	_, identity := projectionFixture(t)
	identity.VerifiedAt = time.Now()
	identity.IssuedAt = identity.VerifiedAt.Add(-3 * time.Minute)
	old, err := initial.config.Rbac.UserProjection.Project(identity)
	require.NoError(t, err)
	broken := strings.Replace(base, "name: id_token.sub", "name: id_token.sub[:1]", 1)
	require.NoError(t, os.WriteFile(f.tmpFile, []byte(broken), 0o600))
	require.Error(t, watcher.reload())
	assert.Same(t, initial, watcher.State())
	updated := strings.Replace(base, "max_claims_age: 15m", "max_claims_age: 5m", 1)
	require.NoError(t, os.WriteFile(f.tmpFile, []byte(updated), 0o600))
	require.NoError(t, watcher.reload())
	assert.NotSame(t, initial, watcher.State())
	fresh, err := watcher.State().config.Rbac.UserProjection.Project(identity)
	require.NoError(t, err)
	assert.Equal(t, identity.VerifiedAt.Add(2*time.Minute), fresh.FreshUntil)
	unchanged, err := initial.config.Rbac.UserProjection.Project(identity)
	require.NoError(t, err)
	assert.Equal(t, old, unchanged)
}

func TestProjectionErrorDetailsAndMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewWithRegisterer(reg)
	logCore, logs := observer.New(zap.WarnLevel)
	restore := zap.ReplaceGlobals(zap.New(logCore))
	defer restore()
	rules, identity := projectionFixture(t)
	rules.MaxTags = 2
	_, err := rules.Project(identity)
	var refusal *ProjectionError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, 3, refusal.Count)
	assert.Equal(t, 2, refusal.Max)
	recordProjectionRefusal(m, "kitchen", refusal)
	families, err := reg.Gather()
	require.NoError(t, err)
	found := false
	for _, family := range families {
		if family.GetName() == "nats_iam_broker_user_projection_errors_total" {
			require.Len(t, family.Metric, 1)
			assert.Equal(t, float64(1), family.Metric[0].Counter.GetValue())
			labels := map[string]string{}
			for _, label := range family.Metric[0].Label {
				labels[label.GetName()] = label.GetValue()
			}
			assert.Equal(t, map[string]string{"idp": "kitchen", "kind": "TooMany"}, labels)
			found = true
		}
	}
	require.True(t, found)
	require.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	assert.NotContains(t, fmt.Sprint(entry.ContextMap()), "alice")
	identity.IssuedAt = identity.VerifiedAt.Add(-16 * time.Minute)
	_, err = rules.Project(identity)
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, "id_token", refusal.Namespace)
	assert.Equal(t, identity.IssuedAt, refusal.AsOf)
}

func TestScopedSignerArtifactValidation(t *testing.T) {
	operator, err := nkeys.CreateOperator()
	require.NoError(t, err)
	operatorPub, err := operator.PublicKey()
	require.NoError(t, err)
	accountKP, err := nkeys.CreateAccount()
	require.NoError(t, err)
	accountPub, err := accountKP.PublicKey()
	require.NoError(t, err)
	signing, err := nkeys.CreateAccount()
	require.NoError(t, err)
	signingPub, err := signing.PublicKey()
	require.NoError(t, err)
	claims := jwt.NewAccountClaims(accountPub)
	scope := jwt.NewUserScope()
	scope.Key = signingPub
	claims.SigningKeys.AddScopedSigner(scope)
	artifact, err := claims.Encode(operator)
	require.NoError(t, err)
	account := UserAccountInfo{Scoped: true, PublicKey: accountPub, SigningNKey: NKey{KeyPair: signing}, AccountJWT: artifact, OperatorPublicKey: operatorPub}
	require.NoError(t, account.validateScopedSigner())

	chunks := strings.Split(artifact, ".")
	prefix := "A"
	if chunks[2][0] == 'A' {
		prefix = "B"
	}
	chunks[2] = prefix + chunks[2][1:]
	account.AccountJWT = strings.Join(chunks, ".")
	require.Error(t, account.validateScopedSigner())
	account.AccountJWT = artifact
	account.AccountJWT = ""
	require.Error(t, account.validateScopedSigner())
	account.AccountJWT = artifact
	account.OperatorPublicKey = accountPub
	require.Error(t, account.validateScopedSigner())
	account.OperatorPublicKey = operatorPub
	otherOperator, err := nkeys.CreateOperator()
	require.NoError(t, err)
	otherPub, err := otherOperator.PublicKey()
	require.NoError(t, err)
	account.OperatorPublicKey = otherPub
	require.Error(t, account.validateScopedSigner())
	account.OperatorPublicKey = operatorPub
	account.PublicKey = signingPub
	require.Error(t, account.validateScopedSigner())
	account.PublicKey = accountPub
	unscoped := jwt.NewAccountClaims(accountPub)
	unscoped.SigningKeys.Add(signingPub)
	account.AccountJWT, err = unscoped.Encode(operator)
	require.NoError(t, err)
	require.Error(t, account.validateScopedSigner())
	claims.Expires = time.Now().Add(-time.Minute).Unix()
	account.AccountJWT, err = claims.Encode(operator)
	require.NoError(t, err)
	require.Error(t, account.validateScopedSigner())
}

func TestExpirySkewNeverExtendsToken(t *testing.T) {
	v := IdpJwtVerifier{MaxTokenLifetime: time.Hour, ClockSkew: 5 * time.Minute}
	err := v.ValidateTimes(time.Now().Add(-time.Minute), time.Unix(time.Now().Unix(), 0))
	require.Error(t, err)
}

func TestProjectionHelperErrorsAreTyped(t *testing.T) {
	rules, identity := projectionFixture(t)
	identity.UserInfo["groups"] = []interface{}{42}
	_, err := rules.Project(identity)
	var refusal *ProjectionError
	require.True(t, errors.As(err, &refusal))
	assert.Equal(t, "Evaluation", refusal.Kind)
}

func TestUserInfoRedirectDoesNotForwardCredentials(t *testing.T) {
	var calls atomic.Int64
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(http.StatusOK) }))
	defer sink.Close()
	verifier := userInfoTestVerifier(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, sink.URL, http.StatusFound) })
	_, err := verifier.GetUserInfo(context.Background(), "private-access", &oidc.IDToken{Subject: "alice"})
	require.Error(t, err)
	assert.Equal(t, int64(0), calls.Load())
}

func TestAggregateProjectionWorkIsBounded(t *testing.T) {
	rules, _ := projectionFixture(t)
	rules.Tags = nil
	for i := 0; i < 128; i++ {
		rules.Tags = append(rules.Tags, ProjectionTagRule{Key: fmt.Sprintf("grant%d", i), Values: `capture(userinfo.groups, "^write:([a-z0-9_]+)$")`})
	}
	require.NoError(t, rules.compile(false))
	_, identity := projectionFixture(t)
	identity.UserInfo["padding"] = strings.Repeat("x", 60000)
	_, err := rules.Project(identity)
	var refusal *ProjectionError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, "work", refusal.Output)
	assert.Greater(t, refusal.Count, refusal.Max)
}

func TestUserInfoAtHashPolicyDefaultsStrict(t *testing.T) {
	verifier := userInfoTestVerifier(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"sub":"alice"}`) })
	verifier.RequireAccessTokenHash = true
	_, err := verifier.GetUserInfo(context.Background(), "access", &oidc.IDToken{Subject: "alice"})
	require.ErrorContains(t, err, "hash required")
	disabled := false
	cfg := Config{Idp: []Idp{{IssuerURL: verifier.issuerURL, ClientID: "client", UserInfo: UserInfoConfig{RequireAtHash: &disabled}}}}
	verifiers, err := NewIdpVerifiers(NewServerContext(&Options{}), &cfg)
	require.NoError(t, err)
	require.Len(t, verifiers, 1)
	assert.False(t, verifiers[0].verifier.RequireAccessTokenHash)
	cfg.Idp[0].UserInfo.RequireAtHash = nil
	verifiers, err = NewIdpVerifiers(NewServerContext(&Options{}), &cfg)
	require.NoError(t, err)
	assert.True(t, verifiers[0].verifier.RequireAccessTokenHash)
}

func TestNullIdentityListsRemainMissingClaims(t *testing.T) {
	claims := &IdpJwtClaims{Groups: []string{"old"}, Roles: []string{"old"}}
	require.NotPanics(t, func() { claims.fromMap(map[string]interface{}{"sub": "alice", "groups": nil, "roles": nil}, nil) })
	assert.Nil(t, claims.Groups)
	assert.Nil(t, claims.Roles)
	rules, identity := projectionFixture(t)
	identity.UserInfo = map[string]interface{}{"groups": nil}
	user, err := rules.Project(identity)
	require.NoError(t, err)
	assert.Empty(t, user.jwtTags())
}

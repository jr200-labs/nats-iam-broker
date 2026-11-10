//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserProjectionScopedCallout(t *testing.T) {
	cluster := SetupTestCluster(t)
	oidc := SetupMockOIDC(t)
	var mu sync.Mutex
	groups := []string{"write:menu_prices", "role:head_chef", "role:waiter"}
	subject := "alice"
	status := http.StatusOK
	fetches := 0
	oidc.UserInfoHandler = func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fetches++
		if r.Header.Get("Authorization") != "Bearer alice-access" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{"sub": subject, "groups": groups}); err != nil {
			t.Error(err)
		}
	}
	// Scope is installed in the real server's account state, not simulated by tests.
	appClaims := jwt.NewAccountClaims(cluster.AppAccount.AccountPub)
	appClaims.Name = "APP1"
	scope := jwt.NewUserScope()
	scope.Key = cluster.AppAccount.SigningPub
	scope.Template.Pub.Allow.Add("cmd.{{tag(write)}}.{{name()}}.{{tag(role)}}")
	scope.Template.Sub.Allow.Add("_INBOX.>")
	appClaims.SigningKeys.AddScopedSigner(scope)
	accountJWT, err := appClaims.Encode(cluster.OperatorKP)
	require.NoError(t, err)
	require.NoError(t, cluster.Server.AccountResolver().Store(cluster.AppAccount.AccountPub, accountJWT))
	account, err := cluster.Server.LookupAccount(cluster.AppAccount.AccountPub)
	require.NoError(t, err)
	cluster.Server.UpdateAccountClaims(account, appClaims)

	setupBroker(t, cluster, oidc, func(files []string) {
		idp, err := os.ReadFile(files[1])
		require.NoError(t, err)
		idp = []byte(strings.Replace(string(idp), `- description: "Mock IDP"`, `- key: kitchen
    custom_mapping:
      external_sub: sub
    description: "Mock IDP"`, 1))
		idp = []byte(strings.Replace(string(idp), "skip_audience_validation: true", "skip_audience_validation: false", 1))
		require.NoError(t, os.WriteFile(files[1], idp, 0o600))
		seed, err := cluster.AppAccount.SigningKP.Seed()
		require.NoError(t, err)
		rbac := fmt.Sprintf(`rbac:
  token_max_expiration: 15m
  user_projection:
    name: id_token.sub
    max_claims_age: 15m
    tags:
      - key: write
        values: 'capture(userinfo.groups, "^write:([a-z0-9_]+)$")'
      - key: role
        values: 'capture(userinfo.groups, "^role:([a-z0-9_]+)$")'
  user_accounts:
    - name: APP1
      public_key: "%s"
      signing_nkey: "%s"
      scoped: true
  role_binding:
    - user_account: APP1
      roles: []
      match:
        - expr: '"waiter" in user.tags.role'
`, cluster.AppAccount.AccountPub, string(seed))
		require.NoError(t, os.WriteFile(files[2], []byte(rbac), 0o600))
	})
	hash := sha256.Sum256([]byte("alice-access"))
	claims := map[string]interface{}{
		"sub": "alice", "aud": "mockclientid", "external_sub": "bob",
		"groups":  []string{"write:forged_table"},
		"at_hash": base64.RawURLEncoding.EncodeToString(hash[:16]),
	}
	token := oidc.MintIDToken(claims)
	encoded, err := json.Marshal(map[string]string{"id_token": token, "access_token": "alice-access"})
	require.NoError(t, err)
	connect := func(raw string) (*nats.Conn, chan error, error) {
		errs := make(chan error, 8)
		nc, err := nats.Connect(cluster.URL, nats.UserCredentials(cluster.MintAccount.Users["nobody"].CredsFile), nats.Token(raw), nats.UserInfo("mallory", ""), nats.MaxReconnects(0), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { errs <- err }))
		return nc, errs, err
	}
	nc, errs, err := connect(string(encoded))
	require.NoError(t, err)
	defer nc.Close()
	assertPublish := func(subject string, denied bool) {
		t.Helper()
		require.NoError(t, nc.Publish(subject, []byte("test")))
		require.NoError(t, nc.Flush())
		if denied {
			select {
			case err := <-errs:
				assert.Contains(t, err.Error(), "Permissions Violation")
			case <-time.After(time.Second):
				t.Fatal("expected permission refusal for " + subject)
			}
		} else {
			select {
			case err := <-errs:
				t.Fatal(err)
			default:
			}
		}
	}
	assertPublish("cmd.menu_prices.alice.head_chef", false)
	assertPublish("cmd.menu_prices.alice.waiter", false)
	assertPublish("cmd.menu_prices.bob.waiter", true)
	assertPublish("cmd.menu_prices.mallory.waiter", true)
	assertPublish("cmd.other_table.alice.waiter", true)
	assertPublish("cmd.menu_prices.alice.admin", true)
	assertPublish("cmd.forged_table.alice.waiter", true)
	nc.Close()
	// Reuse the exact same ID/access tokens after the group change.
	mu.Lock()
	groups = []string{"role:waiter"}
	mu.Unlock()
	nc, errs, err = connect(string(encoded))
	require.NoError(t, err)
	defer nc.Close()
	assertPublish("cmd.menu_prices.alice.waiter", true)
	mu.Lock()
	assert.GreaterOrEqual(t, fetches, 2)
	mu.Unlock()
	nc.Close()

	// Required UserInfo never falls back to the ID-token claims.
	bad, _, err := connect(token)
	if bad != nil {
		bad.Close()
	}
	require.Error(t, err)
	mu.Lock()
	subject = "bob"
	mu.Unlock()
	bad, _, err = connect(string(encoded))
	if bad != nil {
		bad.Close()
	}
	require.Error(t, err)

	// Old signed claims are refused even when the UserInfo response is current.
	mu.Lock()
	subject = "alice"
	mu.Unlock()
	staleToken := oidc.MintIDToken(map[string]interface{}{
		"sub": "alice", "aud": "mockclientid", "iat": time.Now().Add(-16 * time.Minute).Unix(),
		"at_hash": base64.RawURLEncoding.EncodeToString(hash[:16]),
	})
	staleEncoded, err := json.Marshal(map[string]string{"id_token": staleToken, "access_token": "alice-access"})
	require.NoError(t, err)
	bad, _, err = connect(string(staleEncoded))
	if bad != nil {
		bad.Close()
	}
	require.Error(t, err)
	// A wildcard subject is refused even if the IdP vouches for that exact subject.
	mu.Lock()
	subject = ">"
	mu.Unlock()
	unsafeToken := oidc.MintIDToken(map[string]interface{}{
		"sub": ">", "aud": "mockclientid", "at_hash": base64.RawURLEncoding.EncodeToString(hash[:16]),
	})
	unsafeEncoded, err := json.Marshal(map[string]string{"id_token": unsafeToken, "access_token": "alice-access"})
	require.NoError(t, err)
	bad, _, err = connect(string(unsafeEncoded))
	if bad != nil {
		bad.Close()
	}
	require.Error(t, err)
	mu.Lock()
	subject = "alice"
	status = http.StatusServiceUnavailable
	mu.Unlock()
	bad, _, err = connect(string(encoded))
	if bad != nil {
		bad.Close()
	}
	require.Error(t, err)
}

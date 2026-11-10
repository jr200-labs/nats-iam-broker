//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLegacyUserInfoRequiresMatchingCurrentIdentity(t *testing.T) {
	cluster := SetupTestCluster(t)
	oidc := SetupMockOIDC(t)
	var mu sync.Mutex
	subject := "bob@acme.com"
	status := http.StatusOK
	oidc.UserInfoHandler = func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			if err := json.NewEncoder(w).Encode(map[string]interface{}{"sub": subject}); err != nil {
				t.Error(err)
			}
		} else {
			_, _ = w.Write([]byte("sensitive-provider-error"))
		}
	}
	setupBroker(t, cluster, oidc, func(files []string) {
		idp, err := os.ReadFile(files[1])
		require.NoError(t, err)
		idp = []byte(strings.Replace(string(idp), `- description: "Mock IDP"`, `- user_info:
      enabled: true
      require_at_hash: false
    description: "Mock IDP"`, 1))
		require.NoError(t, os.WriteFile(files[1], idp, 0o600))
	})
	// Explicit optional at_hash policy supports code-flow ID tokens. Exact provider/subject
	// verification still binds the returned claims to the verified identity.
	token := oidc.MintIDToken(map[string]interface{}{"sub": "bob@acme.com", "aud": "mockclientid"})
	encoded, err := json.Marshal(map[string]string{"id_token": token, "access_token": "access"})
	require.NoError(t, err)
	nc, err := cluster.ConnectWithToken(t, string(encoded))
	require.NoError(t, err)
	nc.Close()
	bad, err := cluster.ConnectWithToken(t, token)
	if bad != nil {
		bad.Close()
	}
	require.Error(t, err)
	mu.Lock()
	subject = "alice@acme.com"
	mu.Unlock()
	bad, err = cluster.ConnectWithToken(t, string(encoded))
	if bad != nil {
		bad.Close()
	}
	require.Error(t, err)
	mu.Lock()
	subject = "bob@acme.com"
	status = http.StatusServiceUnavailable
	mu.Unlock()
	bad, err = cluster.ConnectWithToken(t, string(encoded))
	if bad != nil {
		bad.Close()
	}
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "sensitive-provider-error")
	mu.Lock()
	status = http.StatusOK
	mu.Unlock()
	// A present but incorrect hash must never be treated as an absent optional hash.
	badHashToken := oidc.MintIDToken(map[string]interface{}{"sub": "bob@acme.com", "aud": "mockclientid", "at_hash": "incorrect"})
	badHashEncoded, err := json.Marshal(map[string]string{"id_token": badHashToken, "access_token": "access"})
	require.NoError(t, err)
	bad, err = cluster.ConnectWithToken(t, string(badHashEncoded))
	if bad != nil {
		bad.Close()
	}
	require.Error(t, err)
}

func TestLegacyMalformedRenderedSubjectRefused(t *testing.T) {
	cluster := SetupTestCluster(t)
	oidc := SetupMockOIDC(t)
	setupBroker(t, cluster, oidc, func(files []string) {
		source, err := os.ReadFile(files[2])
		require.NoError(t, err)
		source = []byte(strings.ReplaceAll(string(source), `"test.>"`, `"basic.{{ .preferred_username }}"`))
		require.NoError(t, os.WriteFile(files[2], source, 0o600))
	})
	token := oidc.MintIDToken(map[string]interface{}{"sub": "alice", "aud": "mockclientid", "preferred_username": ">.tail"})
	bad, err := cluster.ConnectWithToken(t, token)
	if bad != nil {
		bad.Close()
	}
	require.Error(t, err)
	token = oidc.MintIDToken(map[string]interface{}{"sub": "alice", "aud": "mockclientid", "preferred_username": "alice"})
	nc, err := cluster.ConnectWithToken(t, token)
	require.NoError(t, err)
	nc.Close()
}

//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignedClaimsAuthoritativeThroughAuthPipeline(t *testing.T) {
	for _, projected := range []bool{false, true} {
		t.Run(fmt.Sprintf("projection=%t", projected), func(t *testing.T) {
			cluster := SetupTestCluster(t)
			provider := SetupMockOIDC(t)
			provider.UserInfoHandler = func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]interface{}{"sub": "alice", "iat": 1, "exp": 1900000000, "groups": []string{"role:reader"}}); err != nil {
					t.Error(err)
				}
			}
			setupBroker(t, cluster, provider, func(files []string) {
				idp := fmt.Sprintf(`idp:
  - key: kitchen
    issuer_url: "%s"
    client_id: mockclientid
    custom_mapping:
      external_sub: sub
      external_iat: iat
      external_exp: exp
    user_info:
      enabled: true
      require_at_hash: false
`, provider.IssuerURL)
				require.NoError(t, os.WriteFile(files[1], []byte(idp), 0o600))
				projection := ""
				if projected {
					projection = `  user_projection:
    name: id_token.sub
    max_claims_age: 15m
    tags:
      - key: role
        values: 'capture(userinfo.groups, "^role:([a-z0-9_]+)$")'
`
				}
				seed, err := cluster.AppAccount.SigningKP.Seed()
				require.NoError(t, err)
				rbac := fmt.Sprintf(`rbac:
%s  role_binding_matching_strategy: strict
  user_accounts:
    - name: APP1
      public_key: "%s"
      signing_nkey: "%s"
  role_binding:
    - user_account: APP1
      roles: [reader]
      match:
        - expr: 'sub == "alice" && iat > 1 && exp - iat == 3600'
  roles:
    - name: reader
      permissions:
        pub:
          allow: ["protected.{{ .sub }}"]
        sub:
          allow: ["protected.{{ .sub }}"]
`, projection, cluster.AppAccount.AccountPub, string(seed))
				require.NoError(t, os.WriteFile(files[2], []byte(rbac), 0o600))
			})
			token := provider.MintIDToken(map[string]interface{}{"sub": "alice", "aud": "mockclientid",
				"external_sub": "mallory", "external_iat": 1, "external_exp": 1900000000})
			credential, err := json.Marshal(map[string]string{"id_token": token, "access_token": "access"})
			require.NoError(t, err)
			nc, err := cluster.ConnectWithToken(t, string(credential))
			require.NoError(t, err)
			defer nc.Close()
			sub, err := nc.SubscribeSync("protected.alice")
			require.NoError(t, err)
			require.NoError(t, nc.Flush())
			require.NoError(t, nc.Publish("protected.alice", []byte("verified")))
			require.NoError(t, nc.Flush())
			message, err := sub.NextMsg(time.Second)
			require.NoError(t, err)
			assert.Equal(t, "verified", string(message.Data))
		})
	}
}

func TestMixedProvidersCannotUseRawUserAsProjection(t *testing.T) {
	cluster := SetupTestCluster(t)
	provider := SetupMockOIDC(t)
	setupBroker(t, cluster, provider, func(files []string) {
		idp := fmt.Sprintf(`idp:
  - key: projected
    issuer_url: "%s"
    client_id: mockclientid
    user_projection:
      name: 'idp.key + ":" + id_token.sub'
      max_claims_age: 15m
      tags:
        - key: role
          values: '"head_chef"'
  - key: legacy
    issuer_url: "%s"
    client_id: legacyclient
`, provider.IssuerURL, provider.IssuerURL)
		require.NoError(t, os.WriteFile(files[1], []byte(idp), 0o600))
		seed, err := cluster.AppAccount.SigningKP.Seed()
		require.NoError(t, err)
		rbac := fmt.Sprintf(`rbac:
  role_binding_matching_strategy: strict
  user_accounts:
    - name: APP1
      public_key: "%s"
      signing_nkey: "%s"
  role_binding:
    - user_account: APP1
      roles: [projected-role]
      match:
        - expr: '"head_chef" in user.tags.role'
  roles:
    - name: projected-role
      permissions:
        pub:
          allow: ["basic.{{ .user.name }}"]
        sub:
          allow: ["basic.{{ .user.name }}"]
`, cluster.AppAccount.AccountPub, string(seed))
		require.NoError(t, os.WriteFile(files[2], []byte(rbac), 0o600))
	})
	rawUser := map[string]interface{}{"name": ">", "tags": map[string]interface{}{"role": []string{"head_chef"}}}
	projected := provider.MintIDToken(map[string]interface{}{"sub": "alice", "aud": "mockclientid", "user": rawUser})
	nc, err := cluster.ConnectWithToken(t, projected)
	require.NoError(t, err)
	nc.Close()
	legacy := provider.MintIDToken(map[string]interface{}{"sub": "alice", "aud": "legacyclient", "user": rawUser})
	nc, err = cluster.ConnectWithToken(t, legacy)
	if nc != nil {
		nc.Close()
	}
	require.Error(t, err, "a provider without projection cannot supply its own projected user")
}

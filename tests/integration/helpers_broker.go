//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/require"
)

// TestBroker represents a running broker instance for integration testing.
type TestBroker struct {
	ConfigFiles []string
	Done        chan error
	cancel      context.CancelFunc
}

// SetupBroker writes config files and starts the broker in a goroutine.
// It returns once the broker's micro service is registered on $SYS.REQ.USER.AUTH.
func SetupBroker(t *testing.T, cluster *TestCluster, oidc *MockOIDC) *TestBroker {
	return setupBroker(t, cluster, oidc, nil)
}

func setupBroker(t *testing.T, cluster *TestCluster, oidc *MockOIDC, configure func([]string)) *TestBroker {
	t.Helper()

	// Write account keys to files
	_, appSigningKeyFile := cluster.WriteAccountKeys(t, cluster.AppAccount)

	// Write MINT signing key for the service account config
	mintSigningSeed, err := cluster.MintAccount.SigningKP.Seed()
	require.NoError(t, err)

	// Write xkey
	xkeySeed, err := cluster.XKeyPair.Seed()
	require.NoError(t, err)

	configDir := filepath.Join(cluster.Dir, "configs")
	require.NoError(t, os.MkdirAll(configDir, 0o755))

	// Write env config
	envConfig := fmt.Sprintf(`nats:
  url: "%s"
  jwt_expiry_bounds:
    min: 1m
    max: 1h
service:
  name: "test-iam-broker"
  description: "Integration Test IAM Broker"
  version: "0.0.1"
  creds_file: "%s"
  account:
    name: "MINT"
    signing_nkey: "%s"
    xkey_seed: "%s"
`, cluster.URL, cluster.MintAccount.Users["minter"].CredsFile,
		string(mintSigningSeed), string(xkeySeed))

	envFile := filepath.Join(configDir, "env.yaml")
	require.NoError(t, os.WriteFile(envFile, []byte(envConfig), 0o644))

	// Write IDP config
	idpConfig := fmt.Sprintf(`idp:
  - description: "Mock IDP"
    issuer_url: "%s"
    client_id: "mockclientid"
    max_token_lifetime: 24h
    clock_skew: 5m
    validation:
      skip_audience_validation: true
`, oidc.IssuerURL)

	idpFile := filepath.Join(configDir, "idp.yaml")
	require.NoError(t, os.WriteFile(idpFile, []byte(idpConfig), 0o644))

	// Read the APP signing key seed for inline config
	appSigningKeySeed, err := os.ReadFile(appSigningKeyFile)
	require.NoError(t, err)

	// Write RBAC config
	rbacConfig := fmt.Sprintf(`rbac:
  user_accounts:
    - name: APP1
      public_key: "%s"
      signing_nkey: "%s"

  role_binding:
    - user_account: APP1
      match:
        - { claim: sub, value: bob@acme.com }
      roles:
        - can-pubsub
        - streaming

    - user_account: APP1
      match:
        - { claim: aud, value: mockclientid }
      roles:
        - can-pubsub

  roles:
    - name: can-pubsub
      permissions:
        pub:
          allow:
            - "test.>"
        sub:
          allow:
            - "test.>"

    - name: streaming
      permissions:
        sub:
          allow:
            - "$JS.API.>"
            - "_INBOX.>"
        pub:
          allow:
            - "$JS.API.STREAM.CREATE.test_stream"
            - "$JS.API.STREAM.UPDATE.test_stream"
            - "$JS.API.STREAM.INFO.test_stream"
            - "$JS.API.STREAM.DELETE.test_stream"
            - "$JS.API.CONSUMER.CREATE.test_stream.>"
            - "$JS.API.CONSUMER.MSG.NEXT.test_stream.>"
            - "$JS.API.CONSUMER.INFO.test_stream.>"
            - "$JS.API.CONSUMER.DELETE.test_stream.>"
            - "test.stream.>"
        resp:
          max_msgs: 1
          exp:
            max: 1h
      limits:
        data: 65536
`, cluster.AppAccount.AccountPub, string(appSigningKeySeed))

	rbacFile := filepath.Join(configDir, "rbac.yaml")
	require.NoError(t, os.WriteFile(rbacFile, []byte(rbacConfig), 0o644))

	configFiles := []string{envFile, idpFile, rbacFile}
	if configure != nil {
		configure(configFiles)
	}

	ctx, cancel := context.WithCancel(context.Background())

	b := &TestBroker{
		ConfigFiles: configFiles,
		Done:        make(chan error, 1),
		cancel:      cancel,
	}

	go func() {
		b.Done <- brokerStartWithContext(ctx, configFiles)
	}()

	// Wait for the broker to register its micro service
	waitForBrokerReady(t, cluster)

	t.Cleanup(func() {
		cancel()
	})

	return b
}

// waitForBrokerReady polls until the broker's micro service endpoint is registered
// by connecting as the minter user (same account as the broker) and pinging $SRV.PING.
func waitForBrokerReady(t *testing.T, cluster *TestCluster) {
	t.Helper()

	minterUser := cluster.MintAccount.Users["minter"]
	require.NotNil(t, minterUser, "minter user not found")

	nc, err := nats.Connect(cluster.URL,
		nats.UserCredentials(minterUser.CredsFile),
		nats.MaxReconnects(0),
	)
	require.NoError(t, err)
	defer nc.Close()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		msg, err := nc.Request("$SRV.PING", nil, 500*time.Millisecond)
		if err == nil && msg != nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}

	t.Fatal("broker did not become ready within timeout")
}

//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectionJetStreamOwnership(t *testing.T) {
	cluster := SetupTestCluster(t)
	oidc := SetupMockOIDC(t)
	app := jwt.NewAccountClaims(cluster.AppAccount.AccountPub)
	app.Name = "APP1"
	app.Limits.JetStreamLimits.MemoryStorage = 1024 * 1024
	app.Limits.JetStreamLimits.DiskStorage = 1024 * 1024
	app.Limits.JetStreamLimits.Streams = 10
	app.Limits.JetStreamLimits.Consumer = 100
	scope := jwt.NewUserScope()
	scope.Key = cluster.AppAccount.SigningPub
	scope.Template.Pub.Allow.Add(
		"$JS.API.CONSUMER.CREATE.{{tag(read)}}.{{name()}}.{{tag(read)}}.>",
		"$JS.API.CONSUMER.INFO.{{tag(read)}}.{{name()}}",
		"$JS.API.CONSUMER.MSG.NEXT.{{tag(read)}}.{{name()}}",
		"$JS.API.CONSUMER.DELETE.{{tag(read)}}.{{name()}}",
		"$JS.ACK.{{tag(read)}}.{{name()}}.>",
		"$JS.ACK.*.*.{{tag(read)}}.{{name()}}.>",
	)
	scope.Template.Sub.Allow.Add("_INBOX.{{name()}}.>")
	app.SigningKeys.AddScopedSigner(scope)
	artifact, err := app.Encode(cluster.OperatorKP)
	require.NoError(t, err)
	require.NoError(t, cluster.Server.AccountResolver().Store(cluster.AppAccount.AccountPub, artifact))
	account, err := cluster.Server.LookupAccount(cluster.AppAccount.AccountPub)
	require.NoError(t, err)
	cluster.Server.UpdateAccountClaims(account, app)
	setupBroker(t, cluster, oidc, func(files []string) {
		idp := fmt.Sprintf(`idp:
  - key: kitchen
    issuer_url: "%s"
    client_id: mockclientid
`, oidc.IssuerURL)
		require.NoError(t, os.WriteFile(files[1], []byte(idp), 0o600))
		seed, err := cluster.AppAccount.SigningKP.Seed()
		require.NoError(t, err)
		rbac := fmt.Sprintf(`rbac:
  user_projection:
    name: id_token.sub
    max_claims_age: 15m
    tags:
      - key: read
        values: 'capture(id_token.groups, "^read:([a-z0-9_]+)$")'
  user_accounts:
    - name: APP1
      public_key: "%s"
      signing_nkey: "%s"
      scoped: true
      account_jwt: "%s"
      operator_public_key: "%s"
  role_binding:
    - user_account: APP1
      roles: []
`, cluster.AppAccount.AccountPub, string(seed), artifact, cluster.OperatorPub)
		require.NoError(t, os.WriteFile(files[2], []byte(rbac), 0o600))
	})
	// Provision data as the account identity, independently of the scoped user key.
	adminKey, err := nkeys.CreateUser()
	require.NoError(t, err)
	adminPub, err := adminKey.PublicKey()
	require.NoError(t, err)
	adminClaims := jwt.NewUserClaims(adminPub)
	adminClaims.IssuerAccount = cluster.AppAccount.AccountPub
	adminJWT, err := adminClaims.Encode(cluster.AppAccount.AccountKP)
	require.NoError(t, err)
	admin, err := nats.Connect(cluster.URL, nats.UserJWT(func() (string, error) { return adminJWT, nil }, adminKey.Sign))
	require.NoError(t, err)
	defer admin.Close()
	adminJS, err := jetstream.New(admin)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for _, table := range []string{"menu_prices", "staff_rotas", "private_table"} {
		_, err := adminJS.CreateStream(ctx, jetstream.StreamConfig{Name: table, Subjects: []string{table + ".>"}, Storage: jetstream.MemoryStorage})
		require.NoError(t, err)
		_, err = adminJS.Publish(ctx, table+".row", []byte("row"))
		require.NoError(t, err)
	}
	connect := func(name string) (*nats.Conn, jetstream.JetStream, chan error) {
		token := oidc.MintIDToken(map[string]interface{}{"sub": name, "aud": "mockclientid", "groups": []string{"read:menu_prices", "read:staff_rotas"}})
		errs := make(chan error, 32)
		nc, err := nats.Connect(cluster.URL, nats.UserCredentials(cluster.MintAccount.Users["nobody"].CredsFile), nats.Token(token), nats.CustomInboxPrefix("_INBOX."+name), nats.MaxReconnects(0), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { errs <- err }))
		require.NoError(t, err)
		t.Cleanup(nc.Close)
		js, err := jetstream.New(nc)
		require.NoError(t, err)
		return nc, js, errs
	}
	alice, aliceJS, aliceErrors := connect("alice")
	_, bobJS, _ := connect("bob")
	for _, table := range []string{"menu_prices", "staff_rotas"} {
		consumer, err := aliceJS.CreateConsumer(ctx, table, jetstream.ConsumerConfig{Name: "alice", FilterSubject: table + ".>", AckPolicy: jetstream.AckExplicitPolicy})
		require.NoError(t, err)
		message, err := consumer.Next(jetstream.FetchMaxWait(time.Second))
		require.NoError(t, err)
		assert.Equal(t, "row", string(message.Data()))
		require.NoError(t, message.DoubleAck(ctx))
	}
	bobConsumer, err := bobJS.CreateConsumer(ctx, "menu_prices", jetstream.ConsumerConfig{Name: "bob", FilterSubject: "menu_prices.>", AckPolicy: jetstream.AckExplicitPolicy})
	require.NoError(t, err)
	bobMessage, err := bobConsumer.Next(jetstream.FetchMaxWait(time.Second))
	require.NoError(t, err)
	// Alice cannot acknowledge Bob's delivery even if she learns its reply subject.
	reply := bobMessage.Reply()
	require.True(t, strings.HasPrefix(reply, "$JS.ACK."))
	require.NoError(t, alice.Publish(reply, []byte("+ACK")))
	require.NoError(t, alice.Flush())
	select {
	case err := <-aliceErrors:
		assert.Contains(t, err.Error(), "Permissions Violation")
	case <-time.After(time.Second):
		t.Fatal("cross-user acknowledgement was not refused")
	}
	require.NoError(t, bobMessage.DoubleAck(ctx))
	// Learning another consumer's name also cannot authorize a pull request.
	nextSubject := "$JS.API.CONSUMER.MSG.NEXT.menu_prices.bob"
	require.NoError(t, alice.Publish(nextSubject, []byte(`{"batch":1}`)))
	require.NoError(t, alice.Flush())
	select {
	case err := <-aliceErrors:
		assert.Contains(t, err.Error(), nextSubject)
	case <-time.After(time.Second):
		t.Fatal("cross-user pull was not refused")
	}
	// The server must also bind an allowed API subject to the consumer named in
	// its payload; publishing on Alice's subject must not modify Bob's consumer.
	mismatch, err := alice.Request("$JS.API.CONSUMER.CREATE.menu_prices.alice.menu_prices.>", []byte(`{"stream_name":"menu_prices","config":{"name":"bob","durable_name":"bob","filter_subject":"menu_prices.>","ack_policy":"explicit"}}`), time.Second)
	require.NoError(t, err)
	var mismatchResponse struct {
		Error interface{} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(mismatch.Data, &mismatchResponse))
	require.NotNil(t, mismatchResponse.Error)

	// Inbox ownership is enforced by subscriptions as well as consumer names.
	_, err = alice.SubscribeSync("_INBOX.bob.>")
	require.NoError(t, err)
	require.NoError(t, alice.Flush())
	select {
	case err := <-aliceErrors:
		assert.Contains(t, err.Error(), "Permissions Violation")
	case <-time.After(time.Second):
		t.Fatal("cross-user inbox subscription was not refused")
	}
	// Use short bounded requests for expected permission denials.
	denyCtx, denyCancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer denyCancel()
	_, err = aliceJS.CreateConsumer(denyCtx, "menu_prices", jetstream.ConsumerConfig{Name: "bob", FilterSubject: "menu_prices.>", AckPolicy: jetstream.AckExplicitPolicy})
	require.Error(t, err)
	denyCtx2, cancel2 := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel2()
	_, err = aliceJS.UpdateConsumer(denyCtx2, "menu_prices", jetstream.ConsumerConfig{Name: "bob", FilterSubject: "menu_prices.>", AckPolicy: jetstream.AckExplicitPolicy})
	require.Error(t, err)
	denyCtx3, cancel3 := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel3()
	require.Error(t, aliceJS.DeleteConsumer(denyCtx3, "menu_prices", "bob"))
	denyCtx4, cancel4 := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel4()
	_, err = aliceJS.CreateConsumer(denyCtx4, "private_table", jetstream.ConsumerConfig{Name: "alice", FilterSubject: "private_table.>", AckPolicy: jetstream.AckExplicitPolicy})
	require.Error(t, err)
}

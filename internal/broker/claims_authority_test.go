package broker

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisteredClaimsSurviveMappingRoundTrips(t *testing.T) {
	mapping := map[string]string{"external_sub": "sub", "external_iat": "iat", "external_exp": "exp"}
	source := map[string]interface{}{"sub": "alice", "iat": int64(1800000000), "exp": int64(1800003600),
		"external_sub": "mallory", "external_iat": int64(1), "external_exp": int64(1900000000)}
	claims := &IdpJwtClaims{}
	claims.fromMap(source, mapping)
	for i := 0; i < 3; i++ {
		context := claims.toMap()
		assert.Equal(t, "alice", context["sub"])
		assert.EqualValues(t, 1800000000, context["iat"])
		assert.EqualValues(t, 1800003600, context["exp"])
		context["client_id"] = "server-vouched-id"
		claims.fromMap(context, mapping)
		assert.Equal(t, "alice", claims.Subject)
		assert.Equal(t, int64(1800000000), claims.IssuedAt)
		assert.Equal(t, int64(1800003600), claims.Expiry)
	}
}

func TestCustomClaimsCannotShadowRegisteredFields(t *testing.T) {
	claims := &IdpJwtClaims{Subject: "alice", IssuedAt: 1800000000, Expiry: 1800003600,
		CustomClaims: map[string]interface{}{"sub": "mallory", "iat": 1, "exp": 1900000000}}
	context := claims.toMap()
	assert.Equal(t, "alice", context["sub"])
	assert.EqualValues(t, 1800000000, context["iat"])
	assert.EqualValues(t, 1800003600, context["exp"])
}

func TestUnprojectedUserClaimCannotAuthorize(t *testing.T) {
	for _, mode := range []string{"binding", "template"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newTestFixture(t)
			source, err := os.ReadFile(fixture.tmpFile)
			require.NoError(t, err)
			if mode == "binding" {
				source = []byte(strings.Replace(string(source), `roles: ["basic-role"]`, `roles: ["basic-role"]
      match:
        - expr: '"head_chef" in user.tags.role'`, 1))
			} else {
				source = []byte(strings.ReplaceAll(string(source), `allow: ["test.>"]`, `allow: ["basic.{{ .user.name }}"]`))
			}
			require.NoError(t, os.WriteFile(fixture.tmpFile, source, 0o600))
			cm, err := NewConfigManager([]string{fixture.tmpFile})
			require.NoError(t, err)
			claims := &IdpJwtClaims{Subject: "alice", Expiry: time.Now().Add(time.Hour).Unix(), CustomClaims: map[string]interface{}{
				"user": map[string]interface{}{"name": ">", "tags": map[string]interface{}{"role": []interface{}{"head_chef"}}},
			}}
			request := &jwt.AuthorizationRequestClaims{}
			request.UserNkey = fixture.userPub
			result, _, _, _, err := buildUserClaims(fixture.ctx, fixture.config, cm, claims, fakeIdpVerifier(), request)
			require.Error(t, err, "raw user must never act as a verified projection")
			assert.Nil(t, result)
		})
	}
}

//go:build integration

package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	jwtgo "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

// MockOIDC provides an in-process OIDC provider for integration testing.
type MockOIDC struct {
	UserInfoHandler http.HandlerFunc
	Server          *httptest.Server
	IssuerURL       string
	SigningKey      *rsa.PrivateKey
	KeyID           string
	signerOpts      jose.SignerOptions
}

// SetupMockOIDC creates a mock OIDC provider with discovery, JWKS, and token endpoints.
func SetupMockOIDC(t *testing.T) *MockOIDC {
	t.Helper()

	// Generate RSA key for signing
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	m := &MockOIDC{
		SigningKey: key,
		KeyID:      "test-key-1",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", m.handleDiscovery)
	mux.HandleFunc("/jwks", m.handleJWKS)
	mux.HandleFunc("/token", m.handleToken)
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if m.UserInfoHandler == nil {
			http.NotFound(w, r)
			return
		}
		m.UserInfoHandler(w, r)
	})

	m.Server = httptest.NewServer(mux)
	m.IssuerURL = m.Server.URL

	t.Cleanup(func() {
		m.Server.Close()
	})

	return m
}

func (m *MockOIDC) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	discovery := map[string]interface{}{
		"issuer":                                m.IssuerURL,
		"userinfo_endpoint":                     m.IssuerURL + "/userinfo",
		"jwks_uri":                              m.IssuerURL + "/jwks",
		"token_endpoint":                        m.IssuerURL + "/token",
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"id_token"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discovery)
}

func (m *MockOIDC) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	jwk := jose.JSONWebKey{
		Key:       &m.SigningKey.PublicKey,
		KeyID:     m.KeyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func (m *MockOIDC) handleToken(w http.ResponseWriter, _ *http.Request) {
	// Simple token endpoint for client_credentials grant
	token := m.MintIDToken(map[string]interface{}{
		"sub":   "bob@acme.com",
		"email": "bob@acme.com",
		"name":  "Bob",
		"aud":   "mockclientid",
	})

	resp := map[string]interface{}{
		"id_token":   token,
		"token_type": "Bearer",
		"expires_in": 3600,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// MintIDToken creates a signed JWT with the given claims.
func (m *MockOIDC) MintIDToken(claims map[string]interface{}) string {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: m.SigningKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), m.KeyID),
	)
	if err != nil {
		panic("failed to create signer: " + err.Error())
	}

	now := time.Now()

	// Build standard claims
	stdClaims := jwtgo.Claims{
		Issuer:    m.IssuerURL,
		IssuedAt:  jwtgo.NewNumericDate(now),
		NotBefore: jwtgo.NewNumericDate(now.Add(-1 * time.Minute)),
	}

	// Set expiry: use from claims map or default to 1 hour
	if exp, ok := claims["exp"]; ok {
		switch v := exp.(type) {
		case time.Time:
			stdClaims.Expiry = jwtgo.NewNumericDate(v)
		case int64:
			stdClaims.Expiry = jwtgo.NewNumericDate(time.Unix(v, 0))
		}
		delete(claims, "exp")
	} else {
		stdClaims.Expiry = jwtgo.NewNumericDate(now.Add(1 * time.Hour))
	}

	// Set subject from claims map
	if sub, ok := claims["sub"].(string); ok {
		stdClaims.Subject = sub
		delete(claims, "sub")
	}

	// Set audience from claims map
	if aud, ok := claims["aud"]; ok {
		switch v := aud.(type) {
		case string:
			stdClaims.Audience = jwtgo.Audience{v}
		case []string:
			stdClaims.Audience = jwtgo.Audience(v)
		}
		delete(claims, "aud")
	}

	// Set issuer override from claims map
	if iss, ok := claims["iss"].(string); ok {
		stdClaims.Issuer = iss
		delete(claims, "iss")
	}

	token, err := jwtgo.Signed(signer).Claims(stdClaims).Claims(claims).Serialize()
	if err != nil {
		panic("failed to serialize token: " + err.Error())
	}

	return token
}

// MintExpiredIDToken creates a signed JWT that is already expired.
func (m *MockOIDC) MintExpiredIDToken(claims map[string]interface{}) string {
	claims["exp"] = time.Now().Add(-1 * time.Hour)
	return m.MintIDToken(claims)
}

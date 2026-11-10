package broker

import (
	"context"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/nats-io/jwt/v2"
)

func projectVerifiedUser(ctx context.Context, rules *UserProjection, claims *IdpJwtClaims, verifier *IdpAndJwtVerifier, token *oidc.IDToken, tokens TokenRequest, request *jwt.AuthorizationRequestClaims) (*NatsUser, error) {
	idp := verifier.config
	identity := VerifiedIdentity{
		IDToken: claims.toMap(), IssuedAt: token.IssuedAt, VerifiedAt: time.Now(),
		IDP: map[string]interface{}{"key": idp.Key, "description": idp.Description, "issuer_url": idp.IssuerURL, "client_id": idp.ClientID},
		Connection: map[string]interface{}{
			"host": request.ClientInformation.Host, "type": request.ClientInformation.Type, "kind": request.ClientInformation.Kind,
			"tls_verified": request.TLS != nil && len(request.TLS.VerifiedChains) > 0,
		},
		Server: map[string]interface{}{"name": request.Server.Name, "cluster": request.Server.Cluster, "tags": []string(request.Server.Tags)},
	}
	// These are the original signed values, irrespective of custom_mapping.
	identity.IDToken["sub"] = token.Subject
	identity.IDToken["iat"] = token.IssuedAt.Unix()
	identity.IDToken["exp"] = token.Expiry.Unix()
	if rules.compiled.reads["userinfo"] {
		if tokens.AccessToken == "" {
			return nil, unavailableUserInfo("no_access_token")
		}
		fetchCtx, cancel := context.WithTimeout(ctx, oidcTimeout)
		defer cancel()
		info, err := verifier.verifier.GetUserInfo(fetchCtx, tokens.AccessToken, token)
		if err != nil || info["sub"] != token.Subject {
			return nil, unavailableUserInfo("fetch_or_subject_check_failed")
		}
		identity.UserInfo = info
	}
	return rules.Project(identity)
}

func unavailableUserInfo(reason string) *ProjectionError {
	e := projectionError("Unavailable", "userinfo")
	e.Namespace = "userinfo"
	e.Reason = reason
	return e
}

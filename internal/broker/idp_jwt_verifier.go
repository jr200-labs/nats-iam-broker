package broker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type UserInfoProvider interface {
	GetUserInfo(ctx context.Context, accessToken string, idToken *oidc.IDToken) (map[string]interface{}, error)
}

type IdpAndJwtVerifier struct {
	verifier *IdpJwtVerifier
	config   *Idp
}

func NewIdpVerifiers(ctx *Context, config *Config) ([]IdpAndJwtVerifier, error) {
	idpVerifiers := make([]IdpAndJwtVerifier, 0, len(config.Idp))
	for i := range config.Idp {
		idp := &config.Idp[i] // Use a pointer to the IDP config
		idpVerifier, err := NewJwtVerifier(ctx, idp.ClientID, idp.IssuerURL, idp.MaxTokenLifetime.Duration, idp.ClockSkew.Duration)
		if err != nil {
			if idp.IgnoreSetupError {
				zap.L().Warn("Failed to setup IDP verifier, ignoring due to config", zap.Error(err), zap.String("issuer_url", idp.IssuerURL), zap.String("client_id", idp.ClientID))
				continue // Skip this IDP and continue with the next one
			}

			zap.L().Error("Failed to setup IDP verifier, halting startup", zap.Error(err), zap.String("issuer_url", idp.IssuerURL), zap.String("client_id", idp.ClientID))
			return nil, fmt.Errorf("failed to setup verifier for IDP %s (%s): %w", idp.Description, idp.IssuerURL, err)
		}
		if idp.UserInfo.RequireAtHash != nil {
			idpVerifier.RequireAccessTokenHash = *idp.UserInfo.RequireAtHash
		}
		idpVerifiers = append(idpVerifiers, IdpAndJwtVerifier{idpVerifier, idp}) // Pass the pointer to the config
	}
	return idpVerifiers, nil
}

func runVerification(ctx context.Context, jwtToken string, items []IdpAndJwtVerifier) (*IdpJwtClaims, *IdpAndJwtVerifier, *oidc.IDToken, error) {
	var verificationErrors []error
	for _, item := range items {
		if item.verifier.ctx.Options.LogSensitive {
			zap.L().Debug("verifying jwt against spec", zap.String("jwt", jwtToken), zap.Any("spec", item.config.ValidationSpec))
		}
		reqClaims, idToken, err := item.verifier.verifyJWT(ctx, jwtToken, item.config.CustomMapping)
		if err != nil {
			verificationErrors = append(verificationErrors, fmt.Errorf("idp %s: %w", item.config.Description, err))
			var expiredErr *oidc.TokenExpiredError
			if errors.As(err, &expiredErr) {
				zap.L().Debug("error verifying idp-jwt: token expired", zap.String("idp", item.config.Description), zap.Time("expiry", expiredErr.Expiry))
			} else {
				zap.L().Debug("error verifying idp-jwt, trying next idp", zap.String("idp", item.config.Description), zap.Error(err))
			}
			continue
		}

		err = item.verifier.validateAgainstSpec(reqClaims, item.config.ValidationSpec)
		if err != nil {
			verificationErrors = append(verificationErrors, fmt.Errorf("idp %s validation: %w", item.config.Description, err))
			zap.L().Debug("failed checks in idp validation", zap.Error(err))
			continue
		}

		return reqClaims, &item, idToken, nil
	}

	if len(verificationErrors) == 0 {
		return nil, nil, nil, errors.New("no idp verifiers configured")
	}
	return nil, nil, nil, fmt.Errorf("no idp verifier matched token: %w", errors.Join(verificationErrors...))
}

type IdpJwtVerifier struct {
	RequireAccessTokenHash bool
	ctx                    *Context
	*oidc.IDTokenVerifier
	provider         *oidc.Provider
	issuerURL        string
	MaxTokenLifetime time.Duration
	ClockSkew        time.Duration
}

const oidcTimeout = 30 * time.Second

const (
	DefaultMaxTokenLifetime = 24 * time.Hour
	DefaultClockSkew        = 5 * time.Minute
)

func NewJwtVerifier(ctx *Context, clientID string, issuerURL string, maxTokenLifetime time.Duration, clockSkew time.Duration) (*IdpJwtVerifier, error) {
	if maxTokenLifetime <= 0 {
		maxTokenLifetime = DefaultMaxTokenLifetime
	}
	if clockSkew <= 0 {
		clockSkew = DefaultClockSkew
	}

	providerCtx, providerCancel := context.WithTimeout(context.Background(), oidcTimeout)
	defer providerCancel()

	provider, err := oidc.NewProvider(providerCtx, issuerURL)
	if err != nil {
		zap.L().Error("error creating OIDC provider", zap.Error(err))
		return nil, err
	}

	if ctx.Options.LogSensitive {
		zap.L().Debug("NewJwtVerifier config-params", zap.String("client_id", clientID), zap.String("issuer_url", issuerURL),
			zap.Duration("max_token_lifetime", maxTokenLifetime), zap.Duration("clock_skew", clockSkew))
	}

	return &IdpJwtVerifier{
		ctx:                    ctx,
		RequireAccessTokenHash: true,
		IDTokenVerifier:        provider.Verifier(&oidc.Config{ClientID: clientID}),
		provider:               provider,
		issuerURL:              issuerURL,
		MaxTokenLifetime:       maxTokenLifetime,
		ClockSkew:              clockSkew,
	}, nil
}

// Verifies that the ID token was signed by idp and is valid.
// Returns the claims embedded with the token
func (v *IdpJwtVerifier) verifyJWT(ctx context.Context, token string, customMapping map[string]string) (*IdpJwtClaims, *oidc.IDToken, error) {
	if len(token) > projectionMaxInputBytes {
		return nil, nil, errors.New("ID token exceeds input limit")
	}
	claims := &IdpJwtClaims{}

	if v.ctx.Options.LogSensitive {
		zap.L().Debug("VerifyJWT", zap.String("token", token))
	}

	verifyCtx, verifyCancel := context.WithTimeout(ctx, oidcTimeout)
	defer verifyCancel()

	idToken, err := v.Verify(verifyCtx, token)
	if err != nil {
		return nil, nil, err
	}

	// First get all claims as a map
	var rawClaims map[string]interface{}
	if err := idToken.Claims(&rawClaims); err != nil {
		return nil, nil, err
	}

	// Then convert to our claims struct
	if err := idToken.Claims(claims); err != nil {
		return nil, nil, err
	}

	// Store all claims in CustomClaims using the custom mapping
	claims.fromMap(rawClaims, customMapping)
	claims.protectRegisteredClaims(idToken)

	err = v.ValidateTimes(idToken.IssuedAt, idToken.Expiry)
	if err != nil {
		return nil, nil, err
	}

	return claims, idToken, nil
}

func (v *IdpJwtVerifier) ValidateTimes(issuedAt time.Time, expiry time.Time) error {
	if issuedAt.Unix() < 1 {
		return errors.New("missing 'issued at' time in token")
	}

	if expiry.Unix() < 1 {
		return errors.New("missing 'expiry' time in token")
	}

	now := time.Now()
	if expiry.Unix() > now.Unix()+int64(v.MaxTokenLifetime.Seconds()) {
		return errors.New("expiry too far in future")
	}

	skewedEarliest := issuedAt.Unix() - int64(v.ClockSkew.Seconds())
	// Clock skew tolerates future issuance, never extends a credential past exp.
	expiryDeadline := expiry.Unix()

	if now.Unix() < skewedEarliest {
		return errors.New("token used too early. check clock skew?")
	}

	if now.Unix() >= expiryDeadline {
		return errors.New("token used too late: expired")
	}

	return nil
}

func (v *IdpJwtVerifier) validateAgainstSpec(claims *IdpJwtClaims, spec IdpJwtValidationSpec) error {
	if spec.Claims != nil {
		err := claims.exists(spec.Claims)
		if err != nil {
			return err
		}
	}

	if !spec.SkipAudienceValidation && len(spec.Audience) > 0 {
		err := claims.validateAudience(spec.Audience)
		if err != nil {
			zap.L().Error("failed audience check", zap.Any("audience", spec.Audience), zap.Error(err))
			return err
		}
	}

	if spec.TokenExpiryBounds.Min.Duration > 0 || spec.TokenExpiryBounds.Max.Duration > 0 {
		err := claims.validateExpiryBounds(spec.TokenExpiryBounds)
		if err != nil {
			return err
		}
	}

	return nil
}

func (v *IdpJwtVerifier) GetUserInfo(ctx context.Context, accessToken string, idToken *oidc.IDToken) (map[string]interface{}, error) {
	// Parse and verify the ID token
	if accessToken == "" {
		return nil, fmt.Errorf("no access token found in claim sources")
	}

	if idToken == nil {
		return nil, fmt.Errorf("id token is required to verify access token")
	}

	// Preserve the strict default. Optional-hash code-flow providers require an
	// explicit policy choice; exact provider/subject validation still applies.
	if idToken.AccessTokenHash == "" && v.RequireAccessTokenHash {
		return nil, errors.New("access token hash required")
	}
	// Verify the access token matches the hash in the ID token
	if idToken.AccessTokenHash != "" {
		if err := idToken.VerifyAccessToken(accessToken); err != nil {
			return nil, errors.New("access token verification failed")
		}
	}
	fetchCtx, cancel := context.WithTimeout(ctx, oidcTimeout)
	defer cancel()
	fetchCtx = boundedUserInfoContext(fetchCtx)

	// Use the verified access token to fetch user info
	userInfo, err := v.provider.UserInfo(fetchCtx, oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: accessToken,
	}))
	if err != nil {
		return nil, errors.New("failed to fetch user info")
	}

	if idToken.Subject == "" || userInfo.Subject != idToken.Subject {
		return nil, errors.New("user info subject mismatch")
	}
	userInfoClaims := make(map[string]interface{})
	if err := userInfo.Claims(&userInfoClaims); err != nil {
		return nil, fmt.Errorf("failed to parse user info claims: %w", err)
	}

	return userInfoClaims, nil
}

// protectRegisteredClaims restores the signed snapshot for every consumer of
// the claims, including raw role matches and request config templates.
func (claims *IdpJwtClaims) protectRegisteredClaims(token *oidc.IDToken) {
	claims.Subject = token.Subject
	claims.IssuedAt = token.IssuedAt.Unix()
	claims.Expiry = token.Expiry.Unix()
	claims.signedExpiry = token.Expiry.Unix()
	for _, key := range []string{"sub", "iat", "exp"} {
		delete(claims.CustomClaims, key)
	}
}

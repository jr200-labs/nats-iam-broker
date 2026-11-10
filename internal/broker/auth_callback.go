package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jr200-labs/nats-iam-broker/internal/metrics"
	"github.com/jr200-labs/nats-iam-broker/internal/tracing"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

func newAuthCallbackWithWatcher(
	ctx *Context,
	m *metrics.Metrics,
	nc *nats.Conn,
	watcher *ConfigWatcher,
) AuthHandler {
	return func(reqCtx context.Context, request *jwt.AuthorizationRequestClaims) (*jwt.UserClaims, nkeys.KeyPair, *UserAccountInfo, error) {
		// Snapshot current state at request start. All operations in this
		// request use this snapshot, ensuring consistency even if a reload
		// happens mid-request.
		state := watcher.State()
		return handleAuthRequest(reqCtx, ctx, m, nc, state.config, state.configManager, state.idpVerifiers, state.auditSubject, request)
	}
}

func handleAuthRequest(
	reqCtx context.Context,
	srvCtx *Context,
	m *metrics.Metrics,
	nc *nats.Conn,
	config *Config,
	configManager *ConfigManager,
	idpVerifiers []IdpAndJwtVerifier,
	auditEventSubject string,
	request *jwt.AuthorizationRequestClaims,
) (*jwt.UserClaims, nkeys.KeyPair, *UserAccountInfo, error) {
	requestStart := time.Now()
	if m != nil {
		m.AuthRequestsInFlight.Inc()
		defer m.AuthRequestsInFlight.Dec()
	}

	recordResult := func(status string) {
		if m != nil {
			duration := time.Since(requestStart).Seconds()
			m.AuthRequestsTotal.WithLabelValues(status).Inc()
			m.AuthRequestDuration.WithLabelValues(status).Observe(duration)
		}
	}

	// -- extract JWT --
	_, extractSpan := getTracer().Start(reqCtx, "auth.callout.extract_jwt")
	idpRawJwt, tokenReq := extractJWT(srvCtx, request)
	if idpRawJwt == "" {
		extractSpan.SetStatus(codes.Error, "no valid JWT token found")
		extractSpan.End()
		recordResult(metrics.StatusError)
		return nil, nil, nil, fmt.Errorf("no valid JWT token found in request")
	}
	extractSpan.End()

	// -- verify IDP --
	verifyCtx, verifySpan := getTracer().Start(reqCtx, "auth.callout.verify_idp")
	reqClaims, matchedVerifier, _, err := verifyAndEnrich(verifyCtx, m, idpRawJwt, tokenReq, idpVerifiers, configManager, request)
	if err != nil {
		var projectionErr *ProjectionError
		if errors.As(err, &projectionErr) {
			idpKey := "unknown"
			if matchedVerifier != nil {
				idpKey = matchedVerifier.config.Key
			}
			recordProjectionRefusal(m, idpKey, projectionErr)
			// No claims or evaluator details are returned to the client.
			err = fmt.Errorf("authorization failed")
		}
		verifySpan.SetStatus(codes.Error, err.Error())
		verifySpan.RecordError(err)
		verifySpan.End()
		recordResult(metrics.StatusDenied)
		return nil, nil, nil, err
	}
	verifySpan.SetAttributes(attribute.String("auth.idp", matchedVerifier.config.Description))
	verifySpan.End()

	// Merge in client information from the request
	reqJwtClaims := reqClaims.toMap()
	reqJwtClaims["client_id"] = request.ClientInformation.User        // Sentinel ID
	reqJwtClaims["also_known_as"] = request.ClientInformation.NameTag // Sentinel name
	reqClaims.fromMap(reqJwtClaims, matchedVerifier.config.CustomMapping)

	if srvCtx.Options.LogSensitive {
		zap.L().Debug("reqClaims", zap.Any("claims", reqClaims.toMap()))
	}

	// -- build claims --
	_, buildSpan := getTracer().Start(reqCtx, "auth.callout.build_claims")
	claims, signingKeyPair, userAccountInfo, resultStatus, err := buildUserClaims(srvCtx, config, configManager, reqClaims, matchedVerifier, request)
	if err != nil {
		var refusal *ProjectionError
		if errors.As(err, &refusal) {
			recordProjectionRefusal(m, matchedVerifier.config.Key, refusal)
			err = errors.New("authorization failed")
		}
		buildSpan.SetStatus(codes.Error, err.Error())
		buildSpan.RecordError(err)
		buildSpan.End()
		recordResult(resultStatus)
		return nil, nil, nil, err
	}
	buildSpanAttrs := []attribute.KeyValue{
		attribute.String("auth.account", claims.Audience),
	}
	if srvCtx.Options.LogSensitive {
		buildSpanAttrs = append(buildSpanAttrs, attribute.String("auth.user.email", reqClaims.Email))
	}
	buildSpan.SetAttributes(buildSpanAttrs...)
	buildSpan.End()

	// -- audit --
	auditCtx, auditSpan := getTracer().Start(reqCtx, "auth.callout.audit")
	publishAuditEvent(auditCtx, nc, auditEventSubject, config, claims, request, reqClaims, matchedVerifier, userAccountInfo)
	auditSpan.End()

	// Record result attributes on the parent span
	span := trace.SpanFromContext(reqCtx)
	spanAttrs := []attribute.KeyValue{
		attribute.String("auth.idp", matchedVerifier.config.Description),
		attribute.String("auth.account", claims.Audience),
		attribute.String("auth.result", metrics.StatusSuccess),
		attribute.String("auth.token.expires_at", time.Unix(claims.Expires, 0).Format(time.RFC3339)),
	}
	if srvCtx.Options.LogSensitive {
		spanAttrs = append(spanAttrs, attribute.String("auth.user.email", reqClaims.Email))
	}
	span.SetAttributes(spanAttrs...)

	recordResult(metrics.StatusSuccess)
	if m != nil {
		m.TokensMinted.WithLabelValues(claims.Audience, matchedVerifier.config.Description).Inc()
	}

	return claims, signingKeyPair, userAccountInfo, nil
}

func extractJWT(ctx *Context, request *jwt.AuthorizationRequestClaims) (string, TokenRequest) {
	var tokenReq TokenRequest
	var idpRawJwt string

	if ctx.Options.LogSensitive {
		zap.L().Debug("NewAuthService request", zap.Any("request", request))
	}

	if request.ConnectOptions.Token != "" {
		if err := json.Unmarshal([]byte(request.ConnectOptions.Token), &tokenReq); err == nil {
			idpRawJwt = tokenReq.IDToken
		} else {
			idpRawJwt = request.ConnectOptions.Token
		}
	} else {
		if err := json.Unmarshal([]byte(request.ConnectOptions.Password), &tokenReq); err == nil {
			idpRawJwt = tokenReq.IDToken
		} else {
			idpRawJwt = request.ConnectOptions.Password
		}
	}

	return idpRawJwt, tokenReq
}

func verifyAndEnrich(
	ctx context.Context,
	m *metrics.Metrics,
	idpRawJwt string,
	tokenReq TokenRequest,
	idpVerifiers []IdpAndJwtVerifier,
	configManager *ConfigManager,
	request *jwt.AuthorizationRequestClaims,
) (*IdpJwtClaims, *IdpAndJwtVerifier, TokenRequest, error) {
	verifyStart := time.Now()
	reqClaims, matchedVerifier, verifiedIDToken, err := runVerification(ctx, idpRawJwt, idpVerifiers)
	if err != nil {
		if m != nil {
			m.IDPVerifyTotal.WithLabelValues("unknown", metrics.StatusError).Inc()
		}
		return nil, nil, tokenReq, err
	}
	if m != nil {
		idpDesc := matchedVerifier.config.Description
		m.IDPVerifyTotal.WithLabelValues(idpDesc, metrics.StatusSuccess).Inc()
		m.IDPVerifyDuration.WithLabelValues(idpDesc).Observe(time.Since(verifyStart).Seconds())
	}

	reqClaims.signedExpiry = verifiedIDToken.Expiry.Unix()
	if rules := configManager.projection(matchedVerifier.config); rules != nil {
		user, err := projectVerifiedUser(ctx, rules, reqClaims, matchedVerifier, verifiedIDToken, tokenReq, request)
		if err != nil {
			return nil, matchedVerifier, tokenReq, err
		}
		reqClaims.projected = user
		// Keep the legacy claim context for non-projection bindings, but protect
		// minted expiry from mappings. Projection itself never sees client facts.
		reqClaims.Expiry = verifiedIDToken.Expiry.Unix()
		return reqClaims, matchedVerifier, tokenReq, nil
	}

	if matchedVerifier.config.UserInfo.Enabled {
		// Enabling current claims requires them; never silently fall back to an
		// older snapshot after missing credentials, fetch errors or mismatches.
		info, err := matchedVerifier.verifier.GetUserInfo(ctx, tokenReq.AccessToken, verifiedIDToken)
		if err != nil {
			return nil, matchedVerifier, tokenReq, errors.New("authorization failed")
		}
		claims := reqClaims.toMap()
		for key, value := range info {
			claims[key] = value
		}
		reqClaims.fromMap(claims, matchedVerifier.config.CustomMapping)
		reqClaims.Expiry = verifiedIDToken.Expiry.Unix()
	}

	return reqClaims, matchedVerifier, tokenReq, nil
}

func buildUserClaims(
	ctx *Context,
	config *Config,
	configManager *ConfigManager,
	reqClaims *IdpJwtClaims,
	matchedVerifier *IdpAndJwtVerifier,
	request *jwt.AuthorizationRequestClaims,
) (*jwt.UserClaims, nkeys.KeyPair, *UserAccountInfo, string, error) {
	mappings := reqClaims.toMap()
	if reqClaims.projected != nil {
		mappings["user"] = reqClaims.projected.mapping()
	}
	cfgForRequest, err := configManager.GetConfig(mappings)
	if err != nil {
		zap.L().Error("error rendering config against idp-jwt", zap.Error(err))
		return nil, nil, nil, metrics.StatusError, err
	}

	userAccountName, permissions, limits, roleBindingTokenMaxExpiry, err := cfgForRequest.lookupUserAccount(mappings)
	if err != nil {
		zap.L().Error("error looking up user account", zap.Error(err))
		return nil, nil, nil, metrics.StatusDenied, err
	}

	if userAccountName == "" {
		zap.L().Error("role binding matched but account field is empty — check the role-binding configuration for a missing or empty 'account' field")
		return nil, nil, nil, metrics.StatusError, fmt.Errorf("matched role binding has empty account name — ensure all role-bindings specify an 'account'")
	}

	userAccountInfo, err := config.lookupAccountInfo(userAccountName)
	if err != nil {
		availableAccounts := make([]string, 0, len(config.Rbac.Accounts))
		for _, acinfo := range config.Rbac.Accounts {
			availableAccounts = append(availableAccounts, acinfo.Name)
		}
		zap.L().Error("error looking up account-info",
			zap.String("requested_account", userAccountName),
			zap.Strings("available_accounts", availableAccounts),
			zap.Error(err))
		return nil, nil, nil, metrics.StatusError, err
	}

	if ctx.Options.LogSensitive {
		zap.L().Debug("userAccountInfo", zap.Any("info", userAccountInfo))
	}

	claims := jwt.NewUserClaims(request.UserNkey)
	claims.Audience = userAccountName
	claims.Name = request.ConnectOptions.Username
	claims.IssuerAccount = userAccountInfo.PublicKey
	idpExpiry := reqClaims.Expiry
	if reqClaims.signedExpiry > 0 {
		idpExpiry = reqClaims.signedExpiry
	}
	claims.Expires = calculateExpiration(
		cfgForRequest,
		idpExpiry,
		&matchedVerifier.config.ValidationSpec.TokenExpiryBounds,
		&roleBindingTokenMaxExpiry,
	)
	if userAccountInfo.Scoped && reqClaims.projected == nil {
		return nil, nil, nil, metrics.StatusDenied, fmt.Errorf("scoped issuance requires projected identity")
	}
	claims.Permissions = *permissions
	claims.Limits = *limits
	if userAccountInfo.Scoped {
		claims.UserPermissionLimits = jwt.UserPermissionLimits{}
	}
	if user := reqClaims.projected; user != nil {
		claims.Name = user.Name
		claims.Tags.Add(user.jwtTags()...)
		if user.FreshUntil.Unix() < claims.Expires {
			claims.Expires = user.FreshUntil.Unix()
		}
		if claims.Expires <= time.Now().Unix() {
			return nil, nil, nil, metrics.StatusDenied, projectionStaleError("credential", user.FreshUntil)
		}
	} else {
		claims.Tags.Add(fmt.Sprintf("email: %s, name: %s, idp: %s, expires: %s",
			reqClaims.Email,
			reqClaims.Name,
			matchedVerifier.config.Description,
			time.Unix(claims.Expires, 0).Format(time.RFC3339)))
	}

	return claims, userAccountInfo.SigningNKey.KeyPair, userAccountInfo, "", nil
}

func publishAuditEvent(
	ctx context.Context,
	nc *nats.Conn,
	auditEventSubject string,
	config *Config,
	claims *jwt.UserClaims,
	request *jwt.AuthorizationRequestClaims,
	reqClaims *IdpJwtClaims,
	matchedVerifier *IdpAndJwtVerifier,
	userAccountInfo *UserAccountInfo,
) {
	signingKeyInfo, err := determineSigningKeyType(claims, userAccountInfo.SigningNKey.KeyPair, userAccountInfo)
	if err != nil {
		zap.L().Warn("failed to determine signing key type for audit event", zap.Error(err))
	}

	userEvent := map[string]interface{}{
		"account":          claims.Audience,
		"account_pub_nkey": userAccountInfo.PublicKey,
		"user_pub_nkey":    request.UserNkey,
		"username":         request.ConnectOptions.Username,
		"authorized_user":  claims.Name,
		"email":            reqClaims.Email,
		"name":             reqClaims.Name,
		"idp":              matchedVerifier.config.Description,
		"created_at":       time.Now().Format(time.RFC3339),
		"expires_at":       time.Unix(claims.Expires, 0).Format(time.RFC3339),
		"permissions":      &claims.Permissions,
		"limits":           &claims.Limits,
		"signing_account":  config.Service.Account.Name,
	}

	if signingKeyInfo != nil {
		userEvent["signing_key_type"] = signingKeyInfo.Type
		userEvent["signing_key_pub_nkey"] = signingKeyInfo.PublicKey
	}

	eventJSON, err := json.Marshal(userEvent)
	if err != nil {
		zap.L().Warn("failed to marshal user creation event", zap.Error(err))
		return
	}

	msg := &nats.Msg{
		Subject: fmt.Sprintf(auditEventSubject, claims.Audience, request.UserNkey),
		Data:    eventJSON,
		Header:  tracing.InjectTraceContext(ctx, nil),
	}
	if err := nc.PublishMsg(msg); err != nil {
		zap.L().Warn("failed to publish user creation event", zap.Error(err))
	}
}

func recordProjectionRefusal(m *metrics.Metrics, idp string, refusal *ProjectionError) {
	if m != nil {
		m.UserProjectionErrors.WithLabelValues(idp, refusal.Kind).Inc()
	}
	zap.L().Warn("user projection refused", zap.String("kind", refusal.Kind), zap.String("output", refusal.Output),
		zap.String("namespace", refusal.Namespace), zap.String("reason", refusal.Reason), zap.Int("count", refusal.Count), zap.Int("max", refusal.Max), zap.Time("as_of", refusal.AsOf), zap.String("found", refusal.Found))
}

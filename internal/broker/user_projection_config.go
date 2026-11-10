package broker

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func (c *Config) compileProjections() error {
	multiple := len(c.Idp) > 1
	if c.Rbac.UserProjection != nil {
		if err := c.Rbac.UserProjection.compile(multiple); err != nil {
			return err
		}
	}
	enabled := c.Rbac.UserProjection != nil
	for i := range c.Idp {
		if c.Idp[i].UserProjection != nil {
			enabled = true
			if err := c.Idp[i].UserProjection.compile(multiple); err != nil {
				return fmt.Errorf("idp[%d]: %w", i, err)
			}
		}
	}
	if !enabled {
		return nil
	}
	keys := map[string]bool{}
	for _, idp := range c.Idp {
		if !validProjectionToken(idp.Key, true) || strings.Contains(idp.Key, ":") || keys[idp.Key] {
			return fmt.Errorf("projection requires unique lowercase IdP keys without ':'")
		}
		keys[idp.Key] = true
	}
	return nil
}

func (cm *ConfigManager) projection(idp *Idp) *UserProjection {
	// Match the provider identity to the immutable load-time configuration.
	for _, candidate := range cm.baseConfig.Idp {
		if candidate.Key == idp.Key {
			if candidate.UserProjection != nil {
				return candidate.UserProjection
			}
			return cm.baseConfig.Rbac.UserProjection
		}
	}
	return cm.baseConfig.Rbac.UserProjection
}

func (c *Config) validateScopedAccounts() error {
	scoped := map[string]bool{}
	for _, account := range c.Rbac.Accounts {
		if account.Scoped {
			if err := account.validateScopedSigner(); err != nil {
				return fmt.Errorf("scoped account %s: %w", account.Name, err)
			}
			scoped[account.Name] = true
		}
	}
	if len(scoped) == 0 {
		return nil
	}
	xkey := c.Service.Account.XKeySeed.KeyPair
	if xkey == nil {
		return fmt.Errorf("scoped accounts require service.account.xkey_seed")
	}
	public, err := xkey.PublicKey()
	if err != nil || !nkeys.IsValidPublicCurveKey(public) {
		return fmt.Errorf("scoped accounts require a curve xkey_seed")
	}
	for _, idp := range c.Idp {
		if idp.UserProjection == nil && c.Rbac.UserProjection == nil {
			return fmt.Errorf("scoped accounts require a projection for every IdP")
		}
		if idp.ValidationSpec.SkipAudienceValidation {
			return fmt.Errorf("scoped accounts forbid skip_audience_validation")
		}
	}
	for _, binding := range c.Rbac.RoleBinding {
		if !scoped[binding.Account] {
			continue
		}
		for _, name := range binding.Roles {
			role, err := c.lookupRole(name)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(role.Permissions, Permissions{}) || !reflect.DeepEqual(role.Limits, Limits{}) {
				return fmt.Errorf("scoped binding roles must not set permissions or limits")
			}
		}
	}
	return nil
}

// validateScopedSigner verifies the supplied account artifact and pinned operator
// signer. Deploy this same artifact to the NATS resolver: an unscoped key must
// never be accepted solely because a boolean says it is scoped.
func (account *UserAccountInfo) validateScopedSigner() error {
	if !nkeys.IsValidPublicOperatorKey(account.OperatorPublicKey) {
		return fmt.Errorf("operator_public_key must pin the account JWT's operator signer")
	}
	if len(account.AccountJWT) == 0 || len(account.AccountJWT) > projectionMaxInputBytes {
		return fmt.Errorf("account_jwt is required and must fit the input limit")
	}
	claims, err := jwt.DecodeAccountClaims(account.AccountJWT)
	if err != nil {
		return fmt.Errorf("invalid account_jwt")
	}
	if claims.Subject != account.PublicKey || claims.Issuer != account.OperatorPublicKey {
		return fmt.Errorf("account_jwt identity or operator signer mismatch")
	}
	validation := jwt.CreateValidationResults()
	claims.Validate(validation)
	if validation.IsBlocking(true) || (claims.Expires > 0 && claims.Expires <= time.Now().Unix()) {
		return fmt.Errorf("account_jwt failed validation")
	}
	if account.SigningNKey.KeyPair == nil {
		return fmt.Errorf("missing scoped signing_nkey")
	}
	signer, err := account.SigningNKey.KeyPair.PublicKey()
	if err != nil {
		return fmt.Errorf("invalid scoped signing_nkey")
	}
	scope, ok := claims.SigningKeys[signer].(*jwt.UserScope)
	if !ok || scope == nil || scope.Key != signer {
		return fmt.Errorf("account_jwt does not scope this signing key")
	}
	return nil
}

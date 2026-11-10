package broker

import (
	"fmt"
	"reflect"
	"strings"

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

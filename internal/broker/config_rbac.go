package broker

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	internal "github.com/jr200-labs/nats-iam-broker/internal"

	"github.com/nats-io/jwt/v2"
	"go.uber.org/zap"
)

// RoleBindingStrategy defines the strategy for matching role bindings.
type RoleBindingStrategy string

const (
	// StrategyBestMatch selects the binding with the most matching criteria.
	StrategyBestMatch RoleBindingStrategy = "best_match"
	// StrategyStrict requires all match criteria in a binding to succeed.
	StrategyStrict RoleBindingStrategy = "strict"
)

// UnmarshalYAML implements the yaml.Unmarshaler interface for RoleBindingStrategy.
func (rbs *RoleBindingStrategy) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}

	strLower := strings.ToLower(str)
	switch strLower {
	case string(StrategyStrict), string(StrategyBestMatch):
		*rbs = RoleBindingStrategy(strLower)
		return nil
	default:
		// Default to best_match if the value is empty or unrecognized
		if strLower == "" {
			zap.L().Warn("role_binding_matching_strategy is empty, using default", zap.String("default", string(StrategyBestMatch)))
			*rbs = StrategyBestMatch
			return nil
		}
		zap.L().Warn("unrecognized role_binding_matching_strategy, using default", zap.String("value", str), zap.String("default", string(StrategyBestMatch)))
		*rbs = StrategyBestMatch
		return nil // Or return an error if you want to reject invalid values: fmt.Errorf("invalid role binding strategy: %s", str)
	}
}

// Struct definitions
type Rbac struct {
	UserProjection              *UserProjection     `yaml:"user_projection"`
	Accounts                    []UserAccountInfo   `yaml:"user_accounts"`
	RoleBinding                 []RoleBinding       `yaml:"role_binding"`
	Roles                       []Role              `yaml:"roles"`
	TokenMaxExpiry              Duration            `yaml:"token_max_expiration"`
	RoleBindingMatchingStrategy RoleBindingStrategy `yaml:"role_binding_matching_strategy"`
	AutoAccountsDir             string              `yaml:"auto_accounts_dir"`
}

// discoverAccounts scans AutoAccountsDir for files matching *-id-1.pub and *-sk-1.nk pairs,
// extracts account names from the filename prefix, and returns UserAccountInfo entries.
// The public key is read from <name>-id-1.pub and the signing nkey from <name>-sk-1.nk.
func (r *Rbac) discoverAccounts() ([]UserAccountInfo, error) {
	if r.AutoAccountsDir == "" {
		return nil, nil
	}

	pubFiles, err := filepath.Glob(filepath.Join(r.AutoAccountsDir, "*-id-1.pub"))
	if err != nil {
		return nil, fmt.Errorf("error scanning auto_accounts_dir %q: %w", r.AutoAccountsDir, err)
	}

	var discovered []UserAccountInfo
	for _, pubFile := range pubFiles {
		base := filepath.Base(pubFile)
		// Extract account name: everything before "-id-1.pub"
		name := strings.TrimSuffix(base, "-id-1.pub")
		if name == base {
			continue // didn't match the suffix pattern
		}

		skFile := filepath.Join(r.AutoAccountsDir, name+"-sk-1.nk")
		if _, err := os.Stat(skFile); os.IsNotExist(err) {
			zap.L().Warn("auto_accounts_dir: found public key but no signing key, skipping",
				zap.String("account", name),
				zap.String("pub_file", pubFile),
				zap.String("expected_sk", skFile))
			continue
		}

		pubKeyBytes, err := os.ReadFile(pubFile)
		if err != nil {
			return nil, fmt.Errorf("error reading public key for account %q: %w", name, err)
		}

		skBytes, err := os.ReadFile(skFile)
		if err != nil {
			return nil, fmt.Errorf("error reading signing key for account %q: %w", name, err)
		}

		var signingNKey NKey
		if err := signingNKey.UnmarshalText(skBytes); err != nil {
			return nil, fmt.Errorf("error parsing signing key for account %q: %w", name, err)
		}

		discovered = append(discovered, UserAccountInfo{
			Name:        name,
			PublicKey:   strings.TrimSpace(string(pubKeyBytes)),
			SigningNKey: signingNKey,
		})

		zap.L().Info("auto_accounts_dir: discovered account",
			zap.String("account", name),
			zap.String("dir", r.AutoAccountsDir))
	}

	return discovered, nil
}

type UserAccountInfo struct {
	AccountJWT        string `yaml:"account_jwt"`
	OperatorPublicKey string `yaml:"operator_public_key"`
	Scoped            bool   `yaml:"scoped"`
	Name              string `yaml:"name"`
	PublicKey         string `yaml:"public_key"`
	SigningNKey       NKey   `yaml:"signing_nkey"`
}

type RoleBinding struct {
	Account        string   `yaml:"user_account"`
	Roles          []string `yaml:"roles"`
	TokenMaxExpiry Duration `yaml:"token_max_expiration"`
	Match          []Match  `yaml:"match"`
}

type Match struct {
	// Legacy fields (backward compatible)
	Claim      string `yaml:"claim,omitempty"`
	Value      string `yaml:"value,omitempty"`
	Permission string `yaml:"permission,omitempty"`
	// Expression-based matching using expr-lang/expr
	Expr string `yaml:"expr,omitempty"`
}

type Role struct {
	Name        string      `yaml:"name"`
	Permissions Permissions `yaml:"permissions"`
	Limits      Limits      `yaml:"limits"`
}

type Permissions struct {
	Pub  jwt.Permission     `yaml:"pub,omitempty"`
	Sub  jwt.Permission     `yaml:"sub,omitempty"`
	Resp ResponsePermission `yaml:"resp,omitempty"`
}

type ResponsePermission struct {
	MaxMsgs int      `yaml:"max_msgs"`
	Expires Duration `yaml:"exp"`
}

type Limits struct {
	UserLimits jwt.UserLimits `yaml:",inline"`
	NatsLimits jwt.NatsLimits `yaml:",inline"`
}

// loadOrCompileExpr returns a compiled expr program, using the cache if available.
func loadOrCompileExpr(expression string, context map[string]interface{}, cache *sync.Map) (*vm.Program, error) {
	if cache != nil {
		if cached, ok := cache.Load(expression); ok {
			return cached.(*vm.Program), nil
		}
	}

	program, err := expr.Compile(expression, expr.Env(context), expr.AsBool())
	if err != nil {
		return nil, err
	}

	if cache != nil {
		cache.Store(expression, program)
	}
	return program, nil
}

func (c *Config) lookupAccountInfo(userAccount string) (*UserAccountInfo, error) {
	for _, acinfo := range c.Rbac.Accounts {
		if acinfo.Name == userAccount {
			return &acinfo, nil
		}
	}

	return nil, fmt.Errorf("unknown user-account info: %s", userAccount)
}

// evaluateMatchCriterion checks if a single Match criterion is met by the context.
// It returns true if matched, along with a string describing the match, otherwise false and an empty string.
// exprCache is an optional cache of compiled expr-lang programs keyed by expression string.
func evaluateMatchCriterion(match Match, context map[string]interface{}, bindingIndex int, exprCache *sync.Map) (matched bool, description string) {
	// Handle expression-based matching
	if match.Expr != "" {
		program, err := loadOrCompileExpr(match.Expr, context, exprCache)
		if err != nil {
			zap.L().Error("match-fail[expr]: compile error", zap.String("expr", match.Expr), zap.Int("binding_index", bindingIndex), zap.Error(err))
			return false, ""
		}

		result, err := expr.Run(program, context)
		if err != nil {
			zap.L().Debug("match-fail[expr]: eval error", zap.String("expr", match.Expr), zap.Int("binding_index", bindingIndex), zap.Error(err))
			return false, ""
		}

		if boolResult, ok := result.(bool); ok && boolResult {
			zap.L().Debug("match-pass[expr]", zap.String("expr", match.Expr), zap.Int("binding_index", bindingIndex))
			return true, fmt.Sprintf("expr=%s", match.Expr)
		}

		zap.L().Debug("match-fail[expr]", zap.String("expr", match.Expr), zap.Int("binding_index", bindingIndex))
		return false, ""
	}

	// Handle permission-based matching
	if match.Permission != "" {
		isPermissionMatched := false
		if permissions, ok := context["permissions"].([]interface{}); ok {
			for _, p := range permissions {
				if permission, ok := p.(string); ok && permission == match.Permission {
					isPermissionMatched = true
					break
				}
			}
		} else if permission, ok := context["permissions"].(string); ok && permission == match.Permission {
			isPermissionMatched = true
		}

		if isPermissionMatched {
			zap.L().Debug("match-pass[permission]", zap.String("permission", match.Permission), zap.Int("binding_index", bindingIndex))
			return true, fmt.Sprintf("permission=%s", match.Permission)
		}

		zap.L().Debug("match-fail[permission]", zap.String("permission", match.Permission), zap.Int("binding_index", bindingIndex))
		return false, ""
	}

	// Handle regular claim-based matching
	contextValue, exists := context[match.Claim]
	if !exists {
		zap.L().Debug("match-skip: claim key not found in context", zap.String("claim", match.Claim), zap.Int("binding_index", bindingIndex))
		return false, "" // Claim doesn't exist, so it's not a match for this criterion
	}

	isClaimMatched := false
	switch v := contextValue.(type) {
	case string:
		if v == match.Value {
			isClaimMatched = true
			zap.L().Debug("match-pass[claim]", zap.String("claim", match.Claim), zap.String("expected", match.Value), zap.String("actual", v), zap.Int("binding_index", bindingIndex))
		}
	case []interface{}:
		for _, val := range v {
			if sv, ok := val.(string); ok && sv == match.Value {
				isClaimMatched = true
				zap.L().Debug("match-pass[claim]", zap.String("claim", match.Claim), zap.String("expected", match.Value), zap.Any("actual", val), zap.Int("binding_index", bindingIndex))
				break
			}
		}
	case map[string]interface{}:
		if _, ok := v[match.Value]; ok {
			isClaimMatched = true
			zap.L().Debug("match-pass[claim]: key exists in map", zap.String("claim", match.Claim), zap.String("key", match.Value), zap.Int("binding_index", bindingIndex))
		}
	case map[string]string:
		if _, ok := v[match.Value]; ok {
			isClaimMatched = true
			zap.L().Debug("match-pass[claim]: key exists in map", zap.String("claim", match.Claim), zap.String("key", match.Value), zap.Int("binding_index", bindingIndex))
		}
	default:
		zap.L().Debug("match-skip: unsupported type", zap.String("claim", match.Claim), zap.String("type", fmt.Sprintf("%T", v)), zap.Int("binding_index", bindingIndex))
		// Unsupported type cannot match the string value
	}

	if isClaimMatched {
		return true, fmt.Sprintf("%s=%s", match.Claim, match.Value)
	}

	zap.L().Debug("match-fail[claim]: value not found in context", zap.String("claim", match.Claim), zap.String("expected", match.Value), zap.Any("context_value", contextValue), zap.Int("binding_index", bindingIndex))
	return false, ""
}

func (c *Config) lookupUserAccount(context map[string]interface{}) (string, *jwt.Permissions, *jwt.Limits, Duration, error) {
	type matchResult struct {
		matches          int
		numMatchCriteria int // Store the number of criteria in the matched binding
		account          string
		permissions      *jwt.Permissions
		limits           *jwt.Limits
		maxExpiry        Duration
		roleBindingName  string // Use a descriptive name, account might not be unique
		matchedOn        []string
	}

	var bestMatch matchResult
	var fallbackBinding *RoleBinding
	var fallbackIndex int

	strategy := c.Rbac.RoleBindingMatchingStrategy
	zap.L().Debug("Using role binding matching strategy", zap.String("strategy", string(strategy)))

	for i, roleBinding := range c.Rbac.RoleBinding {
		currentMatches := 0
		currentMatchedOn := []string{}
		numMatchCriteria := len(roleBinding.Match)

		if numMatchCriteria == 0 {
			if fallbackBinding == nil {
				fallbackBinding = &c.Rbac.RoleBinding[i]
				fallbackIndex = i
				zap.L().Debug("recorded fallback role binding", zap.Int("binding_index", i), zap.String("account", roleBinding.Account))
			}
			continue
		}

		// Evaluate all match criteria for this binding
		bindingFullyMatched := true // Assume full match for strict initially
		for _, match := range roleBinding.Match {
			matched, description := evaluateMatchCriterion(match, context, i, c.exprCache)

			if matched {
				currentMatches++
				currentMatchedOn = append(currentMatchedOn, description)
			} else {
				// If even one criterion fails, it's not a full match for strict strategy
				bindingFullyMatched = false
				// For strict matching, if one fails, we can stop checking this binding
				if strategy == StrategyStrict {
					currentMatches = -1 // Mark as failed for strict comparison later
					break               // Stop checking criteria for this binding
				}
			}
		}

		// --- Strategy-based selection ---

		if strategy == StrategyStrict {
			// Check if the loop completed without breaking (currentMatches != -1)
			// and if all criteria were actually checked and matched.
			// We use bindingFullyMatched which covers the case where the loop didn't break
			// because no criterion failed, but also ensures all criteria were indeed met.
			if bindingFullyMatched && currentMatches == numMatchCriteria {
				// Strict match found! Use the first one found
				zap.L().Debug("selected first strictly matching role binding",
					zap.Int("matched_count", currentMatches),
					zap.Int("required_count", numMatchCriteria),
					zap.Int("binding_index", i),
					zap.String("role_binding_account", roleBinding.Account),
					zap.Strings("matched_on", currentMatchedOn))

				permissions, limits, err := c.collateRoles(roleBinding.Roles)
				if err != nil {
					return "", nil, nil, Duration{}, err
				}
				return roleBinding.Account, permissions, limits, roleBinding.TokenMaxExpiry, nil
			}
			// If not a full match in strict mode, continue to the next binding
			continue
		}

		// best_match strategy
		if currentMatches > 0 { // Only consider bindings with at least one match
			updateBestMatch := false
			if currentMatches > bestMatch.matches {
				// More matches than current best
				updateBestMatch = true
			} else if currentMatches == bestMatch.matches {
				// Same number of matches, check the number of criteria
				if numMatchCriteria > bestMatch.numMatchCriteria {
					// More specific match (more criteria)
					updateBestMatch = true
				}
				// If numMatchCriteria is also the same, the first one encountered wins (no need to update)
			}

			if updateBestMatch {
				permissions, limits, err := c.collateRoles(roleBinding.Roles)
				if err != nil {
					return "", nil, nil, Duration{}, err
				}
				bestMatch = matchResult{
					matches:          currentMatches,
					numMatchCriteria: numMatchCriteria, // Store the number of criteria
					account:          roleBinding.Account,
					permissions:      permissions,
					limits:           limits,
					maxExpiry:        roleBinding.TokenMaxExpiry,
					roleBindingName:  fmt.Sprintf("%s (Index: %d)", roleBinding.Account, i), // More descriptive name
					matchedOn:        currentMatchedOn,
				}
				zap.L().Debug("new best match found", zap.Int("binding_index", i), zap.Int("matches", currentMatches), zap.Int("criteria", numMatchCriteria))
			}
		}
	}

	// --- Final Return Logic ---

	if strategy == StrategyStrict {
		// If we finished the loop in strict mode, no binding fully matched
		if fallbackBinding != nil {
			zap.L().Debug("no strict match found, using fallback role binding",
				zap.Int("binding_index", fallbackIndex),
				zap.String("role_binding_account", fallbackBinding.Account))
			permissions, limits, err := c.collateRoles(fallbackBinding.Roles)
			if err != nil {
				return "", nil, nil, Duration{}, err
			}
			return fallbackBinding.Account, permissions, limits, fallbackBinding.TokenMaxExpiry, nil
		}
		return "", nil, nil, Duration{}, fmt.Errorf("no role-binding strictly matched idp token")
	}

	// best_match: Check if any match was found
	if bestMatch.matches == 0 {
		if fallbackBinding != nil {
			zap.L().Debug("no best_match found, using fallback role binding",
				zap.Int("binding_index", fallbackIndex),
				zap.String("role_binding_account", fallbackBinding.Account))
			permissions, limits, err := c.collateRoles(fallbackBinding.Roles)
			if err != nil {
				return "", nil, nil, Duration{}, err
			}
			return fallbackBinding.Account, permissions, limits, fallbackBinding.TokenMaxExpiry, nil
		}
		return "", nil, nil, Duration{}, fmt.Errorf("no role-binding matched idp token using best_match strategy")
	}

	zap.L().Debug("selected role binding using best_match strategy",
		zap.Int("matches", bestMatch.matches),
		zap.Int("criteria_count", bestMatch.numMatchCriteria),
		zap.String("account", bestMatch.account),
		zap.String("role_binding", bestMatch.roleBindingName),
		zap.Strings("matched_on", bestMatch.matchedOn))

	return bestMatch.account, bestMatch.permissions, bestMatch.limits, bestMatch.maxExpiry, nil
}

func (c *Config) collateRoles(roles []string) (*jwt.Permissions, *jwt.Limits, error) {
	allPermissions := jwt.Permissions{
		Resp: &jwt.ResponsePermission{
			Expires: 0,
			MaxMsgs: 0,
		},
	}

	allLimits := jwt.Limits{
		UserLimits: jwt.UserLimits{
			Src:    jwt.CIDRList{},
			Times:  nil,
			Locale: "",
		},
		NatsLimits: jwt.NatsLimits{
			Subs:    jwt.NoLimit,
			Data:    jwt.NoLimit,
			Payload: jwt.NoLimit,
		},
	}

	for _, roleName := range roles {
		role, err := c.lookupRole(roleName)
		if err != nil {
			return nil, nil, err
		}

		zap.L().Debug("assigning role",
			zap.String("role", roleName),
			zap.String("permissions", string(internal.IgnoreError(json.Marshal(role.Permissions)))),
			zap.String("limits", string(internal.IgnoreError(json.Marshal(role.Limits)))),
		)

		collatePermissions(&allPermissions, &role.Permissions)
		collateLimits(&allLimits, &role.Limits)
	}

	zap.L().Debug("collated roles",
		zap.String("permissions", string(internal.IgnoreError(json.Marshal(allPermissions)))),
		zap.String("limits", string(internal.IgnoreError(json.Marshal(allLimits)))),
	)

	if err := validateRenderedPermissions(&allPermissions); err != nil {
		return nil, nil, err
	}
	return &allPermissions, &allLimits, nil
}

func collateLimits(base *jwt.Limits, other *Limits) {
	base.UserLimits.Src.Add(other.UserLimits.Src...)
	base.UserLimits.Times = other.UserLimits.Times
	base.UserLimits.Locale = other.UserLimits.Locale

	base.NatsLimits.Subs = other.NatsLimits.Subs
	base.NatsLimits.Data = other.NatsLimits.Data
	base.NatsLimits.Payload = other.NatsLimits.Payload
}

func collatePermissions(base *jwt.Permissions, other *Permissions) {
	base.Pub.Allow.Add(other.Pub.Allow...)
	base.Pub.Deny.Add(other.Pub.Deny...)

	base.Sub.Allow.Add(other.Sub.Allow...)
	base.Sub.Deny.Add(other.Sub.Deny...)

	if other.Resp.Expires.Duration > 0 {
		base.Resp.Expires = other.Resp.Expires.Duration
	}
	if other.Resp.MaxMsgs > 0 {
		base.Resp.MaxMsgs = other.Resp.MaxMsgs
	}
}

func (c *Config) lookupRole(roleName string) (*Role, error) {
	for _, role := range c.Rbac.Roles {
		if role.Name == roleName {
			return &role, nil
		}
	}

	return nil, fmt.Errorf("unknown role: %s", roleName)
}

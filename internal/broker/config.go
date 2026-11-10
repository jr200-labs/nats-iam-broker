package broker

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-playground/validator"
	"github.com/goccy/go-yaml"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/xhit/go-str2duration/v2"
	"go.uber.org/zap"
)

const (
	DefaultTokenExpiryBoundsLower = 1 * time.Minute
	DefaultTokenExpiryBoundsUpper = 1 * time.Hour

	configPhaseInitial = "initial"
	configPhaseRender  = "render"
)

// configParsePhase tracks which config parsing phase is active.
// During "initial" phase, template parse failures are expected and logged at Debug.
// During "render" phase, they indicate a real template rendering failure and are logged at Warn.
// Uses atomic.Value for thread safety since UnmarshalText is called concurrently via GetConfig.
var configParsePhase atomic.Value

func init() {
	configParsePhase.Store(configPhaseRender)
}

func getConfigParsePhase() string {
	return configParsePhase.Load().(string)
}

func setConfigParsePhase(phase string) {
	configParsePhase.Store(phase)
}

// Struct definitions
type Config struct {
	AppParams ConfigParams `yaml:"params"`
	Server    Options      `yaml:"server"`
	NATS      NATS         `yaml:"nats" validate:"required"`
	Service   Service      `yaml:"service" validate:"required"`
	Idp       []Idp        `yaml:"idp" validate:"required"`
	Rbac      Rbac         `yaml:"rbac" validate:"required"`

	exprCache *sync.Map `yaml:"-"` // shared compiled expr-lang expression cache
}

type ConfigParams struct {
	LeftDelim  string `yaml:"left_delim"`
	RightDelim string `yaml:"right_delim"`
}

type NATS struct {
	URL               string         `yaml:"url" validate:"required"`
	TokenExpiryBounds DurationBounds `yaml:"jwt_expiry_bounds" validate:"required"`
}

type Service struct {
	Name        string `yaml:"name" validate:"required"`
	Description string `yaml:"description" validate:"required"`
	// Version is optional. If empty, the broker resolves the runtime
	// service version from (in order) the IAM_SERVICE_VERSION env var,
	// the ldflags-injected internal/version.Version, then "dev". See
	// internal/broker.ResolveServiceVersion. When provided, must still
	// be valid semver. Historically required; relaxed in v1.3.0 so the
	// running image tag (injected via Helm) becomes the source of truth.
	Version   string         `yaml:"version" validate:"omitempty,semver"`
	CredsFile string         `yaml:"creds_file" validate:"required"`
	Account   ServiceAccount `yaml:"account" validate:"required"`
}

type ServiceAccount struct {
	Name        string `yaml:"name"`
	SigningNKey NKey   `yaml:"signing_nkey" validate:"required"`
	XKeySeed    NKey   `yaml:"xkey_seed"`
}

type Idp struct {
	Key               string               `yaml:"key"`
	UserProjection    *UserProjection      `yaml:"user_projection"`
	Description       string               `yaml:"description"`
	IssuerURL         string               `yaml:"issuer_url" validate:"required"`
	ClientID          string               `yaml:"client_id" validate:"required"`
	ValidationSpec    IdpJwtValidationSpec `yaml:"validation"`
	UserInfo          UserInfoConfig       `yaml:"user_info"`
	TokenExpiryBounds DurationBounds       `yaml:"token_bounds"`
	CustomMapping     map[string]string    `yaml:"custom_mapping"`
	IgnoreSetupError  bool                 `yaml:"ignore_setup_error"`
	MaxTokenLifetime  Duration             `yaml:"max_token_lifetime"`
	ClockSkew         Duration             `yaml:"clock_skew"`
}

type UserInfoConfig struct {
	Enabled bool `yaml:"enabled"`
}

type IdpJwtValidationSpec struct {
	Claims                 []string          `yaml:"claims"`
	Audience               []string          `yaml:"aud"`
	SkipAudienceValidation bool              `yaml:"skip_audience_validation"`
	TokenExpiryBounds      DurationBounds    `yaml:"token_bounds"`
	CustomClaimsMapping    map[string]string `yaml:"custom_claims_mapping"`
}

type DurationBounds struct {
	Min Duration `yaml:"min"`
	Max Duration `yaml:"max" validate:"required"`
}

type Duration struct {
	Duration time.Duration
}

type NKey struct {
	KeyPair nkeys.KeyPair
}

type TokenRequest struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Traceparent  string `json:"traceparent"`
}

type ConfigManager struct {
	mergedYAML string
	baseConfig Config // stores the initial config with defaults

	// Cached resources to avoid re-creation on every GetConfig call
	validate      *validator.Validate
	templateCache *templateCache
	exprCache     *sync.Map // map[string]*vm.Program — compiled expr-lang expressions
}

// ServerOptions returns the server options parsed from the YAML configuration.
func (cm *ConfigManager) ServerOptions() Options {
	return cm.baseConfig.Server
}

// NewConfigManager creates a new ConfigManager instance
func NewConfigManager(files []string) (*ConfigManager, error) {
	merged, err := mergeConfigurationFiles(files)
	if err != nil {
		return nil, err
	}

	// Initialize base config with defaults
	baseConfig := Config{}

	// Parse the merged YAML into base config
	// Template expressions haven't been rendered yet, so parse failures for
	// templated values (NKey, Duration) are expected and logged at Debug level.
	setConfigParsePhase(configPhaseInitial)
	if err := yaml.UnmarshalWithOptions([]byte(merged), &baseConfig, yaml.DisallowUnknownField()); err != nil {
		setConfigParsePhase(configPhaseRender)
		return nil, improveYAMLErrorMessage(err)
	}
	setConfigParsePhase(configPhaseRender)

	if baseConfig.Service.Name == "" {
		return nil, fmt.Errorf("missing configuration value service.name")
	}

	if baseConfig.AppParams.LeftDelim == "" {
		baseConfig.AppParams.LeftDelim = "{{"
	}
	if baseConfig.AppParams.RightDelim == "" {
		baseConfig.AppParams.RightDelim = "}}"
	}

	if baseConfig.NATS.TokenExpiryBounds.Min.Duration == 0 {
		baseConfig.NATS.TokenExpiryBounds.Min.Duration = DefaultTokenExpiryBoundsLower
	}
	if baseConfig.NATS.TokenExpiryBounds.Max.Duration == 0 {
		baseConfig.NATS.TokenExpiryBounds.Max.Duration = DefaultTokenExpiryBoundsUpper
	}

	if err := baseConfig.compileProjections(); err != nil {
		return nil, err
	}

	// Pre-compile validator with custom validations
	v := validator.New()
	if err := v.RegisterValidation("semver", validateSemVer); err != nil {
		return nil, fmt.Errorf("error registering semver validation: %v", err)
	}

	// Pre-compile template regex and templates
	tc := newTemplateCache(merged, baseConfig.AppParams)

	return &ConfigManager{
		mergedYAML:    merged,
		baseConfig:    baseConfig,
		validate:      v,
		templateCache: tc,
		exprCache:     &sync.Map{},
	}, nil
}

// GetConfig renders the merged YAML and returns a Config instance
func (cm *ConfigManager) GetConfig(mappings map[string]interface{}) (*Config, error) {
	// Create a new config instance starting with the base config
	cfg := cm.baseConfig

	// Render templates only within parsed scalar values so rendered data cannot
	// alter the YAML document structure.
	renderedYAML, err := cm.templateCache.renderYAML(cm.mergedYAML, mappings)
	if err != nil {
		return nil, err
	}

	// Create a temporary config to hold rendered values
	var tempCfg Config
	if err := yaml.UnmarshalWithOptions([]byte(renderedYAML), &tempCfg, yaml.DisallowUnknownField()); err != nil {
		return nil, improveYAMLErrorMessage(err)
	}

	// Selectively update fields that might have been templated
	// while preserving special types from the base config
	cfg.NATS.URL = tempCfg.NATS.URL
	cfg.NATS.TokenExpiryBounds = tempCfg.NATS.TokenExpiryBounds
	if cfg.NATS.TokenExpiryBounds.Max.Duration == 0 {
		cfg.NATS.TokenExpiryBounds.Max.Duration = DefaultTokenExpiryBoundsUpper
	}
	if cfg.NATS.TokenExpiryBounds.Min.Duration == 0 {
		cfg.NATS.TokenExpiryBounds.Min.Duration = DefaultTokenExpiryBoundsLower
	}

	cfg.Service.Name = tempCfg.Service.Name
	cfg.Service.Description = tempCfg.Service.Description
	cfg.Service.Version = tempCfg.Service.Version
	cfg.Service.CredsFile = tempCfg.Service.CredsFile

	// Sanitize service name for use in NATS subjects
	// NATS subjects cannot contain spaces, tabs, CR, LF, or the following characters: . * > /
	// Replace any illegal characters inside the string with underscore
	// Remove illegal characters at the start or end of the string
	illegalChars := " \t\r\n.*>/"
	if strings.ContainsAny(cfg.Service.Name, illegalChars) {
		// First, replace illegal chars inside the string with underscores
		sanitizedName := cfg.Service.Name
		for _, c := range illegalChars {
			sanitizedName = strings.ReplaceAll(sanitizedName, string(c), "_")
		}

		// Then trim any remaining illegal chars from start and end
		sanitizedName = strings.TrimFunc(sanitizedName, func(r rune) bool {
			return strings.ContainsRune(illegalChars, r)
		})

		zap.L().Warn("Service name contained illegal characters for NATS subjects, sanitizing", zap.String("original", cfg.Service.Name), zap.String("sanitized", sanitizedName))
		cfg.Service.Name = sanitizedName
	}

	// Only update NKeys if they were successfully parsed in the temp config
	if tempCfg.Service.Account.SigningNKey.KeyPair != nil {
		cfg.Service.Account.SigningNKey = tempCfg.Service.Account.SigningNKey
	}
	if tempCfg.Service.Account.XKeySeed.KeyPair != nil {
		cfg.Service.Account.XKeySeed = tempCfg.Service.Account.XKeySeed
	}

	cfg.Service.Account.Name = tempCfg.Service.Account.Name

	// Update IDP list and RBAC
	cfg.Idp = tempCfg.Idp
	cfg.Rbac = tempCfg.Rbac
	// Projection rules are literal and compiled once, never per-request templates.
	cfg.Rbac.UserProjection = cm.baseConfig.Rbac.UserProjection
	for i := range cfg.Idp {
		cfg.Idp[i].UserProjection = cm.baseConfig.Idp[i].UserProjection
	}

	// Validate the final config using pre-compiled validator
	if err := cm.validate.Struct(&cfg); err != nil {
		if validationErrors, ok := err.(validator.ValidationErrors); ok {
			var errorMessages []string
			for _, fieldErr := range validationErrors {
				errorMessages = append(errorMessages, "Field '"+fieldErr.Field()+"' is required")
			}
			return nil, fmt.Errorf("%s", strings.Join(errorMessages, ", "))
		}
		return nil, err
	}

	// Discover and merge auto-accounts if auto_accounts_dir is set
	if cfg.Rbac.AutoAccountsDir != "" {
		discovered, err := cfg.Rbac.discoverAccounts()
		if err != nil {
			return nil, fmt.Errorf("auto-account discovery failed: %w", err)
		}
		// Merge discovered accounts, skipping any that already exist by name
		existing := make(map[string]bool, len(cfg.Rbac.Accounts))
		for _, acct := range cfg.Rbac.Accounts {
			existing[acct.Name] = true
		}
		for _, acct := range discovered {
			if existing[acct.Name] {
				zap.L().Debug("auto_accounts_dir: skipping already-defined account", zap.String("account", acct.Name))
				continue
			}
			cfg.Rbac.Accounts = append(cfg.Rbac.Accounts, acct)
		}
	}

	// Warn about role bindings with missing account or roles
	for i, rb := range cfg.Rbac.RoleBinding {
		if rb.Account == "" {
			zap.L().Warn("role binding has empty 'user_account' — auth requests matching this binding will fail",
				zap.Int("binding_index", i),
				zap.Int("match_criteria", len(rb.Match)))
		}
		if len(rb.Roles) == 0 {
			zap.L().Warn("role binding has no 'roles' assigned — matched users will get empty permissions",
				zap.Int("binding_index", i),
				zap.String("user_account", rb.Account))
		}
	}

	if err := cfg.validateScopedAccounts(); err != nil {
		return nil, err
	}

	// Attach shared expression cache for role binding evaluation
	cfg.exprCache = cm.exprCache

	return &cfg, nil
}

// natsOptions returns the NATS options for the service account
func (c *Config) natsOptions() []nats.Option {
	natsCreds := c.Service.CredsFile

	var opts []nats.Option
	if natsCreds != "" {
		opts = append(opts, nats.UserCredentials(natsCreds))
	}
	return opts
}

// serviceEncryptionXkey returns the encryption key pair for the service account.
// Encryption is enabled when an xkey_seed is configured.
func (c *Config) serviceEncryptionXkey() nkeys.KeyPair {
	return c.Service.Account.XKeySeed.KeyPair
}

// UnmarshalText unmarshals a Duration from a string
func (v *Duration) UnmarshalText(text []byte) error {
	d, err := str2duration.ParseDuration(string(text))
	if err != nil {
		s := string(text)
		if strings.Contains(s, "{{") && getConfigParsePhase() == configPhaseInitial {
			zap.L().Debug("skipped parsing duration (unrendered template)",
				zap.String("value", s))
		} else {
			zap.L().Warn("failed to parse duration",
				zap.String("value", s), zap.Error(err))
		}
		return nil
	}
	v.Duration = d
	return nil
}

// UnmarshalText unmarshals a NKey from a string
func (v *NKey) UnmarshalText(text []byte) error {
	text = bytes.TrimSpace(text)
	nkey, err := nkeys.FromSeed(text)
	if err != nil {
		s := string(text)
		if strings.Contains(s, "{{") && getConfigParsePhase() == configPhaseInitial {
			zap.L().Debug("skipped parsing nkey (unrendered template)",
				zap.String("value", SecureLogKey(s)))
		} else {
			zap.L().Warn("failed to parse nkey",
				zap.String("value", SecureLogKey(s)), zap.Error(err))
		}
		return nil
	}
	v.KeyPair = nkey
	return nil
}

// UnmarshalYAML implements scalar decoding for Duration (supports strings, numbers, or maps with value/max/min)
func (v *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try string
	var s string
	if err := unmarshal(&s); err == nil {
		return v.UnmarshalText([]byte(s))
	}

	// Try integer nanoseconds
	var i64 int64
	if err := unmarshal(&i64); err == nil {
		v.Duration = time.Duration(i64)
		return nil
	}

	// Try float nanoseconds
	var f64 float64
	if err := unmarshal(&f64); err == nil {
		v.Duration = time.Duration(f64)
		return nil
	}

	// Try map forms: {value: "1h"} or {max: "1h"} or {min: "1h"}
	var m map[string]interface{}
	if err := unmarshal(&m); err == nil {
		for _, key := range []string{"value", "max", "min"} {
			if val, ok := m[key]; ok {
				switch vv := val.(type) {
				case string:
					return v.UnmarshalText([]byte(vv))
				case int:
					v.Duration = time.Duration(vv)
					return nil
				case int64:
					v.Duration = time.Duration(vv)
					return nil
				case float64:
					v.Duration = time.Duration(vv)
					return nil
				default:
					return fmt.Errorf("invalid duration.%s type %T", key, vv)
				}
			}
		}
		return fmt.Errorf("invalid duration map keys %v", m)
	}

	// Fallback
	var raw interface{}
	if err := unmarshal(&raw); err != nil {
		return err
	}
	switch x := raw.(type) {
	case string:
		return v.UnmarshalText([]byte(x))
	case int:
		v.Duration = time.Duration(x)
		return nil
	case int64:
		v.Duration = time.Duration(x)
		return nil
	case float64:
		v.Duration = time.Duration(x)
		return nil
	default:
		return fmt.Errorf("invalid duration type %T", raw)
	}
}

// UnmarshalYAML implements scalar decoding for NKey
func (v *NKey) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	return v.UnmarshalText([]byte(s))
}

// Helper function to improve YAML unmarshaling error messages
func improveYAMLErrorMessage(err error) error {
	errMsg := err.Error()

	// Check for unknown field errors (from DisallowUnknownField)
	var unknownFieldErr *yaml.UnknownFieldError
	if errors.As(err, &unknownFieldErr) {
		return fmt.Errorf("YAML configuration error: %w\n\n"+
			"This field is not recognized. Common causes:\n"+
			"  - Incorrect indentation (e.g. a field nested inside 'match' that belongs on the role-binding level)\n"+
			"  - Typo in the field name\n"+
			"  - Using camelCase instead of snake_case (e.g. 'tokenMaxExpiration' should be 'token_max_expiration')\n"+
			"Check the indentation and field names in ALL your config files.", err)
	}

	// Check if it's an unmarshaling error
	if !strings.Contains(errMsg, "unmarshal") {
		return err
	}

	// First check for the specific array error pattern that doesn't get captured properly
	if strings.Contains(errMsg, "cannot unmarshal !!map into []") {
		// Extract a more helpful line number if possible
		lineMatch := regexp.MustCompile(`line (\d+):`).FindStringSubmatch(errMsg)
		lineNum := "unknown"
		//nolint:mnd // 2 is the index of the line number capture group in the regex
		if len(lineMatch) >= 2 {
			lineNum = lineMatch[1]
		}

		// Extract the type if possible
		typeMatch := regexp.MustCompile(`into \[\]([^\s]+)`).FindStringSubmatch(errMsg)
		typeStr := "array"
		//nolint:mnd // 2 is the index of the type capture group in the regex
		if len(typeMatch) >= 2 {
			typeStr = typeMatch[1]
		}

		typeExplanation := fmt.Sprintf(
			"In your YAML configuration: Found a single object where an array was expected.\n"+
				"The merged configuration shows this at line %s, but it might be in any of your config files.\n"+
				"Field type: []%s\n"+
				"Check ALL your config files for this pattern:\n"+
				"  field: { key: value }\n"+
				"And replace with:\n"+
				"  field:\n"+
				"  - { key: value }\n"+
				"Note the dash (-) which indicates an array element.",
			lineNum, typeStr)

		return fmt.Errorf("YAML configuration error: %s\n\nOriginal error: %v", typeExplanation, err)
	}

	// Extract line number and type information if available
	lineMatch := regexp.MustCompile(`line (\d+):.*unmarshal !!(\w+) into \[?]?([^\s]+)`).FindStringSubmatch(errMsg)
	//nolint:mnd // 4 is the minimum length of lineMatch array to have all capture groups
	if len(lineMatch) >= 4 {
		lineNum := lineMatch[1]
		actualType := lineMatch[2]
		expectedType := lineMatch[3]

		typeExplanation := ""

		// Common type mismatch scenarios
		switch {
		case actualType == "map" && strings.HasPrefix(expectedType, "[]"):
			// Map into array error
			typeExplanation = fmt.Sprintf(
				"In your YAML configuration: Found a single object where an array was expected.\n"+
					"The merged configuration shows this at line %s, but it might be in any of your config files.\n"+
					"Field type: %s\n"+
					"Check ALL your config files for this pattern:\n"+
					"  field: { key: value }\n"+
					"And replace with:\n"+
					"  field:\n"+
					"  - { key: value }\n"+
					"Note the dash (-) which indicates an array element.",
				lineNum, expectedType)
		case actualType == "seq" && !strings.HasPrefix(expectedType, "[]"):
			// Array into non-array error
			typeExplanation = fmt.Sprintf(
				"In your YAML configuration: Found an array where a single object was expected.\n"+
					"The merged configuration shows this at line %s, but it might be in any of your config files.\n"+
					"Field type: %s\n"+
					"Check ALL your config files for this pattern:\n"+
					"  field:\n"+
					"  - key: value\n"+
					"And replace with:\n"+
					"  field:\n"+
					"    key: value\n"+
					"Remove the dash (-) since this isn't an array.",
				lineNum, expectedType)
		default:
			// Generic type mismatch
			typeExplanation = fmt.Sprintf(
				"In your YAML configuration: Type mismatch - found '%s' but expected '%s'.\n"+
					"The merged configuration shows this at line %s, but it might be in any of your config files.\n"+
					"Check the YAML structure in all your configuration files.",
				actualType, expectedType, lineNum)
		}

		return fmt.Errorf("YAML configuration error: %s\n\nOriginal error: %v", typeExplanation, err)
	}

	// If we couldn't parse the specific error, return a slightly improved general message
	return fmt.Errorf("error in YAML configuration. Please check your YAML syntax and field types.\nOriginal error: %v", err)
}

// mergeConfigurationFiles merges the given YAML files into a single YAML string
func mergeConfigurationFiles(files []string) (string, error) {
	var mergedMap map[string]interface{}

	for _, pattern := range files {
		paths := []string{pattern}
		if strings.ContainsAny(pattern, "*?[]") {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				return "", fmt.Errorf("invalid glob pattern %q: %v", pattern, err)
			}
			if len(matches) == 0 {
				return "", fmt.Errorf("glob pattern %q did not match any files", pattern)
			}
			paths = matches
		}

		for _, filePath := range paths {
			zap.L().Debug("merging config", zap.String("file", filePath))
			raw, err := os.ReadFile(filePath)
			if err != nil {
				return "", fmt.Errorf("error reading file content: %v", err)
			}

			var nextMapToMerge map[string]interface{}
			if err := yaml.Unmarshal(raw, &nextMapToMerge); err != nil {
				return "", fmt.Errorf("error in file %s: %v", filePath, improveYAMLErrorMessage(err))
			}

			if mergedMap == nil {
				mergedMap = nextMapToMerge
				continue
			}

			// Recursively merge the maps
			mergedMap = deepMerge(mergedMap, nextMapToMerge)
		}
	}

	mergedYAML, err := yaml.Marshal(mergedMap)
	if err != nil {
		return "", fmt.Errorf("error marshalling merged config to YAML: %v", err)
	}

	return string(mergedYAML), nil
}

// deepMerge recursively merges overlay into base. Maps are merged recursively,
// arrays are concatenated (not replaced), and primitive values from overlay
// take precedence over base.
func deepMerge(base, overlay map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// Copy base map
	for k, v := range base {
		result[k] = v
	}

	// Merge overlay map
	for k, v := range overlay {
		if baseVal, exists := result[k]; exists {
			// If both values are maps, merge them recursively
			if baseMap, ok := baseVal.(map[string]interface{}); ok {
				if overlayMap, ok := v.(map[string]interface{}); ok {
					result[k] = deepMerge(baseMap, overlayMap)
					continue
				}
			}

			// If both values are arrays, concatenate them
			if baseArr, ok := baseVal.([]interface{}); ok {
				if overlayArr, ok := v.([]interface{}); ok {
					result[k] = append(baseArr, overlayArr...)
					continue
				}
			}

			// For primitive types (strings, numbers, bools), overlay value takes precedence
			result[k] = v
			continue
		}

		// If key doesn't exist in base, add from overlay
		result[k] = v
	}

	return result
}

// validateSemVer validates that a version string is a valid semantic version
func validateSemVer(fl validator.FieldLevel) bool {
	version := fl.Field().String()
	semVerRegex := `^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$`
	r := regexp.MustCompile(semVerRegex)
	return r.MatchString(version)
}

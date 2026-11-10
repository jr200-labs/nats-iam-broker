package broker

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"go.uber.org/zap"
)

// Mapping of JSON field names to struct field names
var jsonToField = map[string]string{
	"name":               "Name",
	"given_name":         "GivenName",
	"family_name":        "FamilyName",
	"preferred_username": "PreferredUsername",
	"nickname":           "Nickname",
	"gender":             "Gender",
	"zoneinfo":           "ZoneInfo",
	"locale":             "Locale",
	"client_id":          "ClientID",
	"groups":             "Groups",
	"roles":              "Roles",
	"email":              "Email",
	"email_verified":     "EmailVerified",
	"picture":            "Picture",
	"sub":                "Subject",
	"exp":                "Expiry",
	"iat":                "IssuedAt",
	"nbf":                "NotBeforeTime",
	"jti":                "JwtID",
	"at_hash":            "AccessTokenHash",
	"also_known_as":      "AlsoKnownAs",
}

// Standard claims that are handled by the IdpJwtClaims struct
var standardClaims = func() map[string]bool {
	claims := make(map[string]bool)
	for k := range jsonToField {
		claims[k] = true
	}
	claims["aud"] = true // Add audience separately as it's handled specially
	return claims
}()

// https://www.iana.org/assignments/jwt/jwt.xhtml#claims
type IdpJwtClaims struct {
	signedExpiry      int64
	projected         *NatsUser
	Name              string                 `json:"name,omitempty"`
	GivenName         string                 `json:"given_name,omitempty"`
	FamilyName        string                 `json:"family_name,omitempty"`
	PreferredUsername string                 `json:"preferred_username,omitempty"`
	Nickname          string                 `json:"nickname,omitempty"`
	Gender            string                 `json:"gender,omitempty"`
	ZoneInfo          string                 `json:"zoneinfo,omitempty"`
	Locale            string                 `json:"locale,omitempty"`
	ClientID          string                 `json:"client_id,omitempty"`
	Groups            interface{}            `json:"groups,omitempty"`
	Roles             interface{}            `json:"roles,omitempty"`
	Email             string                 `json:"email,omitempty"`
	EmailVerified     bool                   `json:"email_verified,omitempty"`
	Picture           string                 `json:"picture,omitempty"`
	Subject           string                 `json:"sub,omitempty"`
	Audience          JwtClaimAudience       `json:"aud,omitempty"`
	Expiry            int64                  `json:"exp,omitempty"`
	IssuedAt          int64                  `json:"iat,omitempty"`
	NotBeforeTime     int64                  `json:"nbf,omitempty"`
	JwtID             string                 `json:"jti,omitempty"`
	AccessTokenHash   string                 `json:"at_hash,omitempty"`
	AlsoKnownAs       string                 `json:"also_known_as,omitempty"`
	CustomClaims      map[string]interface{} `json:"-"`
}

type JwtClaimAudience []string

func (a *JwtClaimAudience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = JwtClaimAudience{single}
		return nil
	}

	var multi []string
	if err := json.Unmarshal(data, &multi); err == nil {
		*a = JwtClaimAudience(multi)
		return nil
	}

	return fmt.Errorf("aud field is not a valid string or array of strings")
}

func (j *IdpJwtClaims) toMap() map[string]interface{} {
	result := make(map[string]interface{})

	// Marshal standard fields
	jsonBytes, err := json.Marshal(j)
	if err != nil {
		zap.L().Error("failed to marshal claims", zap.Error(err))
		return result
	}

	// Unmarshal standard fields
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		zap.L().Error("failed to unmarshal claims", zap.Error(err))
		return result
	}

	// Add custom claims
	for k, v := range j.CustomClaims {
		result[k] = v
	}

	return result
}

func (j *IdpJwtClaims) exists(expected []string) error {
	claimsMap := j.toMap()
	zap.L().Debug("idp claims", zap.Any("claims", claimsMap))
	for _, claimName := range expected {
		_, found := claimsMap[claimName]

		if !found {
			return fmt.Errorf("missing or empty claim '%s' in idp token", claimName)
		}
	}

	return nil
}

func (j *IdpJwtClaims) validateAudience(expected []string) error {
	for _, claimAud := range j.Audience {
		for _, expectedClaim := range expected {
			if claimAud == expectedClaim {
				return nil
			}
		}
	}

	return fmt.Errorf("idp 'aud' did not match expected. 0 == intersect(%v, %v)", j.Audience, expected)
}

func (j *IdpJwtClaims) validateExpiryBounds(bounds DurationBounds) error {
	now := time.Now().Unix()
	ttl := time.Duration((j.Expiry - now) * int64(time.Second))

	if ttl < bounds.Min.Duration {
		return fmt.Errorf("idp 'exp' (%v) too short. must have at least %v remaining", ttl, bounds.Min.Duration)
	}

	if ttl > bounds.Max.Duration {
		return fmt.Errorf("idp 'exp' (%v) too long. must expire within %v", ttl, bounds.Max.Duration)
	}

	return nil
}

func (j *IdpJwtClaims) fromMap(m map[string]interface{}, customMapping map[string]string) {
	// Initialize custom claims map
	j.CustomClaims = make(map[string]interface{})

	// Helper function to safely convert interface{} to string
	toString := func(v interface{}) string {
		if v == nil {
			return ""
		}
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}

	// Helper function to safely convert interface{} to bool
	toBool := func(v interface{}) bool {
		if v == nil {
			return false
		}
		if b, ok := v.(bool); ok {
			return b
		}
		return false
	}

	// Helper function to safely convert interface{} to int64
	toInt64 := func(v interface{}) int64 {
		if v == nil {
			return 0
		}
		switch n := v.(type) {
		case float64:
			return int64(n)
		case int64:
			return n
		case int:
			return int64(n)
		}
		return 0
	}

	// Handle audience specially due to its custom type
	if aud, ok := m["aud"]; ok {
		switch v := aud.(type) {
		case []interface{}:
			j.Audience = make([]string, len(v))
			for i, a := range v {
				j.Audience[i] = toString(a)
			}
		case []string:
			j.Audience = v
		case string:
			j.Audience = []string{v}
		}
	}

	// Map standard fields using the mapping
	for jsonField, structField := range jsonToField {
		if value, exists := m[jsonField]; exists {
			switch structField {
			case "EmailVerified":
				j.EmailVerified = toBool(value)
			case "Expiry":
				j.Expiry = toInt64(value)
			case "IssuedAt":
				j.IssuedAt = toInt64(value)
			case "NotBeforeTime":
				j.NotBeforeTime = toInt64(value)
			case "Groups", "Roles":
				// Preserve original type (string or array) for expression matching
				field := reflect.ValueOf(j).Elem().FieldByName(structField)
				if field.IsValid() && field.CanSet() {
					if value == nil {
						field.SetZero()
					} else {
						field.Set(reflect.ValueOf(value))
					}
				}
			default:
				// Use reflection to set the field value
				field := reflect.ValueOf(j).Elem().FieldByName(structField)
				if field.IsValid() && field.CanSet() {
					field.SetString(toString(value))
				}
			}
		}
	}

	// Store all other fields in CustomClaims, applying custom mapping if available
	for k, v := range m {
		// Skip standard fields
		if _, isStandard := standardClaims[k]; isStandard {
			continue
		}

		// Apply custom mapping if available
		if customMapping != nil {
			if mappedKey, ok := customMapping[k]; ok {
				j.CustomClaims[mappedKey] = v
			} else {
				j.CustomClaims[k] = v
			}
		} else {
			j.CustomClaims[k] = v
		}
	}
}

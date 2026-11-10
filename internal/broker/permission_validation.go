package broker

import (
	"errors"
	"strings"
	"unicode"

	"github.com/nats-io/jwt/v2"
)

// Validate the final rendered permissions before adding them to a JWT. This
// preserves intentional wildcard grants; raw templated claim values should still
// be migrated to validated .user fields to prevent syntactically valid widening.
func validateRenderedPermissions(permissions *jwt.Permissions) error {
	lists := []struct {
		values jwt.StringList
		queue  bool
	}{
		{permissions.Pub.Allow, false}, {permissions.Pub.Deny, false},
		{permissions.Sub.Allow, true}, {permissions.Sub.Deny, true},
	}
	for _, list := range lists {
		for _, subject := range list.values {
			parts := strings.Split(subject, " ")
			if len(parts) > 2 || (len(parts) > 1 && !list.queue) {
				return errors.New("invalid rendered permission subject")
			}
			for _, part := range parts {
				if !validPermissionSubject(part) {
					return errors.New("invalid rendered permission subject")
				}
			}
		}
	}
	return nil
}

func validPermissionSubject(subject string) bool {
	if subject == "" || strings.Contains(subject, "{{") || strings.Contains(subject, "}}") {
		return false
	}
	if strings.ContainsFunc(subject, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return false
	}
	tokens := strings.Split(subject, ".")
	for i, token := range tokens {
		if token == "" {
			return false
		}
		if token == ">" {
			if i != len(tokens)-1 {
				return false
			}
			continue
		}
		if token != "*" && strings.ContainsAny(token, "*>") {
			return false
		}
	}
	return true
}

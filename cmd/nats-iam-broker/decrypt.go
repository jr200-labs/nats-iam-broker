package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/nats-io/jwt/v2"
	"github.com/spf13/cobra"
)

// jwePartCount is the number of dot-separated segments in a compact JWE token.
const jwePartCount = 5

// natsJWTPartCount is the number of dot-separated segments in a NATS JWT token.
const natsJWTPartCount = 3

func newDecryptCmd() *cobra.Command {
	var keyStr string

	cmd := &cobra.Command{
		Use:   "decrypt [flags] <token>",
		Short: "Decode a NATS JWT or decrypt a JWE-encrypted token",
		Long: `Decode a NATS JWT (3 dot-separated parts) directly, or decrypt
a JWE-encrypted token (5 dot-separated parts) using a symmetric key.

For NATS JWTs, no key is needed. For JWE tokens, provide --key with
the symmetric key in base64url encoding.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			token := args[0]
			parts := strings.Split(token, ".")
			switch len(parts) {
			case natsJWTPartCount:
				return runDecodeNATSJWT(token)
			case jwePartCount:
				return runDecodeJWEToken(token, keyStr)
			default:
				return fmt.Errorf("unrecognised token format: expected %d parts (NATS JWT) or %d parts (JWE), got %d",
					natsJWTPartCount, jwePartCount, len(parts))
			}
		},
	}

	cmd.Flags().StringVar(&keyStr, "key", "", "symmetric key in base64url encoding (for JWE decryption)")

	return cmd
}

func runDecodeNATSJWT(token string) error {
	decoded, err := tryDecodeNATSJWT(token)
	if err != nil {
		return fmt.Errorf("error decoding NATS JWT: %w", err)
	}
	_, _ = fmt.Fprintf(os.Stdout, "=== NATS JWT ===\n%s\n", decoded)
	return nil
}

func runDecodeJWEToken(token, keyStr string) error {
	// Always display the JWE header
	header, err := decodeJWEHeader(token)
	if err != nil {
		return fmt.Errorf("error decoding JWE header: %w", err)
	}

	headerJSON, err := json.MarshalIndent(header, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshalling JWE header: %w", err)
	}
	_, _ = fmt.Fprintf(os.Stdout, "=== JWE Header ===\n%s\n", headerJSON)

	if keyStr == "" {
		_, _ = fmt.Fprintf(os.Stdout, "\nNo --key provided; only header shown. Provide --key to decrypt payload.\n")
		return nil
	}

	key, err := base64.RawURLEncoding.DecodeString(keyStr)
	if err != nil {
		return fmt.Errorf("error decoding key: %w", err)
	}

	plaintext, err := decryptJWE(token, key)
	if err != nil {
		return fmt.Errorf("error decrypting token: %w", err)
	}

	// Try to decode as a NATS JWT
	if decoded, err := tryDecodeNATSJWT(string(plaintext)); err == nil {
		_, _ = fmt.Fprintf(os.Stdout, "\n=== Decrypted NATS JWT ===\n%s\n", decoded)
		return nil
	}

	// Try to pretty-print as generic JSON
	var raw json.RawMessage
	if err := json.Unmarshal(plaintext, &raw); err == nil {
		var buf []byte
		buf, err = json.MarshalIndent(raw, "", "  ")
		if err == nil {
			_, _ = fmt.Fprintf(os.Stdout, "\n=== Decrypted Payload (JSON) ===\n%s\n", buf)
			return nil
		}
	}

	// Fall back to raw output
	_, _ = fmt.Fprintf(os.Stdout, "\n=== Decrypted Payload (raw) ===\n%s\n", plaintext)
	return nil
}

func decodeJWEHeader(token string) (map[string]interface{}, error) {
	idx := strings.IndexByte(token, '.')
	if idx < 0 {
		return nil, fmt.Errorf("invalid JWE token format")
	}
	headerPart := token[:idx]

	headerBytes, err := base64.RawURLEncoding.DecodeString(headerPart)
	if err != nil {
		return nil, fmt.Errorf("invalid base64url header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid JSON header: %w", err)
	}

	return header, nil
}

func decryptJWE(token string, key []byte) ([]byte, error) {
	jwe, err := jose.ParseEncryptedCompact(token,
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A256CBC_HS512},
	)
	if err != nil {
		return nil, fmt.Errorf("parsing JWE: %w", err)
	}

	plaintext, err := jwe.Decrypt(key)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}

func tryDecodeNATSJWT(token string) (string, error) {
	gc, err := jwt.DecodeGeneric(token)
	if err != nil {
		return "", err
	}

	result := map[string]interface{}{
		"type":       string(gc.ClaimType()),
		"issuer":     gc.Issuer,
		"subject":    gc.Subject,
		"issued_at":  formatUnixTime(gc.IssuedAt),
		"expires":    formatUnixTime(gc.Expires),
		"not_before": formatUnixTime(gc.NotBefore),
		"name":       gc.Name,
		"audience":   gc.Audience,
		"id":         gc.ID,
		"nats":       gc.Data,
	}

	pretty, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}

	return string(pretty), nil
}

func formatUnixTime(t int64) string {
	if t == 0 {
		return ""
	}
	return time.Unix(t, 0).UTC().Format(time.RFC3339)
}

package broker

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Bound encoded responses before the OIDC library reads or unmarshals them.
// Use the caller's transport/TLS configuration without mutating shared clients.
func boundedUserInfoContext(ctx context.Context) context.Context {
	base, ok := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if !ok || base == nil {
		base = http.DefaultClient
	}
	client := *base
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = userInfoTransport{base: transport}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return oidc.ClientContext(ctx, &client)
}

type userInfoTransport struct{ base http.RoundTripper }

func (t userInfoTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > projectionMaxInputBytes {
		_ = response.Body.Close()
		return nil, errors.New("user info response exceeds input limit")
	}
	response.Body = &limitedUserInfoBody{ReadCloser: response.Body, remaining: projectionMaxInputBytes}
	return response, nil
}

type limitedUserInfoBody struct {
	io.ReadCloser
	remaining int
}

func (b *limitedUserInfoBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.remaining == 0 {
		var probe [1]byte
		n, err := b.ReadCloser.Read(probe[:])
		if n > 0 {
			return 0, errors.New("user info response exceeds input limit")
		}
		return 0, err
	}
	if len(p) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= n
	return n, err
}

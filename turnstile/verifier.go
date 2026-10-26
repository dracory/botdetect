// Package turnstile is a Cloudflare Turnstile siteverify client plus
// net/http middleware for protecting form submissions and expensive
// anonymous endpoints. Unlike the botdetect core it performs network
// I/O; the subpackage boundary keeps the core pure.
//
// Never verify the same token twice (e.g. in two stacked middlewares):
// Cloudflare rejects replays.
package turnstile

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultEndpoint is Cloudflare's siteverify URL.
const DefaultEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// ErrMissingToken is returned when the request carries no Turnstile
// token at all — a client error, not a transport failure.
var ErrMissingToken = errors.New("turnstile: missing token")

// Result is the siteverify response payload.
type Result struct {
	Success     bool      `json:"success"`
	ErrorCodes  []string  `json:"error-codes"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	Action      string    `json:"action"`
	CData       string    `json:"cdata"`
}

// Verifier calls the siteverify endpoint.
type Verifier struct {
	Secret   string
	Endpoint string       // override in tests
	Client   *http.Client // defaults to a 5s timeout client
}

// New returns a Verifier for the given site secret.
func New(secret string) *Verifier {
	return &Verifier{
		Secret:   secret,
		Endpoint: DefaultEndpoint,
		Client:   &http.Client{Timeout: 5 * time.Second},
	}
}

// Verify returns a non-nil error only for transport/decoding failures
// (and ErrMissingToken). A rejected token is Result.Success == false,
// not an error.
func (v *Verifier) Verify(ctx context.Context, token, remoteIP string) (*Result, error) {
	if token == "" {
		return nil, ErrMissingToken
	}
	form := url.Values{"secret": {v.Secret}, "response": {token}}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.Endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var res Result
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}

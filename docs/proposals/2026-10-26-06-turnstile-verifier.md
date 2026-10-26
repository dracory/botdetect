# Proposal: Turnstile verifier subpackage

Status: proposed
Date: 2026-10-26

## Problem

For protecting expensive anonymous endpoints (e.g. an unauthenticated LLM
call) or form submissions (login, signup, contact), `botdetect`'s
heuristics alone aren't enough — a headless browser with a real UA from a
residential IP passes undetected. The standard answer is Cloudflare
Turnstile: free, near-invisible, proof-of-human.

`botdetect`'s core must stay pure (no I/O), but a `turnstile` subpackage
is allowed to do network I/O — the subpackage boundary resolves the
design friction.

## Proposal

Add `botdetect/turnstile` — a siteverify client + net/http middleware.
~150–250 lines of Go including tests; roughly half a day to a day.

### Layout

```
turnstile/
  verifier.go      // Siteverify client
  middleware.go    // net/http middleware
  verifier_test.go
```

### verifier.go

```go
package turnstile

const DefaultEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

type Result struct {
    Success     bool      `json:"success"`
    ErrorCodes  []string  `json:"error-codes"`
    ChallengeTS time.Time `json:"challenge_ts"`
    Hostname    string    `json:"hostname"`
    Action      string    `json:"action"`
    CData       string    `json:"cdata"`
}

type Verifier struct {
    Secret   string
    Endpoint string       // override in tests
    Client   *http.Client // defaults to a 5s timeout client
}

func New(secret string) *Verifier {
    return &Verifier{
        Secret:   secret,
        Endpoint: DefaultEndpoint,
        Client:   &http.Client{Timeout: 5 * time.Second},
    }
}

var ErrMissingToken = errors.New("turnstile: missing token")

// Verify returns a non-nil error only for transport/decoding failures.
// A rejected token is Result.Success == false, not an error.
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
    if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
        return nil, err
    }
    return &res, nil
}
```

### middleware.go

The widget posts the token in a form field named `cf-turnstile-response`.

```go
type Options struct {
    Hostname  string // optional: require res.Hostname to match
    Action    string // optional: require res.Action to match
    FailOpen  bool   // allow request if Cloudflare is unreachable
    OnFailure http.HandlerFunc
    RemoteIP  func(*http.Request) string // plug in trusted-proxy logic
}

func Middleware(v *Verifier, opt Options) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if r.Method != http.MethodPost { // only gate form submissions
                next.ServeHTTP(w, r)
                return
            }
            ip := ""
            if opt.RemoteIP != nil {
                ip = opt.RemoteIP(r)
            }
            res, err := v.Verify(r.Context(), r.PostFormValue("cf-turnstile-response"), ip)
            switch {
            case err != nil && errors.Is(err, ErrMissingToken):
                fail(w, r, opt)
            case err != nil:
                if opt.FailOpen {
                    next.ServeHTTP(w, r)
                    return
                }
                http.Error(w, "verification unavailable", http.StatusServiceUnavailable)
            case !res.Success,
                opt.Hostname != "" && res.Hostname != opt.Hostname,
                opt.Action != "" && res.Action != opt.Action:
                fail(w, r, opt)
            default:
                next.ServeHTTP(w, r)
            }
        })
    }
}

func fail(w http.ResponseWriter, r *http.Request, opt Options) {
    if opt.OnFailure != nil {
        opt.OnFailure(w, r)
        return
    }
    http.Error(w, "Forbidden", http.StatusForbidden)
}
```

## Design decisions

- **Where it plugs in.** Turnstile protects specific form submissions,
  not whole sites — per-route middleware, separate from the global
  `botdetect.Middleware`.
- **Fail open vs. closed.** If Cloudflare is unreachable: closed by
  default, `FailOpen` option for consumers that prefer availability.
- **Single-use tokens.** Never verify the same token twice (e.g. in two
  stacked middlewares) — Cloudflare rejects replays.
- **Hostname/action checks.** Stop a token issued for another site or
  form from being replayed. Optional but cheap.
- **Tests.** Point `Endpoint` at an `httptest.Server`. Cloudflare also
  publishes dummy sitekeys/secrets enabling one opt-in integration test.
- **Widget side.** Either a small `Widget(sitekey, action)` helper
  returning the `<script>` + `<div class="cf-turnstile">` HTML, or left
  to the consumer. Trivial either way.

## Optional integration with the core

`OnlyIfSuspicious bool` middleware option: only demand a Turnstile token
when `botdetect.DetectRequest(r)` or `IsDataCenterIP` flags the request —
normal users never see widget friction on a protected form. A few extra
lines.

## Estimate

~150–250 lines Go including tests; half a day to a day.

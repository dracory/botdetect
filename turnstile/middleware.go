package turnstile

import (
	"errors"
	"net"
	"net/http"

	"github.com/dracory/botdetect"
)

// Options configures Middleware.
type Options struct {
	// Hostname, when set, requires the verify result's hostname to
	// match — stops a token issued for another site being replayed.
	Hostname string

	// Action, when set, requires the verify result's action to match —
	// stops a token issued for another form being replayed.
	Action string

	// FailOpen allows the request through when Cloudflare is
	// unreachable. Default fails closed with 503.
	FailOpen bool

	// OnlyIfSuspicious only demands a token when botdetect flags the
	// request (detected bot or datacenter IP) — normal users never see
	// widget friction on a protected form.
	OnlyIfSuspicious bool

	// OnFailure writes the rejection for failed verifications.
	// Defaults to a 403 "Forbidden".
	OnFailure http.HandlerFunc

	// RemoteIP extracts the client IP sent to siteverify as remoteip.
	// Defaults to the RemoteAddr host; plug in trusted-proxy logic
	// behind a reverse proxy. Return "" to omit remoteip.
	RemoteIP func(*http.Request) string
}

// Middleware gates POST requests on a valid Turnstile token (form field
// cf-turnstile-response). Non-POST requests pass through — mount it
// per-route on the forms being protected, separate from the global
// botdetect.Middleware.
func Middleware(v *Verifier, opt Options) func(http.Handler) http.Handler {
	remoteIP := opt.RemoteIP
	if remoteIP == nil {
		remoteIP = func(r *http.Request) string {
			if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				return host
			}
			return r.RemoteAddr
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}
			if opt.OnlyIfSuspicious &&
				!botdetect.DetectRequest(r).Bot &&
				!botdetect.IsDataCenterIP(remoteIP(r)) {
				next.ServeHTTP(w, r)
				return
			}
			res, err := v.Verify(r.Context(),
				r.PostFormValue("cf-turnstile-response"), remoteIP(r))
			switch {
			case errors.Is(err, ErrMissingToken):
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

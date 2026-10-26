# Proposal: stateless proof-of-work challenge

Status: implemented
Date: 2026-10-26

## Problem

`botdetect` today only *detects*: `DetectRequest`/`IsDataCenterIP` return a
verdict, and the consumer's middleware typically responds with a bare `403`.
That works for declared bots and datacenter traffic, but gives suspicious
clients no path forward — and gives consumers no intermediate option between
"allow" and "block" for protecting expensive anonymous endpoints (e.g. an
unauthenticated LLM call).

Consumers currently have to bolt on an external CAPTCHA/Turnstile service
for that middle ground.

## Proposal

Add a `botdetect/challenge` subpackage: a stateless, HMAC-signed
proof-of-work challenge ("our own Turnstile") that fits the library's
philosophy — no store, no DB, no goroutines.

Scope: ~300–500 lines of Go plus ~80 lines of embedded JS. Stops commodity
scrapers and scripts; does **not** stop a determined headless-browser
operator (see Limitations).

### Flow

1. **Gate.** Middleware checks `DetectRequest` and `IsDataCenterIP`. A
   suspicious request without a valid pass cookie receives a small
   challenge page (`HTTP 403` or `503` + page) instead of a bare `403`.
2. **Issue.** Server returns a token
   `nonce.expiry.difficulty.bind.hmac`, where `bind` hashes the
   User-Agent + client IP prefix. Nothing stored server-side.
3. **Solve.** Embedded JS (`go:embed`) finds a `counter` such that
   `SHA-256(token + ":" + counter)` has N leading zero bits — ideally in a
   Web Worker so the page stays responsive — and POSTs the solution.
4. **Verify.** Server checks HMAC, expiry, binding, and recomputes the
   hash; on success it sets a signed pass cookie (~1h). Subsequent
   requests only check the cookie — cheap.
5. **Optional signals.** Hidden honeypot field, minimum solve-time check,
   `navigator.webdriver`. Weak alone; filters lazy bots.

### Core API sketch

```go
package challenge

type Config struct {
    Secret     []byte
    Difficulty int           // leading zero bits; 18-20 ≈ 0.2-1s in browser
    TTL        time.Duration // challenge token validity
}

func (c Config) bind(r *http.Request) string {
    ip, _, _ := net.SplitHostPort(r.RemoteAddr) // trusted-proxy logic in prod
    h := sha256.Sum256([]byte(r.UserAgent() + "|" + ip))
    return hex.EncodeToString(h[:8])
}

func (c Config) sign(s string) string {
    m := hmac.New(sha256.New, c.Secret)
    m.Write([]byte(s))
    return hex.EncodeToString(m.Sum(nil))
}

func (c Config) Issue(r *http.Request) string {
    nonce := make([]byte, 12)
    _, _ = rand.Read(nonce)
    payload := fmt.Sprintf("%x.%d.%d.%s", nonce,
        time.Now().Add(c.TTL).Unix(), c.Difficulty, c.bind(r))
    return payload + "." + c.sign(payload)
}

func (c Config) Verify(r *http.Request, token, counter string) bool {
    i := strings.LastIndex(token, ".")
    if i < 0 {
        return false
    }
    payload, sig := token[:i], token[i+1:]
    if !hmac.Equal([]byte(sig), []byte(c.sign(payload))) {
        return false
    }
    p := strings.Split(payload, ".") // nonce, exp, difficulty, bind
    if len(p) != 4 || p[3] != c.bind(r) {
        return false
    }
    exp, _ := strconv.ParseInt(p[1], 10, 64)
    diff, _ := strconv.Atoi(p[2])
    if time.Now().Unix() > exp {
        return false
    }
    sum := sha256.Sum256([]byte(token + ":" + counter))
    return leadingZeroBits(sum[:]) >= diff
}

func leadingZeroBits(b []byte) int {
    n := 0
    for _, v := range b {
        if v == 0 {
            n += 8
            continue
        }
        return n + bits.LeadingZeros8(v)
    }
    return n
}
```

The pass cookie reuses `sign` over `exp|bind`. Middleware integration:
a `Challenge` option on the existing `botdetect.Middleware`, or a separate
handler wrapping it.

## Limitations (honest)

- **Replay.** Stateless means one solved token is reusable until expiry.
  Short TTL + IP/UA binding limit the blast radius. True single-use
  tokens would need an optional `ReplayStore` interface — keeps the core
  store-free but allows consumers to plug a cache.
- **Strength.** PoW costs a scraper CPU time but doesn't prove "human" —
  headless Chrome passes. It raises the cost of bulk scraping; it is not
  an identity check.
- **IP binding.** Mobile network switches and CGNAT users may re-solve.
  Binding to a /24 or to UA only is a tradeoff to make configurable.
- **Accessibility / no-JS.** No-JS clients cannot pass. Consumers must
  decide which paths are gated or offer a fallback.
- **Difficulty tuning.** Fixed difficulty to start; too-high values hurt
  low-end phones.

## Why a subpackage

`botdetect/challenge` keeps the core package I/O-free and dependency-free
(stdlib only: `crypto/hmac`, `crypto/sha256`, `crypto/rand`,
`encoding/hex`, `math/bits`, `embed`). Consumers who only want detection
are unaffected.

## Estimate

~300–500 lines Go, ~80 lines JS, 2–4 days including tests.

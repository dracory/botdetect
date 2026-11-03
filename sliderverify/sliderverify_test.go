package sliderverify

import (
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	cfg := Config{
		Secret:          []byte("test-secret-key-12345"),
		VerifyPath:      "/slider-verify",
		MinDuration:     300 * time.Millisecond,
		MaxDuration:     10 * time.Second,
		TargetTolerance: 5.0,
	}
	cfg.defaults()
	return cfg
}

func hit(t *testing.T, cfg Config, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h := cfg.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func extractTokenAndTarget(t *testing.T, body string) (string, int) {
	t.Helper()
	const tokMarker = `data-token="`
	i := strings.Index(body, tokMarker)
	if i < 0 {
		t.Fatal("no token in page")
	}
	rest := body[i+len(tokMarker):]
	token := rest[:strings.Index(rest, `"`)]

	const tgtMarker = `data-target="`
	j := strings.Index(body, tgtMarker)
	if j < 0 {
		t.Fatal("no target in page")
	}
	restTgt := body[j+len(tgtMarker):]
	tgtStr := restTgt[:strings.Index(restTgt, `"`)]
	targetPct, err := strconv.Atoi(tgtStr)
	if err != nil {
		t.Fatalf("bad target %q: %v", tgtStr, err)
	}
	return token, targetPct
}

// generateHumanTrajectory generates a realistic human trajectory satisfying Fitts's law (ease-in/ease-out),
// natural microtremors on the Y-axis, and appropriate duration.
func generateHumanTrajectory(targetPct float64, durationMS int, ptrType string) KinematicsReport {
	steps := 30
	pts := make([]Point, steps)
	for i := 0; i < steps; i++ {
		progress := float64(i) / float64(steps-1)
		t := int(progress * float64(durationMS))

		// S-curve / sigmoid easing for human velocity profile: 3*p^2 - 2*p^3
		eased := progress * progress * (3 - 2*progress)
		x := eased * targetPct

		// Subtle sinusoidal + micro-jitter on Y
		y := math.Sin(progress*math.Pi)*3.0 + (float64(i%3) - 1.0)*0.5

		pts[i] = Point{
			T: t,
			X: math.Round(x*100) / 100,
			Y: math.Round(y*10) / 10,
		}
	}

	return KinematicsReport{
		DurationMS:  durationMS,
		FinalPos:    targetPct,
		PointerType: ptrType,
		Trajectory:  pts,
	}
}

func TestGetWithoutPassServesSliderPage(t *testing.T) {
	cfg := testConfig()
	rec := hit(t, cfg, httptest.NewRequest("GET", "/protected", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("expected text/html, got %q", ct)
	}

	token, targetPct := extractTokenAndTarget(t, rec.Body.String())
	if token == "" {
		t.Fatal("empty token extracted")
	}
	if targetPct < 50 || targetPct > 90 {
		t.Fatalf("target %d out of expected [50..90] range", targetPct)
	}
}

func TestNonGetGatedRequestForbidden(t *testing.T) {
	cfg := testConfig()
	rec := hit(t, cfg, httptest.NewRequest("POST", "/protected", nil))
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Header().Get("Content-Type"), "html") {
		t.Fatalf("expected plain 403, got %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestVerifySuccessIssuesPassCookie(t *testing.T) {
	cfg := testConfig()
	pageRec := hit(t, cfg, httptest.NewRequest("GET", "/protected", nil))
	token, targetPct := extractTokenAndTarget(t, pageRec.Body.String())

	rep := generateHumanTrajectory(float64(targetPct), 800, "mouse")
	kinematicsJSON, _ := json.Marshal(rep)

	form := url.Values{
		"token":      {token},
		"kinematics": {string(kinematicsJSON)},
		"sv_hp":      {""},
		"sv_next":    {"/protected"},
	}

	verifyReq := httptest.NewRequest("POST", "/slider-verify", strings.NewReader(form.Encode()))
	verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	verifyRec := hit(t, cfg, verifyReq)

	if verifyRec.Code != http.StatusOK {
		b, _ := io.ReadAll(verifyRec.Result().Body)
		t.Fatalf("verify failed: status=%d body=%s", verifyRec.Code, b)
	}

	var pass *http.Cookie
	for _, c := range verifyRec.Result().Cookies() {
		if c.Name == cfg.CookieName {
			pass = c
		}
	}
	if pass == nil {
		t.Fatal("no pass cookie issued")
	}
	if !pass.HttpOnly {
		t.Fatal("pass cookie missing HttpOnly")
	}

	// Gated route with pass cookie must succeed
	nextReq := httptest.NewRequest("GET", "/protected", nil)
	nextReq.AddCookie(pass)
	nextRec := hit(t, cfg, nextReq)
	if nextRec.Code != http.StatusTeapot {
		t.Fatalf("gated request with valid pass = %d, want %d", nextRec.Code, http.StatusTeapot)
	}
}

func TestKinematicsRejections(t *testing.T) {
	cfg := testConfig()

	tests := []struct {
		name      string
		mutateRep func(rep *KinematicsReport, targetPct int)
		wantErr   string
	}{
		{
			name: "too fast / bot click",
			mutateRep: func(rep *KinematicsReport, targetPct int) {
				rep.DurationMS = 50
				for i := range rep.Trajectory {
					rep.Trajectory[i].T = i * 2
				}
			},
			wantErr: "too fast",
		},
		{
			name: "missed target zone",
			mutateRep: func(rep *KinematicsReport, targetPct int) {
				rep.FinalPos = float64(targetPct) - 15.0
			},
			wantErr: "missed target zone",
		},
		{
			name: "insufficient samples / teleport",
			mutateRep: func(rep *KinematicsReport, targetPct int) {
				rep.Trajectory = []Point{
					{T: 0, X: 0, Y: 0},
					{T: rep.DurationMS, X: float64(targetPct), Y: 0},
				}
			},
			wantErr: "insufficient trajectory samples",
		},
		{
			name: "strictly linear constant velocity bot",
			mutateRep: func(rep *KinematicsReport, targetPct int) {
				steps := 20
				rep.Trajectory = make([]Point, steps)
				for i := 0; i < steps; i++ {
					t := i * 40
					x := float64(i) / float64(steps-1) * float64(targetPct)
					rep.Trajectory[i] = Point{T: t, X: x, Y: 2.0}
				}
				rep.DurationMS = (steps - 1) * 40
			},
			wantErr: "velocity profile is unnaturally constant",
		},
		{
			name: "mouse drag with zero orthogonal jitter",
			mutateRep: func(rep *KinematicsReport, targetPct int) {
				rep.PointerType = "mouse"
				for i := range rep.Trajectory {
					rep.Trajectory[i].Y = 0.0
				}
			},
			wantErr: "zero orthogonal jitter",
		},
		{
			name: "instantaneous single-step teleportation",
			mutateRep: func(rep *KinematicsReport, targetPct int) {
				rep.Trajectory = []Point{
					{T: 0, X: 0, Y: 0},
					{T: 100, X: 0.1, Y: 0.2},
					{T: 200, X: 0.2, Y: 0.4},
					{T: 300, X: float64(targetPct), Y: 1.0}, // jump
					{T: 400, X: float64(targetPct), Y: 1.2},
					{T: 500, X: float64(targetPct), Y: 1.1},
				}
				rep.DurationMS = 500
				rep.FinalPos = float64(targetPct)
			},
			wantErr: "instantaneous teleportation",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			targetPct := 75
			rep := generateHumanTrajectory(float64(targetPct), 900, "mouse")
			tc.mutateRep(&rep, targetPct)

			err := ValidateKinematics(&rep, targetPct, cfg)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got error %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestHoneypotAndRedirectSanitization(t *testing.T) {
	cfg := testConfig()
	pageRec := hit(t, cfg, httptest.NewRequest("GET", "/protected", nil))
	token, targetPct := extractTokenAndTarget(t, pageRec.Body.String())

	rep := generateHumanTrajectory(float64(targetPct), 700, "mouse")
	kinematicsJSON, _ := json.Marshal(rep)

	// Honeypot filled must fail
	form := url.Values{
		"token":      {token},
		"kinematics": {string(kinematicsJSON)},
		"sv_hp":      {"bot-input"},
		"sv_next":    {"/protected"},
	}
	r := httptest.NewRequest("POST", "/slider-verify", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := hit(t, cfg, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("honeypot failed to block: status=%d", rec.Code)
	}

	// Open redirect attempts must be sanitized to "/"
	for _, openRedirect := range []string{"https://evil.example.com", "//evil.com", "/\\evil.com"} {
		form["sv_hp"] = []string{""}
		form["sv_next"] = []string{openRedirect}
		r := httptest.NewRequest("POST", "/slider-verify", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := hit(t, cfg, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("verify failed for open redirect test: status=%d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"next":"/"`) {
			t.Fatalf("open redirect %q was not sanitized to /: %s", openRedirect, rec.Body.String())
		}
	}
}

func TestTamperedTokenRejected(t *testing.T) {
	cfg := testConfig()
	req := httptest.NewRequest("GET", "/", nil)
	token, _, err := cfg.issueToken(req)
	if err != nil {
		t.Fatalf("issueToken failed: %v", err)
	}

	parts := strings.Split(token, ".")
	parts[2] = "99" // alter target position
	tamperedToken := strings.Join(parts, ".")

	_, err = cfg.verifyToken(tamperedToken, time.Now(), req)
	if err == nil {
		t.Fatal("tampered token was accepted")
	}
}

func TestPassCookieBoundToClient(t *testing.T) {
	cfg := testConfig()

	reqA := httptest.NewRequest("GET", "/protected", nil)
	reqA.RemoteAddr = "192.0.2.1:1234"
	reqA.Header.Set("User-Agent", "Browser-A")

	pass := cfg.issuePass(time.Now(), reqA)

	// Valid on original client
	if !cfg.verifyPassValue(pass, time.Now(), reqA) {
		t.Fatal("valid pass rejected on original client")
	}

	// Different IP
	reqB := httptest.NewRequest("GET", "/protected", nil)
	reqB.RemoteAddr = "192.0.2.2:1234"
	reqB.Header.Set("User-Agent", "Browser-A")
	if cfg.verifyPassValue(pass, time.Now(), reqB) {
		t.Fatal("pass accepted from different IP")
	}

	// Different UA
	reqC := httptest.NewRequest("GET", "/protected", nil)
	reqC.RemoteAddr = "192.0.2.1:1234"
	reqC.Header.Set("User-Agent", "Browser-C")
	if cfg.verifyPassValue(pass, time.Now(), reqC) {
		t.Fatal("pass accepted from different User-Agent")
	}
}

func TestReplayStoreEnforcement(t *testing.T) {
	cfg := testConfig()
	usedTokens := make(map[string]bool)
	cfg.Replay = replayFunc(func(token string, exp time.Time) bool {
		if usedTokens[token] {
			return false
		}
		usedTokens[token] = true
		return true
	})

	pageRec := hit(t, cfg, httptest.NewRequest("GET", "/protected", nil))
	token, targetPct := extractTokenAndTarget(t, pageRec.Body.String())

	rep := generateHumanTrajectory(float64(targetPct), 800, "mouse")
	kinematicsJSON, _ := json.Marshal(rep)

	form := url.Values{
		"token":      {token},
		"kinematics": {string(kinematicsJSON)},
		"sv_hp":      {""},
		"sv_next":    {"/protected"},
	}

	r1 := httptest.NewRequest("POST", "/slider-verify", strings.NewReader(form.Encode()))
	r1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec1 := hit(t, cfg, r1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first solve should succeed, got %d", rec1.Code)
	}

	// Replay attempt with same token
	r2 := httptest.NewRequest("POST", "/slider-verify", strings.NewReader(form.Encode()))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := hit(t, cfg, r2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("replayed token should be rejected with 403, got %d", rec2.Code)
	}
}

type replayFunc func(token string, expiresAt time.Time) bool

func (f replayFunc) CheckAndMark(token string, expiresAt time.Time) bool {
	return f(token, expiresAt)
}

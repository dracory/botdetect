package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dracory/botdetect/sliderverify"
)

func main() {
	cfg := sliderverify.Config{
		Secret:          []byte("example-secret-key-sliderverify"),
		MinDuration:     350 * time.Millisecond,
		TargetTolerance: 5.0,
		CookieTTL:       24 * time.Hour,
		VerifyPath:      "/slider-verify",
	}

	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<h1>Protected Area</h1><p>You verified humanity via kinematics slider!</p>")
	})

	handler := cfg.Middleware(app)
	log.Println("Sliderverify server listening on http://localhost:8083")
	log.Fatal(http.ListenAndServe(":8083", handler))
}

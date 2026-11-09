package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dracory/botdetect/humanverify"
)

func main() {
	cfg := humanverify.Config{
		Secret:     []byte("example-secret-key-humanverify"),
		MinHold:    800 * time.Millisecond,
		CookieTTL:  24 * time.Hour,
		VerifyPath: "/human-verify",
	}

	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<h1>Protected Area</h1><p>You verified humanity via press-and-hold!</p>")
	})

	handler := cfg.Middleware(app)
	log.Println("Humanverify server listening on http://localhost:8082")
	log.Fatal(http.ListenAndServe(":8082", handler))
}

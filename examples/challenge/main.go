package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dracory/botdetect/challenge"
)

func main() {
	cfg := challenge.Config{
		Secret:     []byte("example-secret-key-challenge"),
		Difficulty: 18,
		TTL:        5 * time.Minute,
	}

	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<h1>Protected Area</h1><p>You solved the Proof-of-Work challenge!</p>")
	})

	handler := cfg.Middleware(app)
	log.Println("Challenge server listening on http://localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", handler))
}

package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/dracory/botdetect/turnstile"
)

const (
	// Cloudflare dummy test keys:
	// https://developers.cloudflare.com/turnstile/troubleshooting/testing/
	demoSiteKey = "1x00000000000000000000AA" // Always passes
	demoSecret  = "1x0000000000000000000000000000000000000000AA"
)

var formTpl = template.Must(template.New("form").Parse(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Turnstile Protected Form</title>
<style>
body{font-family:system-ui,sans-serif;max-width:400px;margin:50px auto;padding:20px;border:1px solid #ddd;border-radius:8px}
button{margin-top:16px;padding:8px 16px;background:#0051c3;color:#fff;border:none;border-radius:4px;cursor:pointer}
</style>
</head>
<body>
<h2>Protected Submission</h2>
<form method="POST" action="/submit">
  <label for="name">Name:</label><br>
  <input type="text" id="name" name="name" required style="width:100%;margin-bottom:12px;padding:6px;box-sizing:border-box"><br>
  {{.Widget}}
  <button type="submit">Submit</button>
</form>
</body>
</html>`))

func main() {
	verifier := turnstile.New(demoSecret)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = formTpl.Execute(w, map[string]interface{}{
			"Widget": turnstile.Widget(demoSiteKey, "submit"),
		})
	})

	protectedSubmit := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.FormValue("name")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<h1>Success!</h1><p>Welcome, %s. Form submission verified by Turnstile.</p>", template.HTMLEscapeString(name))
	})

	mux.Handle("/submit", turnstile.Middleware(verifier, turnstile.Options{
		Action: "submit",
	})(protectedSubmit))

	log.Println("Turnstile server listening on http://localhost:8084")
	log.Fatal(http.ListenAndServe(":8084", mux))
}

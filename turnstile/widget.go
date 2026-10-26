package turnstile

import "html/template"

// Widget returns the HTML snippet rendering the Turnstile widget:
// the Cloudflare script tag plus the widget div. Place it inside the
// protected form; it emits the cf-turnstile-response field. Action may
// be empty. Include it once per page — multiple calls emit duplicate
// api.js script tags (browsers dedupe by URL, but it's needless).
func Widget(sitekey, action string) template.HTML {
	attr := ""
	if action != "" {
		attr = ` data-action="` + template.HTMLEscapeString(action) + `"`
	}
	return template.HTML(`<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>` +
		`<div class="cf-turnstile" data-sitekey="` + template.HTMLEscapeString(sitekey) + `"` + attr + `></div>`)
}

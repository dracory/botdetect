package challenge

import (
	_ "embed"
	"html/template"
)

// challengeJS is the embedded solver. It reads the token from the
// #bd-pow element, runs a SHA-256 counter search in a Web Worker, and
// POSTs the solution to the verify endpoint.
//
//go:embed challenge.js
var challengeJS string

type pageData struct {
	Token      string
	VerifyPath string
	Next       string
	JS         template.JS
}

var pageTpl = template.Must(template.New("challenge").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Checking your browser</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif;background:#fafafa;color:#111}
.card{max-width:26rem;padding:2rem;border:2px solid #111;box-shadow:6px 6px 0 #111;background:#fff;text-align:center}
h1{font-size:1.25rem;margin:0 0 .75rem}
p{margin:.25rem 0;color:#444}
#bd-status{font-variant-numeric:tabular-nums}
.hp{position:absolute;left:-9999px;top:-9999px;height:0;overflow:hidden}
</style>
</head>
<body>
<div class="card">
<h1>Verifying you are not a bot</h1>
<p id="bd-status">Starting&hellip;</p>
<p><noscript>This check requires JavaScript.</noscript></p>
</div>
<div id="bd-pow" data-token="{{.Token}}" data-action="{{.VerifyPath}}"></div>
<input type="text" name="bd_next" class="hp" value="{{.Next}}" tabindex="-1" autocomplete="off" readonly>
<input type="text" name="bd_hp" class="hp" value="" tabindex="-1" autocomplete="off">
<script>{{.JS}}</script>
</body>
</html>`))

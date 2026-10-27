package humanverify

import (
	_ "embed"
	"html/template"
)

// pageJS is the embedded press-and-hold solver. It times the hold,
// counts pointermove events and accumulates pointer travel, then
// POSTs the signals to the verify endpoint.
//
//go:embed humanverify.js
var pageJS string

type pageData struct {
	Token      string
	VerifyPath string
	Next       string
	MinHoldMS  string
	JS         template.JS
}

var pageTpl = template.Must(template.New("humanverify").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Human verification</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif;background:#fafafa;color:#111}
.card{max-width:26rem;padding:2rem;border:2px solid #111;box-shadow:6px 6px 0 #111;background:#fff;text-align:center}
h1{font-size:1.25rem;margin:0 0 .75rem}
p{margin:.25rem 0;color:#444}
#hv-btn{margin-top:1.25rem;width:100%;padding:1rem;font:inherit;font-weight:600;border:2px solid #111;background:#ffe94a;box-shadow:4px 4px 0 #111;cursor:pointer;user-select:none;-webkit-user-select:none;touch-action:none;position:relative;overflow:hidden}
#hv-btn:active{transform:translate(2px,2px);box-shadow:2px 2px 0 #111}
#hv-fill{position:absolute;left:0;top:0;bottom:0;width:0;background:rgba(0,0,0,.12);pointer-events:none}
#hv-status{font-variant-numeric:tabular-nums;font-size:.875rem}
.hp{position:absolute;left:-9999px;top:-9999px;height:0;overflow:hidden}
</style>
</head>
<body>
<div class="card">
<h1>Quick human check</h1>
<p id="hv-status">Press and hold the button to continue.</p>
<button id="hv-btn" type="button" data-token="{{.Token}}" data-action="{{.VerifyPath}}"
 data-next="{{.Next}}" data-min-hold="{{.MinHoldMS}}">
<span id="hv-fill"></span>Press &amp; hold
</button>
<p><noscript>This check requires JavaScript.</noscript></p>
</div>
<input type="text" name="hv_hp" class="hp" value="" tabindex="-1" autocomplete="off">
<script>{{.JS}}</script>
</body>
</html>`))

package sliderverify

import (
	_ "embed"
	"fmt"
	"html/template"
)

// pageJS is the embedded slider solver.
//
//go:embed sliderverify.js
var pageJS string

type pageData struct {
	Token      string
	VerifyPath string
	Next       string
	TargetPct  int
	TargetLeft string
	JS         template.JS
}

var pageTpl = template.Must(template.New("sliderverify").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Security Verification</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:system-ui,-apple-system,BlinkMacSystemFont,sans-serif;background:#f4f5f7;color:#1e293b}
.card{width:100%;max-width:24rem;padding:2rem;border-radius:12px;background:#ffffff;box-shadow:0 10px 25px -5px rgba(0,0,0,0.1),0 8px 10px -6px rgba(0,0,0,0.1);text-align:center;box-sizing:border-box}
h1{font-size:1.25rem;font-weight:700;margin:0 0 .5rem;color:#0f172a}
p{margin:.25rem 0;color:#64748b;font-size:.875rem}
.slider-container{margin-top:1.5rem;position:relative}
.slider-track{width:100%;height:48px;background:#e2e8f0;border-radius:24px;position:relative;overflow:hidden;user-select:none;-webkit-user-select:none;touch-action:none}
.slider-fill{position:absolute;left:0;top:0;height:100%;width:0;background:#93c5fd;pointer-events:none}
.slider-target{position:absolute;top:4px;width:40px;height:40px;border-radius:20px;border:2px dashed #3b82f6;background:rgba(59,130,246,0.15);box-sizing:border-box;pointer-events:none;transform:translateX(-50%)}
.slider-thumb{position:absolute;left:2px;top:2px;width:44px;height:44px;border-radius:22px;background:#2563eb;color:#fff;display:flex;align-items:center;justify-content:center;cursor:grab;box-shadow:0 4px 6px -1px rgba(37,99,235,0.4);transition:background .15s}
.slider-thumb:hover{background:#1d4ed8}
.slider-thumb:active{cursor:grabbing;background:#1e40af}
.slider-thumb svg{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
#sv-status{margin-top:1rem;font-size:.8125rem;font-weight:500;min-height:1.25rem}
.hp{position:absolute;left:-9999px;top:-9999px;height:0;overflow:hidden}
</style>
</head>
<body>
<div class="card">
<h1>Verify you are human</h1>
<p>Slide the button into the target circle to continue.</p>
<div class="slider-container">
  <div id="sv-track" class="slider-track" data-token="{{.Token}}" data-action="{{.VerifyPath}}" data-next="{{.Next}}" data-target="{{.TargetPct}}">
    <div id="sv-fill" class="slider-fill"></div>
    <div id="sv-target" class="slider-target" style="left:{{.TargetLeft}};"></div>
    <div id="sv-thumb" class="slider-thumb" aria-label="Slider handle" role="slider">
      <svg viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
    </div>
  </div>
</div>
<div id="sv-status"></div>
<p><noscript>Please enable JavaScript to complete verification.</noscript></p>
</div>
<input type="text" name="sv_hp" class="hp" value="" tabindex="-1" autocomplete="off">
<script>{{.JS}}</script>
</body>
</html>`))

func formatPercent(pct int) string {
	return fmt.Sprintf("%d%%", pct)
}

// Press-and-hold solver for the humanverify challenge page. Tracks
// the pointer hold duration, movement count, and accumulated travel
// (jitter), then POSTs the signals to the verify endpoint.
(function () {
  'use strict';

  var btn = document.getElementById('hv-btn');
  var fill = document.getElementById('hv-fill');
  var status = document.getElementById('hv-status');
  var hp = document.querySelector('input[name="hv_hp"]');
  if (!btn) { return; }

  var token = btn.getAttribute('data-token');
  var action = btn.getAttribute('data-action');
  var next = btn.getAttribute('data-next') || '/';
  var minHold = parseInt(btn.getAttribute('data-min-hold'), 10) || 800;

  var holding = false;
  var startT = 0;
  var moves = 0;
  var jitter = 0;
  var lastX = null, lastY = null;
  var raf = null;

  function setStatus(s) { if (status) { status.textContent = s; } }

  function onMove(e) {
    if (!holding) { return; }
    moves++;
    if (lastX !== null) {
      jitter += Math.abs(e.clientX - lastX) + Math.abs(e.clientY - lastY);
    }
    lastX = e.clientX; lastY = e.clientY;
  }

  function tick() {
    if (!holding) { return; }
    var pct = Math.min(100, ((performance.now() - startT) / minHold) * 100);
    if (fill) { fill.style.width = pct + '%'; }
    raf = requestAnimationFrame(tick);
  }

  function submit() {
    var body = 'token=' + encodeURIComponent(token) +
      '&hold_ms=' + encodeURIComponent(String(Math.round(performance.now() - startT))) +
      '&moves=' + encodeURIComponent(String(moves)) +
      '&jitter=' + encodeURIComponent(String(jitter)) +
      '&ptr=' + encodeURIComponent(btn._ptrType || '') +
      '&hv_hp=' + encodeURIComponent(hp ? hp.value : '') +
      '&hv_next=' + encodeURIComponent(next);
    setStatus('Verifying…');
    fetch(action, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      credentials: 'same-origin',
      body: body
    }).then(function (res) {
      if (res.ok) {
        res.json().then(function (d) {
          window.location.href = (d && d.next) ? d.next : '/';
        }).catch(function () { window.location.href = '/'; });
        return;
      }
      setStatus('Verification failed. Please reload to try again.');
    }).catch(function () {
      setStatus('Network error. Please reload to try again.');
    });
  }

  function start(e) {
    if (holding) { return; }
    e.preventDefault();
    holding = true;
    startT = performance.now();
    moves = 0; jitter = 0;
    lastX = e.clientX; lastY = e.clientY;
    btn._ptrType = e.pointerType || '';
    setStatus('Keep holding…');
    document.addEventListener('pointermove', onMove);
    raf = requestAnimationFrame(tick);
  }

  function stop() {
    if (!holding) { return; }
    holding = false;
    cancelAnimationFrame(raf);
    document.removeEventListener('pointermove', onMove);
    var held = performance.now() - startT;
    if (fill) { fill.style.width = '0'; }
    if (held >= minHold) { submit(); return; }
    setStatus('Released too soon — hold a little longer.');
  }

  btn.addEventListener('pointerdown', start);
  btn.addEventListener('pointerup', stop);
  btn.addEventListener('pointerleave', stop);
  btn.addEventListener('pointercancel', stop);
  btn.addEventListener('contextmenu', function (e) { e.preventDefault(); });
})();

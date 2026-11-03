// Slider solver: captures pointer events, tracks trajectory with timestamps,
// coordinates, orthogonal jitter, and posts kinematics to the server upon drop.
(function () {
  'use strict';

  var track = document.getElementById('sv-track');
  var thumb = document.getElementById('sv-thumb');
  var fill = document.getElementById('sv-fill');
  var target = document.getElementById('sv-target');
  var status = document.getElementById('sv-status');
  var hp = document.querySelector('input[name="sv_hp"]');
  if (!track || !thumb || !target) { return; }

  var token = track.getAttribute('data-token');
  var action = track.getAttribute('data-action');
  var next = track.getAttribute('data-next') || '/';
  var targetPct = parseFloat(track.getAttribute('data-target')) || 70;

  var dragging = false;
  var startT = 0;
  var startX = 0, startY = 0;
  var currentX = 0;
  var trajectory = [];
  var ptrType = '';

  function setStatus(s) { if (status) { status.textContent = s; } }

  function getTrackRect() {
    return track.getBoundingClientRect();
  }

  function onPointerDown(e) {
    if (dragging) { return; }
    e.preventDefault();
    dragging = true;
    ptrType = e.pointerType || 'mouse';
    startT = performance.now();
    startX = e.clientX;
    startY = e.clientY;
    currentX = 0;
    trajectory = [{
      t: 0,
      x: 0,
      y: 0
    }];

    track.classList.add('active');
    setStatus('Slide to match the target box…');

    document.addEventListener('pointermove', onPointerMove);
    document.addEventListener('pointerup', onPointerUp);
    document.addEventListener('pointercancel', onPointerCancel);
  }

  function onPointerMove(e) {
    if (!dragging) { return; }
    var rect = getTrackRect();
    var thumbWidth = thumb.offsetWidth || 44;
    var maxTravel = rect.width - thumbWidth;
    if (maxTravel <= 0) { maxTravel = 1; }

    var dx = e.clientX - startX;
    var dy = e.clientY - startY;

    var clampedX = Math.max(0, Math.min(dx, maxTravel));
    var pct = (clampedX / maxTravel) * 100;
    currentX = pct;

    thumb.style.transform = 'translateX(' + clampedX + 'px)';
    if (fill) { fill.style.width = clampedX + 'px'; }

    var now = performance.now();
    trajectory.push({
      t: Math.round(now - startT),
      x: Math.round(pct * 100) / 100,
      y: Math.round(dy * 10) / 10
    });
  }

  function resetSlider() {
    dragging = false;
    track.classList.remove('active');
    thumb.style.transform = 'translateX(0px)';
    if (fill) { fill.style.width = '0px'; }
    document.removeEventListener('pointermove', onPointerMove);
    document.removeEventListener('pointerup', onPointerUp);
    document.removeEventListener('pointercancel', onPointerCancel);
  }

  function onPointerCancel() {
    resetSlider();
    setStatus('Slide cancelled. Try again.');
  }

  function onPointerUp(e) {
    if (!dragging) { return; }
    var now = performance.now();
    var duration = Math.round(now - startT);
    var finalPos = currentX;

    // Append final coordinate
    var dy = e.clientY - startY;
    trajectory.push({
      t: duration,
      x: Math.round(finalPos * 100) / 100,
      y: Math.round(dy * 10) / 10
    });

    document.removeEventListener('pointermove', onPointerMove);
    document.removeEventListener('pointerup', onPointerUp);
    document.removeEventListener('pointercancel', onPointerCancel);
    dragging = false;
    track.classList.remove('active');

    setStatus('Verifying…');

    var payload = {
      duration_ms: duration,
      final_pos: finalPos,
      pointer_type: ptrType,
      trajectory: trajectory
    };

    var body = 'token=' + encodeURIComponent(token) +
      '&kinematics=' + encodeURIComponent(JSON.stringify(payload)) +
      '&sv_hp=' + encodeURIComponent(hp ? hp.value : '') +
      '&sv_next=' + encodeURIComponent(next);

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
      setStatus('Verification failed. Try again.');
      setTimeout(resetSlider, 800);
    }).catch(function () {
      setStatus('Network error. Reload and try again.');
      setTimeout(resetSlider, 800);
    });
  }

  thumb.addEventListener('pointerdown', onPointerDown);
  thumb.addEventListener('contextmenu', function (e) { e.preventDefault(); });
})();

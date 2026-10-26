// Proof-of-work solver for the botdetect challenge page. Finds a
// counter such that SHA-256(token + ":" + counter) has the required
// leading zero bits, running inside a Web Worker so the page stays
// responsive, then POSTs the solution to the verify endpoint.
//
// Note: crypto.subtle requires a secure context (HTTPS or localhost).
(function () {
  'use strict';

  var el = document.getElementById('bd-pow');
  if (!el) { return; }
  var token = el.getAttribute('data-token');
  var action = el.getAttribute('data-action');
  var status = document.getElementById('bd-status');
  var hp = document.querySelector('input[name="bd_hp"]');
  var next = document.querySelector('input[name="bd_next"]');
  if (!token || !action) { return; }

  var diff = parseInt(token.split('.')[2], 10);

  function setStatus(s) { if (status) { status.textContent = s; } }

  var workerSrc =
    'function sha(s){return crypto.subtle.digest("SHA-256",new TextEncoder().encode(s))' +
    '.then(function(b){return new Uint8Array(b)})}' +
    'function zb(a){var n=0;for(var i=0;i<a.length;i++){var v=a[i];' +
    'if(v===0){n+=8;continue}var m=128;while(!(v&m)){n++;m>>=1}return n}return n}' +
    'onmessage=function(e){var t=e.data[0],d=e.data[1],c=0;' +
    '(function step(){sha(t+":"+c).then(function(h){' +
    'if(zb(h)>=d){postMessage({c:c});return}c++;' +
    'if(c%8192===0){postMessage({p:c});setTimeout(step,0);return}step()})})()};';

  function submit(counter) {
    var body = 'token=' + encodeURIComponent(token) +
      '&counter=' + encodeURIComponent(String(counter)) +
      '&bd_hp=' + encodeURIComponent(hp ? hp.value : '') +
      '&bd_next=' + encodeURIComponent(next ? next.value : '/');
    setStatus('Solution found — verifying…');
    fetch(action, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      credentials: 'same-origin',
      body: body
    }).then(function (res) {
      if (res.ok) { window.location.reload(); return; }
      setStatus('Verification failed. Please reload to try again.');
    }).catch(function () {
      setStatus('Network error. Please reload to try again.');
    });
  }

  try {
    var w = new Worker(URL.createObjectURL(new Blob([workerSrc], { type: 'text/javascript' })));
    w.onmessage = function (e) {
      if (e.data.c !== undefined) { w.terminate(); submit(e.data.c); return; }
      setStatus('Working… ' + (e.data.p || 0).toLocaleString() + ' attempts');
    };
    w.onerror = function () { setStatus('Challenge failed to start. Please reload.'); };
    w.postMessage([token, diff]);
  } catch (err) {
    setStatus('Your browser cannot run this challenge.');
  }
})();

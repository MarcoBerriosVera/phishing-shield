// content-blocker.js  — Phishing Shield MV3
// Injected into every page. If the orchestrator returns danger,
// this script replaces the page DOM with the block screen.

(function () {
  'use strict';

  // Avoid running inside iframes or already-blocked pages
  if (window !== window.top) return;
  if (document.getElementById('ps-block-overlay')) return;

  // ── State ──────────────────────────────────────────────────────────────────
  let analysisResult = null;
  let overlayInjected = false;

  // ── Listen for messages from the background service worker ─────────────────
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.action === 'blockPage') {
      injectBlockOverlay(msg.data);
      sendResponse({ ok: true });
    }
    if (msg.action === 'clearBlock') {
      removeOverlay();
      sendResponse({ ok: true });
    }
  });

  // ── Inject block overlay ───────────────────────────────────────────────────
  function injectBlockOverlay(data = {}) {
    if (overlayInjected) return;
    overlayInjected = true;

    // Stop the page from doing anything
    window.stop();

    // Build the overlay that covers the entire viewport
    const overlay = document.createElement('div');
    overlay.id = 'ps-block-overlay';

    const blockUrl = chrome.runtime.getURL('block.html');
    const params = new URLSearchParams({
      url:        encodeURIComponent(data.url        || location.href),
      score:      data.score       || '0',
      heuristics: data.heuristics  || '0',
      similarity: data.similarity  || '0',
      reputation: data.reputation  || '0',
      ml:         data.ml          || '0',
      reasons:    encodeURIComponent((data.reasons || []).join('|')),
    });

    overlay.style.cssText = [
      'position:fixed',
      'inset:0',
      'width:100vw',
      'height:100vh',
      'z-index:2147483647',
      'background:#0d0d0d',
      'border:none',
      'margin:0',
      'padding:0',
    ].join(';');

    const iframe = document.createElement('iframe');
    iframe.src = `${blockUrl}?${params.toString()}`;
    iframe.style.cssText = [
      'width:100%',
      'height:100%',
      'border:none',
      'display:block',
    ].join(';');

    overlay.appendChild(iframe);

    // Replace entire body content
    document.documentElement.innerHTML = '';
    document.documentElement.appendChild(overlay);

    // Also push a history entry so back-button works from within the iframe
    history.pushState(null, '', location.href);
  }

  function removeOverlay() {
    const el = document.getElementById('ps-block-overlay');
    if (el) el.remove();
    overlayInjected = false;
  }

})();

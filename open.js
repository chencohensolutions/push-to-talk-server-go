// Talk's link pages (2026-11-24): the words after # are a ptt:// link's own (never sent to this site). "Open in
// Talk" hands them to the app; without it, the latest release is one tap away.
(function () {
  var kind = document.documentElement.getAttribute('data-kind');
  var words = location.hash.replace(/^#/, '');
  var app = 'ptt://' + kind + '?' + words;
  var release = 'https://github.com/chencohensolutions/push-to-talk-kmp/releases/latest';
  var android = /Android/i.test(navigator.userAgent);
  var open = document.getElementById('open');
  var link = document.getElementById('link');
  if (!words) {
    document.getElementById('missing').hidden = false;
    open.hidden = true;
    return;
  }
  open.href = android
    ? 'intent://' + kind + '?' + words + '#Intent;scheme=ptt;package=com.chencohen.ptt;S.browser_fallback_url=' + encodeURIComponent(release) + ';end'
    : app;
  link.textContent = app;
  document.getElementById('copy').onclick = function () {
    navigator.clipboard && navigator.clipboard.writeText(app);
    this.textContent = this.getAttribute('data-done');
  };
  // Straight into the app on Android, the page staying for when it isn't installed.
  if (android) setTimeout(function () { location.href = open.href; }, 300);
})();

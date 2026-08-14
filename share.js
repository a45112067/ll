(function () {
  'use strict';
  if (document.getElementById('shareFab')) return;

  var isEn = document.documentElement.getAttribute('lang') === 'en';
  var pageUrl = location.href;
  var cleanUrl = location.protocol + '//' + location.host + location.pathname;
  var siteText = isEn
    ? 'Ahmed Ayman Yahya - Official Website: '
    : 'أحمد أيمن يحيى - الموقع الرسمي: ';

  var fab = document.createElement('button');
  fab.id = 'shareFab';
  fab.className = 'share-fab';
  fab.setAttribute('aria-label', isEn ? 'Share this page' : 'مشاركة هذه الصفحة');
  fab.innerHTML = '<i class="fas fa-share-alt fab-open"></i><i class="fas fa-times fab-close"></i>';

  var modal = document.createElement('div');
  modal.id = 'shareModal';
  modal.className = 'share-modal';
  modal.innerHTML =
    '<h4><i class="fas fa-share-alt"></i><span class="sh-ar">مشاركة الصفحة</span><span class="sh-en">Share this page</span></h4>' +
    '<p><span class="sh-ar">شارك رابط الصفحة الحالية مع أصدقائك بسهولة</span><span class="sh-en">Share this page link with your friends easily</span></p>' +
    '<div class="share-url"><span class="sh-url"></span><button type="button" class="sh-copy"><i class="fas fa-copy"></i><span class="sh-ar">نسخ</span><span class="sh-en">Copy</span></button></div>' +
    '<div class="share-grid">' +
    '<a class="swa" target="_blank" rel="noopener noreferrer" title="WhatsApp"><i class="fab fa-whatsapp"></i><span>WhatsApp</span></a>' +
    '<a class="sfb" target="_blank" rel="noopener noreferrer" title="Facebook"><i class="fab fa-facebook-f"></i><span>Facebook</span></a>' +
    '<a class="stg" target="_blank" rel="noopener noreferrer" title="Telegram"><i class="fab fa-telegram-plane"></i><span>Telegram</span></a>' +
    '<a class="sx" target="_blank" rel="noopener noreferrer" title="X (Twitter)"><i class="fab fa-x-twitter"></i><span>X</span></a>' +
    '<a class="sli" target="_blank" rel="noopener noreferrer" title="LinkedIn"><i class="fab fa-linkedin-in"></i><span>LinkedIn</span></a>' +
    '<button type="button" class="scp"><i class="fas fa-link"></i><span class="sh-ar">رابط مختصر</span><span class="sh-en">Short</span></button>' +
    '</div>';

  var enEls = modal.querySelectorAll('.sh-en');
  var arEls = modal.querySelectorAll('.sh-ar');
  if (isEn) { arEls.forEach(function (el) { el.style.display = 'none'; }); }
  else { enEls.forEach(function (el) { el.style.display = 'none'; }); }

  document.body.appendChild(fab);
  document.body.appendChild(modal);

  modal.querySelector('.sh-url').textContent = cleanUrl;

  var open = false;
  function toggle() {
    open = !open;
    fab.classList.toggle('open', open);
    modal.classList.toggle('open', open);
  }
  fab.addEventListener('click', toggle);

  function toast(msg) {
    var isEnglish = document.body.classList.contains('english');
    var t = document.createElement('div');
    t.style.cssText = 'position:fixed;bottom:100px;z-index:9000;background:#0f172a;color:#fff;padding:12px 20px;border-radius:12px;font-weight:800;font-size:.85rem;font-family:inherit;box-shadow:0 14px 34px rgba(0,0,0,.3);transition:opacity .3s,transform .3s;right:24px;';
    if (isEnglish) { t.style.left = '24px'; t.style.right = 'auto'; }
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(function () { t.style.opacity = '0'; t.style.transform = 'translateY(8px)'; }, 1800);
    setTimeout(function () { t.remove(); }, 2200);
  }

  function copyToClipboard(text, okMsg) {
    var done = function () { toast(okMsg); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { legacyCopy(text, done); });
    } else { legacyCopy(text, done); }
  }
  function legacyCopy(text, cb) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); cb(); } catch (e) {}
    ta.remove();
  }

  modal.querySelector('.sh-copy').addEventListener('click', function () {
    copyToClipboard(cleanUrl, isEn ? 'Link copied!' : 'تم نسخ الرابط!');
  });

  function shorten() {
    var btn = modal.querySelector('.scp');
    btn.disabled = true;
    btn.style.opacity = '.6';
    fetch('https://is.gd/create.php?format=json&url=' + encodeURIComponent(cleanUrl))
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d && d.shorturl) {
          cleanUrl = d.shorturl;
          modal.querySelector('.sh-url').textContent = d.shorturl;
          copyToClipboard(d.shorturl, isEn ? 'Short link created & copied!' : 'تم إنشاء الرابط المختصر ونسخه!');
        } else {
          toast(isEn ? 'Could not shorten the link' : 'تعذر تقصير الرابط');
        }
      })
      .catch(function () { toast(isEn ? 'Could not shorten the link' : 'تعذر تقصير الرابط'); })
      .then(function () { btn.disabled = false; btn.style.opacity = '1'; });
  }
  modal.querySelector('.scp').addEventListener('click', shorten);

  var urlEnc = encodeURIComponent(pageUrl);
  var textEnc = encodeURIComponent(siteText);
  var links = {
    '.swa': 'https://wa.me/?text=' + textEnc + '%20' + urlEnc,
    '.sfb': 'https://www.facebook.com/sharer/sharer.php?u=' + urlEnc,
    '.stg': 'https://t.me/share/url?url=' + urlEnc + '&text=' + textEnc,
    '.sx': 'https://twitter.com/intent/tweet?url=' + urlEnc + '&text=' + textEnc,
    '.sli': 'https://www.linkedin.com/sharing/share-offsite/?url=' + urlEnc
  };
  Object.keys(links).forEach(function (sel) {
    var el = modal.querySelector(sel);
    if (el) el.href = links[sel];
  });

  document.addEventListener('click', function (e) {
    if (open && !fab.contains(e.target) && !modal.contains(e.target)) toggle();
  });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && open) toggle(); });
})();
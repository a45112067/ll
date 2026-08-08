/* ===== حماية الموقع: طبقة ردع من الفحص وسرقة المحتوى =====
   ملاحظة أمنية صادقة: ملف ثابت يُرسل للمتصفح ليتمكن الموقع من العمل،
   فلا يمكن منع المشاهدة نهائيًا، لكن هذا يقف في وجه الفحص العابر وأدوات النسخ الآلي. */
(function () {
  "use strict";

  var DEV = false; // ارفعها true أثناء التطوير لترجيع الاختصارات

  /* منع قائمة الفحص بزر الفأرة الأيمن */
  document.addEventListener("contextmenu", function (e) {
    if (!DEV) e.preventDefault();
  }, false);

  /* منع اختصارات الفحص: F12 / Ctrl+Shift+I,J,C / Ctrl+U / Ctrl+S / Ctrl+P */
  document.addEventListener("keydown", function (e) {
    if (DEV) return;
    var k = e.keyCode || e.which;
    var ctrl = e.ctrlKey || e.metaKey;
    var shift = e.shiftKey;
    var blocked = (
      k === 123 ||
      (ctrl && shift && (k === 73 || k === 74 || k === 67)) ||
      (ctrl && (k === 85 || k === 83 || k === 80))
    );
    if (blocked) { e.preventDefault(); e.stopPropagation(); }
  }, true);

  /* حماية الاختيار والنسخ (مع إبقاء الحقول النصية تعمل) */
  document.addEventListener("copy", function (e) { if (!DEV) e.preventDefault(); }, true);
  document.addEventListener("selectstart", function (e) {
    var tag = (e.target && e.target.tagName) || "";
    if (tag === "INPUT" || tag === "TEXTAREA") return;
    if (!DEV) e.preventDefault();
  }, true);
  document.addEventListener("dragstart", function (e) {
    var tag = (e.target && e.target.tagName) || "";
    if (tag === "INPUT" || tag === "TEXTAREA") return;
    if (!DEV) e.preventDefault();
  }, true);
})();
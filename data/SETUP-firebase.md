# إعداد Firebase للموقع (مدونة + لوحة إدارة)

تم ربط الموقع بخدمات **Firebase** لتعمل المدونة ولوحة الإدارة مباشرة دون خادم.

## الملفات
- `firebase-init.js` — إعدادات المشروع (آمنة للكشف، ليست سرية).
- `blog.html` — المدونة: تعرض المنشورات ذات الحالة `published` من Firestore.
- `admin.html` — لوحة الإدارة: تسجيل دخول + إدارة منشورات + إعدادات موقع، تخزّن في Firestore.

## المطلوب في Firebase Console (خطوة واحدة ضرورية)
1. افتح https://console.firebase.google.com → مشروعك `ahmed-ayman-ef2f4`.
2. من **Build → Firestore Database** أنشئ قاعدة بيانات (وضع إنتاج).
3. من **Build → Authentication → Sign-in method** فعّل **Email/Password**.

## إضافة قواعد الأمان (مهم — بدونها لن تعمل/سيُخنق الموقع)
التنسيق **Firestore Database → Rules**:

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    // قراءة عامة آمنة
    match /{document=**} {
      allow read: if true;
    }

    match /posts/{postId} {
      allow write: if false;
    }
    match /site/{siteId} {
      allow write: if false;
    }

    // صلاحيات المدير الموسّعة للمستخدمين المسجّلين فقط
    match /{document=**} {
      allow write: if request.auth != null;
    }
  }
}
```

⚠️ ملاحظة: `allow write: if request.auth != null` يسمح بأيّ مستخدم مسجّل. للحدّ، اكتب بريدك
داخل الدالة:
```text
allow write: if request.auth?.token.email == ['admin@ahmedayman.website'].hasAny([request.auth.token.email]);
```
واستبدل البريد ببريد هندمان.

## خطوات الاستخدام
1. افتح `admin.html` في المتصفح.
2. اضغط **+ إنشاء حساب أدمن جديد** ببريد وكلمة مرور (أول مرة فقط) — أو أنشئ الحساب من الكونسول (Authentication → Add user) ثم قم بإدخاله عبر صفحة الدخول.
3. اكتب منشورات من قسم «المنشورات/منشور جديد» وحدّث «إعدادات الموقع».
4. افتح `blog.html` سترى المنشورات المنشورة فقط.
5. اربط `blog.html` بربّل القائمة في كل الصفحات.

## الاختبار محلياً
افتح الملفات مباشرة في المتصفح (شفرة JS تُنفّذ محلياً). لو احتجت خادماً محلياً لغرض تخطيط: `python -m http.server 8000`.

## رفع المدونة للزائر (اختياري لاحقاً)
- أدر `blog.html` و`firebase-init.js` ضمن ملفات النشر.
- يمكن لاحقاً ربط `blog.html` بقائمة الصفحات.
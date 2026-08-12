# Sun-Mi Payment Integration — Shopify + Kashier + Coolify

هذه الحزمة تنقل صفحة العرض الحالية من:

`Product page → Shopify Checkout`

إلى:

`Product page → اختيار الشحن → اختيار الدفع → Kashier iframe أو COD`

## 1) ما تم تنفيذه

- Backend آمن لـ Kashier على Coolify.
- Shopify Client Credentials token مع تجديد تلقائي كل 24 ساعة.
- Shopify App Proxy validation باستخدام HMAC.
- حساب طرق الشحن من Shopify عبر `draftOrderAvailableDeliveryOptions`.
- حساب الخصومات التلقائية والإجمالي عبر `draftOrderCalculate`.
- إنشاء Shopify Draft Order بالسعر النهائي قبل الدفع.
- COD: تحويل الـDraft إلى Order بحالة دفع معلقة باستخدام `paymentPending: true`.
- Kashier: إنشاء `/v3/payment/sessions` بالمبلغ النهائي المحسوب من Shopify.
- Kashier iframe داخل صفحة المنتج.
- Endpoint للرجوع من Kashier + polling لحالة Shopify.
- Endpoint Webhook آمن بمسار سري، لكنه **لا يضع الطلب Paid تلقائياً حتى يتم تأكيد بنية Webhook والتوقيع الرسمي من Kashier**.

## 2) Shopify Dev Dashboard

أنشئ App باسم:

`Sunmi Payment Integration`

الـScopes المطلوبة:

- `read_products`
- `read_draft_orders`
- `write_draft_orders`
- `read_orders`
- `write_app_proxy`

أنشئ Version ثم App Proxy:

- Prefix: `apps`
- Subpath: `sunmi-pay`
- Proxy URL: `/proxy`

إذا كان عنوان التطبيق على Coolify:

`https://pay.sunmilab.com`

فإن:

`https://YOUR-STORE/apps/sunmi-pay/quote`

سيتم تمريره إلى:

`https://pay.sunmilab.com/proxy/quote`

بعد Release ثبّت التطبيق على متجرك.

من Settings في Dev Dashboard انسخ لديك فقط:

- Client ID
- Client secret

ولا ترسلهما في المحادثة.

## 3) Coolify

أنشئ Application جديدة من Git repository أو ارفع هذه الحزمة إلى GitHub.

Build Pack:
- Dockerfile

Port:
- `3000`

Domain مثال:
- `https://pay.sunmilab.com`

أضف Environment Variables من `.env.example`.

مهم:
- `SHOPIFY_SHOP_DOMAIN` يجب أن يكون `xxxx.myshopify.com` وليس الدومين المخصص.
- `STORE_ORIGIN` يكون دومين المتجر الذي يراه العميل مثل `https://sunmilab.com`.
- `PUBLIC_BASE_URL` يكون دومين تطبيق Coolify.
- لا تضع أي Secret داخل Shopify Theme.

## 4) Kashier

ابدأ بـ:

`KASHIER_MODE=test`

واستخدم مفاتيح Test إن كانت لوحة Kashier تفصل Test/Live.

الـBackend ينشئ Payment Session عبر:

`POST https://test-api.kashier.io/v3/payment/sessions`

وعند التحويل إلى Live:

`KASHIER_MODE=live`

فيستخدم:

`POST https://api.kashier.io/v3/payment/sessions`

## 5) Shopify Theme

استبدل سكشن الطلب الحالي بالملف:

`shopify/sunmi_customer_order_form_one_page.liquid`

ثم تأكد أن App Proxy يعمل قبل اختبار الدفع.

## 6) اختبار الصحة

افتح:

`https://pay.sunmilab.com/health`

المتوقع:

```json
{
  "ok": true,
  "service": "sunmi-payment-api",
  "shopifyApiVersion": "2026-07",
  "kashierMode": "test",
  "webhookAutocomplete": false
}
```

## 7) ترتيب الاختبار

1. افتح صفحة المنتج.
2. أدخل عنواناً مصرياً صالحاً.
3. يجب أن تظهر طرق الشحن القادمة من Shopify.
4. اختر Kashier.
5. اضغط الدفع الآن.
6. يجب أن يظهر Kashier داخل Modal في نفس الصفحة.
7. نفّذ **TEST payment فقط**.
8. افتح Coolify → Application → Logs.
9. ابحث عن:
   `[KASHIER_WEBHOOK_CAPTURE]`
10. نستخدم الـpayload الناتج مع قسم Webhook في Kashier Dashboard لتطبيق التحقق النهائي من التوقيع والحالة.

## لماذا Webhook لا يضع الطلب Paid الآن؟

لأننا لم نستلم بعد من توثيق حساب Kashier:
- شكل Webhook payload الحقيقي.
- Header أو field الخاص بالتوقيع.
- خوارزمية التحقق الرسمية.
- القيمة الرسمية التي تعني نجاح الدفع النهائي.

لا يجوز تخمين هذه القيم في نظام دفع Live.

باقي النظام جاهز، والـWebhook الحالي مصمم **fail-closed**: يستقبل Test webhook ويسجله بعد إخفاء الحقول الحساسة، لكنه لا يكمل الطلب كـPaid.

## ملاحظة حول COD

الإصدار الحالي يستخدم `paymentPending: true` في `draftOrderComplete`.
الحقل ما زال متاحاً في Shopify API 2026-07 ولكنه Deprecated. بعد تثبيت التدفق الأساسي يمكن استبداله بـPayment Terms أو Payment Gateway ID إذا أردت مطابقة طريقة COD في Shopify حرفياً.

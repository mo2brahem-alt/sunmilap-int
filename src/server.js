import express from "express";
import crypto from "node:crypto";

const app = express();

const env = {
  PORT: Number(process.env.PORT || 3000),
  SHOPIFY_SHOP_DOMAIN: String(process.env.SHOPIFY_SHOP_DOMAIN || "").trim(),
  SHOPIFY_CLIENT_ID: String(process.env.SHOPIFY_CLIENT_ID || "").trim(),
  SHOPIFY_CLIENT_SECRET: String(process.env.SHOPIFY_CLIENT_SECRET || "").trim(),
  SHOPIFY_API_VERSION: String(process.env.SHOPIFY_API_VERSION || "2026-07").trim(),
  PUBLIC_BASE_URL: String(process.env.PUBLIC_BASE_URL || "").replace(/\/+$/, ""),
  STORE_ORIGIN: String(process.env.STORE_ORIGIN || "").replace(/\/+$/, ""),
  KASHIER_MODE: String(process.env.KASHIER_MODE || "test").toLowerCase(),
  KASHIER_API_KEY: String(process.env.KASHIER_API_KEY || "").trim(),
  KASHIER_SECRET_KEY: String(process.env.KASHIER_SECRET_KEY || "").trim(),
  KASHIER_MERCHANT_ID: String(process.env.KASHIER_MERCHANT_ID || "").trim(),
  KASHIER_ALLOWED_METHODS: String(process.env.KASHIER_ALLOWED_METHODS || "card,wallet").trim(),
  KASHIER_SESSION_MINUTES: Math.max(5, Math.min(60, Number(process.env.KASHIER_SESSION_MINUTES || 20))),
  KASHIER_WEBHOOK_TOKEN: String(process.env.KASHIER_WEBHOOK_TOKEN || "").trim(),
  KASHIER_WEBHOOK_AUTOCOMPLETE:
    String(process.env.KASHIER_WEBHOOK_AUTOCOMPLETE || "false").toLowerCase() === "true",
};

const required = [
  "SHOPIFY_SHOP_DOMAIN",
  "SHOPIFY_CLIENT_ID",
  "SHOPIFY_CLIENT_SECRET",
  "PUBLIC_BASE_URL",
  "STORE_ORIGIN",
  "KASHIER_API_KEY",
  "KASHIER_SECRET_KEY",
  "KASHIER_MERCHANT_ID",
  "KASHIER_WEBHOOK_TOKEN",
];

for (const key of required) {
  if (!env[key]) {
    console.warn(`[Sun-Mi] Missing environment variable: ${key}`);
  }
}

app.disable("x-powered-by");
app.use(express.json({ limit: "128kb" }));

function json(res, status, payload) {
  res.status(status);
  res.set("Cache-Control", "no-store");
  return res.json(payload);
}

function safeEqualHex(a, b) {
  try {
    const aa = Buffer.from(String(a || ""), "hex");
    const bb = Buffer.from(String(b || ""), "hex");
    if (!aa.length || aa.length !== bb.length) return false;
    return crypto.timingSafeEqual(aa, bb);
  } catch {
    return false;
  }
}

function verifyAppProxy(req) {
  const url = new URL(req.originalUrl, env.PUBLIC_BASE_URL || "https://localhost");
  const params = new Map();

  for (const [key, value] of url.searchParams.entries()) {
    if (key === "signature") continue;
    const list = params.get(key) || [];
    list.push(value);
    params.set(key, list);
  }

  const signature = url.searchParams.get("signature") || "";
  const message = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, values]) => `${key}=${values.join(",")}`)
    .join("");

  const expected = crypto
    .createHmac("sha256", env.SHOPIFY_CLIENT_SECRET)
    .update(message)
    .digest("hex");

  if (!safeEqualHex(signature, expected)) return false;

  const shop = url.searchParams.get("shop");
  if (!shop || shop.toLowerCase() !== env.SHOPIFY_SHOP_DOMAIN.toLowerCase()) {
    return false;
  }

  const timestamp = Number(url.searchParams.get("timestamp") || 0);
  if (!timestamp || Math.abs(Date.now() / 1000 - timestamp) > 10 * 60) {
    return false;
  }

  return true;
}

function requireProxy(req, res, next) {
  if (!verifyAppProxy(req)) {
    return json(res, 401, { success: false, error: "Invalid Shopify app proxy signature." });
  }
  next();
}

function normalizeEgyptPhone(value) {
  let digits = String(value || "").replace(/\D/g, "");
  if (digits.startsWith("0020")) digits = digits.slice(2);
  if (digits.startsWith("20")) digits = digits.slice(2);
  if (digits.startsWith("0")) digits = digits.slice(1);
  if (!/^1[0125]\d{8}$/.test(digits)) {
    throw new Error("Invalid Egyptian mobile number.");
  }
  return `+20${digits}`;
}

function cleanText(value, max = 180) {
  return String(value || "").trim().slice(0, max);
}

function validateOrderBody(body) {
  const quantity = Math.max(1, Math.min(99, Number(body?.quantity || 1)));
  const variantIdRaw = String(body?.variantId || "").replace(/\D/g, "");
  if (!variantIdRaw) throw new Error("Variant is required.");

  const customer = {
    firstName: cleanText(body?.customer?.firstName, 80),
    lastName: cleanText(body?.customer?.lastName, 80),
    email: cleanText(body?.customer?.email, 160).toLowerCase(),
    phone: normalizeEgyptPhone(body?.customer?.phone),
    address1: cleanText(body?.customer?.address1, 180),
    address2: cleanText(body?.customer?.address2, 180),
    city: cleanText(body?.customer?.city, 100),
    provinceCode: cleanText(body?.customer?.provinceCode, 10).toUpperCase(),
    zip: cleanText(body?.customer?.zip, 30),
  };

  const requiredFields = ["firstName", "lastName", "email", "address1", "city", "provinceCode"];
  for (const field of requiredFields) {
    if (!customer[field]) throw new Error(`Missing customer field: ${field}`);
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(customer.email)) {
    throw new Error("Invalid email address.");
  }

  const paymentMethod = body?.paymentMethod === "cod" ? "cod" : "kashier";
  const language = body?.language === "ar" ? "ar" : "en";
  const shippingHandle = cleanText(body?.shippingHandle, 500);

  return {
    variantGid: `gid://shopify/ProductVariant/${variantIdRaw}`,
    variantIdRaw,
    quantity,
    customer,
    paymentMethod,
    language,
    shippingHandle,
  };
}

let tokenCache = { token: "", expiresAt: 0 };

async function getShopifyToken() {
  if (tokenCache.token && tokenCache.expiresAt > Date.now() + 60_000) {
    return tokenCache.token;
  }

  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: env.SHOPIFY_CLIENT_ID,
    client_secret: env.SHOPIFY_CLIENT_SECRET,
  });

  const response = await fetch(
    `https://${env.SHOPIFY_SHOP_DOMAIN}/admin/oauth/access_token`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    },
  );

  const payload = await response.json();
  if (!response.ok || !payload?.access_token) {
    throw new Error(payload?.error_description || payload?.error || "Could not obtain Shopify access token.");
  }

  tokenCache = {
    token: payload.access_token,
    expiresAt: Date.now() + Math.max(60, Number(payload.expires_in || 86399)) * 1000,
  };

  return tokenCache.token;
}

async function shopifyGraphQL(query, variables = {}) {
  const token = await getShopifyToken();
  const response = await fetch(
    `https://${env.SHOPIFY_SHOP_DOMAIN}/admin/api/${env.SHOPIFY_API_VERSION}/graphql.json`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": token,
      },
      body: JSON.stringify({ query, variables }),
    },
  );

  const payload = await response.json();
  if (!response.ok || payload?.errors?.length) {
    const message = payload?.errors?.map((e) => e.message).join(" | ") || `Shopify HTTP ${response.status}`;
    throw new Error(message);
  }
  return payload.data;
}

function buildShippingAddress(customer) {
  return {
    firstName: customer.firstName,
    lastName: customer.lastName,
    phone: customer.phone,
    address1: customer.address1,
    address2: customer.address2 || undefined,
    city: customer.city,
    provinceCode: customer.provinceCode,
    zip: customer.zip || undefined,
    countryCode: "EG",
  };
}

const SHIPPING_OPTIONS_QUERY = `
  query SunmiShipping($input: DraftOrderAvailableDeliveryOptionsInput!) {
    draftOrderAvailableDeliveryOptions(input: $input) {
      availableShippingRates {
        handle
        title
        code
        source
        price { amount currencyCode }
      }
      availableLocalDeliveryRates {
        handle
        title
        code
        source
        price { amount currencyCode }
      }
    }
  }
`;

const CALCULATE_DRAFT_MUTATION = `
  mutation SunmiCalculate($input: DraftOrderInput!) {
    draftOrderCalculate(input: $input) {
      calculatedDraftOrder {
        totalPriceSet { shopMoney { amount currencyCode } }
        subtotalPriceSet { shopMoney { amount currencyCode } }
        totalDiscountsSet { shopMoney { amount currencyCode } }
        totalTaxSet { shopMoney { amount currencyCode } }
        shippingLine {
          title
          shippingRateHandle
          originalPriceSet { shopMoney { amount currencyCode } }
        }
      }
      userErrors { field message }
    }
  }
`;

async function getShippingRates(order) {
  const input = {
    acceptAutomaticDiscounts: true,
    marketRegionCountryCode: "EG",
    lineItems: [{ variantId: order.variantGid, quantity: order.quantity }],
    shippingAddress: buildShippingAddress(order.customer),
  };

  const data = await shopifyGraphQL(SHIPPING_OPTIONS_QUERY, { input });
  const result = data?.draftOrderAvailableDeliveryOptions;
  const rates = [
    ...(result?.availableShippingRates || []).map((r) => ({ ...r, type: "shipping" })),
    ...(result?.availableLocalDeliveryRates || []).map((r) => ({ ...r, type: "local_delivery" })),
  ];
  return rates;
}

async function calculateDraft(order, selectedRate) {
  const input = {
    acceptAutomaticDiscounts: true,
    email: order.customer.email,
    phone: order.customer.phone,
    presentmentCurrencyCode: "EGP",
    lineItems: [{ variantId: order.variantGid, quantity: order.quantity }],
    shippingAddress: buildShippingAddress(order.customer),
  };

  if (selectedRate?.handle) {
    input.shippingLine = { shippingRateHandle: selectedRate.handle };
  }

  const data = await shopifyGraphQL(CALCULATE_DRAFT_MUTATION, { input });
  const result = data?.draftOrderCalculate;
  if (result?.userErrors?.length) {
    throw new Error(result.userErrors.map((e) => e.message).join(" | "));
  }
  if (!result?.calculatedDraftOrder) throw new Error("Shopify could not calculate the order.");
  return result.calculatedDraftOrder;
}

async function quoteOrder(order) {
  const rates = await getShippingRates(order);
  let selectedRate = null;

  if (rates.length) {
    selectedRate = rates.find((rate) => rate.handle === order.shippingHandle) || rates[0];
  }

  const calculated = await calculateDraft(order, selectedRate);

  return {
    rates,
    selectedRate,
    totals: {
      subtotal: calculated?.subtotalPriceSet?.shopMoney || null,
      discounts: calculated?.totalDiscountsSet?.shopMoney || null,
      tax: calculated?.totalTaxSet?.shopMoney || null,
      shipping: calculated?.shippingLine?.originalPriceSet?.shopMoney || {
        amount: "0.00",
        currencyCode: "EGP",
      },
      total: calculated?.totalPriceSet?.shopMoney || null,
    },
  };
}

const CREATE_DRAFT_MUTATION = `
  mutation SunmiDraftCreate($input: DraftOrderInput!) {
    draftOrderCreate(input: $input) {
      draftOrder {
        id
        name
        status
        totalPriceSet { shopMoney { amount currencyCode } }
        totalDiscountsSet { shopMoney { amount currencyCode } }
        shippingLine {
          title
          shippingRateHandle
          originalPriceSet { shopMoney { amount currencyCode } }
        }
      }
      userErrors { field message }
    }
  }
`;

async function createDraftOrder(order, selectedRate) {
  const reserveUntil = new Date(Date.now() + env.KASHIER_SESSION_MINUTES * 60_000).toISOString();

  const input = {
    acceptAutomaticDiscounts: true,
    email: order.customer.email,
    phone: order.customer.phone,
    presentmentCurrencyCode: "EGP",
    lineItems: [{ variantId: order.variantGid, quantity: order.quantity }],
    shippingAddress: buildShippingAddress(order.customer),
    reserveInventoryUntil: reserveUntil,
    visibleToCustomer: false,
    tags: [
      "SUNMI_ONE_PAGE",
      order.paymentMethod === "cod" ? "SUNMI_COD" : "SUNMI_KASHIER_PENDING",
    ],
    customAttributes: [
      { key: "order_source", value: "Sun-Mi one-page product checkout" },
      { key: "payment_preference", value: order.paymentMethod },
      { key: "language", value: order.language },
    ],
  };

  if (selectedRate?.handle) {
    input.shippingLine = { shippingRateHandle: selectedRate.handle };
  }

  const data = await shopifyGraphQL(CREATE_DRAFT_MUTATION, { input });
  const result = data?.draftOrderCreate;
  if (result?.userErrors?.length) {
    throw new Error(result.userErrors.map((e) => e.message).join(" | "));
  }
  if (!result?.draftOrder?.id) throw new Error("Shopify draft order was not created.");
  return result.draftOrder;
}

const DELETE_DRAFT_MUTATION = `
  mutation SunmiDraftDelete($input: DraftOrderDeleteInput!) {
    draftOrderDelete(input: $input) {
      deletedId
      userErrors { field message }
    }
  }
`;

async function deleteDraftOrder(id) {
  try {
    await shopifyGraphQL(DELETE_DRAFT_MUTATION, { input: { id } });
  } catch (error) {
    console.error("[Sun-Mi] Could not delete failed draft:", error.message);
  }
}

const COMPLETE_DRAFT_MUTATION = `
  mutation SunmiDraftComplete($id: ID!, $paymentPending: Boolean) {
    draftOrderComplete(id: $id, paymentPending: $paymentPending) {
      draftOrder {
        id
        order {
          id
          name
          displayFinancialStatus
        }
      }
      userErrors { field message }
    }
  }
`;

async function completeDraftOrder(id, paymentPending = false) {
  const data = await shopifyGraphQL(COMPLETE_DRAFT_MUTATION, { id, paymentPending });
  const result = data?.draftOrderComplete;
  if (result?.userErrors?.length) {
    throw new Error(result.userErrors.map((e) => e.message).join(" | "));
  }
  if (!result?.draftOrder?.order?.id) throw new Error("Shopify order was not completed.");
  return result.draftOrder.order;
}

function numericIdFromGid(gid) {
  return String(gid || "").split("/").pop().replace(/\D/g, "");
}

function draftGidFromOrderRef(ref) {
  const match = /^SUNMI-D(\d+)$/.exec(String(ref || ""));
  return match ? `gid://shopify/DraftOrder/${match[1]}` : null;
}

async function createKashierSession(draftOrder, order, amount) {
  const orderRef = `SUNMI-D${numericIdFromGid(draftOrder.id)}`;
  const expireAt = new Date(Date.now() + env.KASHIER_SESSION_MINUTES * 60_000).toISOString();
  const base = env.KASHIER_MODE === "live"
    ? "https://api.kashier.io"
    : "https://test-api.kashier.io";

  const merchantRedirect = `${env.PUBLIC_BASE_URL}/kashier/return?ref=${encodeURIComponent(orderRef)}`;
  const serverWebhook = `${env.PUBLIC_BASE_URL}/webhooks/kashier/${encodeURIComponent(env.KASHIER_WEBHOOK_TOKEN)}`;

  const payload = {
    expireAt,
    maxFailureAttempts: 3,
    paymentType: "credit",
    amount: String(amount),
    currency: "EGP",
    order: orderRef,
    merchantRedirect,
    display: order.language === "ar" ? "ar" : "en",
    type: "one-time",
    allowedMethods: env.KASHIER_ALLOWED_METHODS,
    redirectMethod: null,
    iframeBackgroundColor: "#FFFFFF",
    metaData: {
      shopifyDraftOrderId: draftOrder.id,
      source: "Sun-Mi Shopify one-page checkout",
    },
    merchantId: env.KASHIER_MERCHANT_ID,
    failureRedirect: false,
    brandColor: "#6A36BE",
    defaultMethod: "card",
    description: `Sun-Mi order ${orderRef}`,
    manualCapture: false,
    customer: {
      email: order.customer.email,
      reference: orderRef,
    },
    saveCard: "optional",
    retrieveSavedCard: true,
    interactionSource: "ECOMMERCE",
    enable3DS: true,
    serverWebhook,
    notes: `Shopify draft ${draftOrder.name || orderRef}`,
  };

  const response = await fetch(`${base}/v3/payment/sessions`, {
    method: "POST",
    headers: {
      Authorization: env.KASHIER_SECRET_KEY,
      "api-key": env.KASHIER_API_KEY,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(payload),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data?.sessionUrl || !data?._id) {
    const message =
      data?.message ||
      data?.error ||
      `Kashier session creation failed with HTTP ${response.status}`;
    throw new Error(message);
  }

  return {
    orderRef,
    sessionId: String(data._id),
    sessionUrl: String(data.sessionUrl),
    status: String(data.status || "CREATED"),
    returnOrigin: new URL(env.PUBLIC_BASE_URL).origin,
  };
}

const DRAFT_STATUS_QUERY = `
  query SunmiDraftStatus($id: ID!) {
    draftOrder(id: $id) {
      id
      name
      status
      order {
        id
        name
        displayFinancialStatus
      }
    }
  }
`;

async function getDraftStatus(ref) {
  const gid = draftGidFromOrderRef(ref);
  if (!gid) throw new Error("Invalid order reference.");
  const data = await shopifyGraphQL(DRAFT_STATUS_QUERY, { id: gid });
  const draft = data?.draftOrder;
  if (!draft) return { exists: false, completed: false };

  return {
    exists: true,
    completed: Boolean(draft.order?.id),
    draftStatus: draft.status,
    orderName: draft.order?.name || null,
    financialStatus: draft.order?.displayFinancialStatus || null,
  };
}

function redactSensitive(value) {
  if (Array.isArray(value)) return value.map(redactSensitive);
  if (!value || typeof value !== "object") return value;

  const output = {};
  for (const [key, val] of Object.entries(value)) {
    if (/(secret|api.?key|authorization|card|pan|cvv|cvc|token)/i.test(key)) {
      output[key] = "[REDACTED]";
    } else {
      output[key] = redactSensitive(val);
    }
  }
  return output;
}

app.get("/health", (_req, res) => {
  json(res, 200, {
    ok: true,
    service: "sunmi-payment-api",
    shopifyApiVersion: env.SHOPIFY_API_VERSION,
    kashierMode: env.KASHIER_MODE,
    webhookAutocomplete: env.KASHIER_WEBHOOK_AUTOCOMPLETE,
  });
});

app.post("/proxy/quote", requireProxy, async (req, res) => {
  try {
    const order = validateOrderBody(req.body);
    const quote = await quoteOrder(order);

    return json(res, 200, {
      success: true,
      shippingRates: quote.rates.map((rate) => ({
        handle: rate.handle,
        title: rate.title,
        type: rate.type,
        amount: rate.price?.amount || "0.00",
        currency: rate.price?.currencyCode || "EGP",
      })),
      selectedShippingHandle: quote.selectedRate?.handle || "",
      totals: quote.totals,
    });
  } catch (error) {
    console.error("[Sun-Mi quote]", error);
    return json(res, 422, { success: false, error: error.message || "Quote failed." });
  }
});

app.post("/proxy/create", requireProxy, async (req, res) => {
  let draft = null;

  try {
    const order = validateOrderBody(req.body);
    const quote = await quoteOrder(order);

    if (quote.rates.length && !order.shippingHandle) {
      order.shippingHandle = quote.selectedRate?.handle || "";
    }

    const selectedRate =
      quote.rates.find((rate) => rate.handle === order.shippingHandle) ||
      quote.selectedRate ||
      null;

    if (quote.rates.length && !selectedRate) {
      throw new Error("Please select a valid shipping method.");
    }

    draft = await createDraftOrder(order, selectedRate);

    if (order.paymentMethod === "cod") {
      const completed = await completeDraftOrder(draft.id, true);
      return json(res, 200, {
        success: true,
        mode: "cod",
        orderName: completed.name,
        financialStatus: completed.displayFinancialStatus,
      });
    }

    const amount = draft?.totalPriceSet?.shopMoney?.amount;
    const currency = draft?.totalPriceSet?.shopMoney?.currencyCode;

    if (!amount || currency !== "EGP") {
      throw new Error("Shopify returned an invalid order total.");
    }

    const session = await createKashierSession(draft, order, amount);

    return json(res, 200, {
      success: true,
      mode: "kashier",
      orderRef: session.orderRef,
      sessionId: session.sessionId,
      sessionUrl: session.sessionUrl,
      status: session.status,
      returnOrigin: session.returnOrigin,
      total: {
        amount,
        currency,
      },
    });
  } catch (error) {
    console.error("[Sun-Mi create]", error);

    if (draft?.id) {
      await deleteDraftOrder(draft.id);
    }

    return json(res, 422, {
      success: false,
      error: error.message || "Could not create order.",
    });
  }
});

app.get("/proxy/status", requireProxy, async (req, res) => {
  try {
    const ref = cleanText(req.query.ref, 100);
    const status = await getDraftStatus(ref);
    return json(res, 200, { success: true, ...status });
  } catch (error) {
    return json(res, 422, { success: false, error: error.message || "Status check failed." });
  }
});

app.get("/kashier/return", (req, res) => {
  const ref = cleanText(req.query.ref, 100);
  const targetOrigin = env.STORE_ORIGIN || "*";

  res.set("Cache-Control", "no-store");
  res.type("html").send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Payment verification</title>
  <style>
    body{font-family:Arial,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#fff;color:#21172f}
    .box{text-align:center;padding:28px}
    .spinner{width:34px;height:34px;border:4px solid #eee;border-top-color:#6a36be;border-radius:50%;margin:0 auto 16px;animation:s 1s linear infinite}
    @keyframes s{to{transform:rotate(360deg)}}
  </style>
</head>
<body>
  <div class="box"><div class="spinner"></div><strong>Verifying payment…</strong></div>
  <script>
    try {
      window.parent.postMessage(
        { type: "SUNMI_KASHIER_RETURN", ref: ${JSON.stringify(ref)} },
        ${JSON.stringify(targetOrigin)}
      );
    } catch (_) {}
  </script>
</body>
</html>`);
});

/**
 * SECURITY NOTE
 * -------------
 * This endpoint deliberately FAILS CLOSED.
 *
 * We already know the Kashier Payment Session create request/response from the
 * merchant dashboard, but the exact webhook payload + signature verification
 * contract has not yet been supplied. Until it is confirmed from Kashier's own
 * dashboard documentation, this route captures a redacted test payload only
 * and DOES NOT call draftOrderComplete().
 *
 * After one TEST payment, inspect Coolify logs for:
 *   [KASHIER_WEBHOOK_CAPTURE]
 * and use Kashier's webhook-signature docs to implement exact verification.
 */
app.post("/webhooks/kashier/:token", async (req, res) => {
  if (!env.KASHIER_WEBHOOK_TOKEN || req.params.token !== env.KASHIER_WEBHOOK_TOKEN) {
    return json(res, 404, { ok: false });
  }

  console.log(
    "[KASHIER_WEBHOOK_CAPTURE]",
    JSON.stringify(redactSensitive(req.body || {})),
  );

  if (env.KASHIER_WEBHOOK_AUTOCOMPLETE) {
    console.error(
      "[Sun-Mi] KASHIER_WEBHOOK_AUTOCOMPLETE=true is ignored until exact Kashier webhook verification is implemented.",
    );
  }

  return json(res, 200, { received: true });
});

app.use((_req, res) => json(res, 404, { success: false, error: "Not found." }));

app.listen(env.PORT, "0.0.0.0", () => {
  console.log(`[Sun-Mi] payment API listening on :${env.PORT}`);
  console.log(`[Sun-Mi] Shopify shop: ${env.SHOPIFY_SHOP_DOMAIN || "(missing)"}`);
  console.log(`[Sun-Mi] Kashier mode: ${env.KASHIER_MODE}`);
});

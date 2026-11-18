// MeshGuard outbound mail relay — Cloudflare Worker (P3-T05b-mail; owner decision 2026-11-18: Cloudflare Email Service
// through a paid Worker). The SMTP bridge `meshguard-worker mailrelay` (internal/mailrelay) posts every message here; the
// Worker sends it through the `send_email` binding EMAIL (restricted by allowed_sender_addresses — wrangler.toml, rendered
// by tools/render_mail.py from the environment file: no domain in this repository).
//
// Contract — the only endpoint: POST /v1/send (anything else ⇒ 404)
//   headers  Content-Type: application/json
//            X-MG-Timestamp: Unix seconds (decimal)
//            X-MG-Signature: hex(HMAC-SHA256(RELAY_HMAC_KEY, timestamp + "\n" + hex(sha256(body))))
//   body     {"from": "<allowed sender>", "to": ["<address>", … at most 10], "raw_b64": "<RFC 5322 message, ≤ 1 MiB>"}
//   answer   JSON {"ok", "code", …}; per recipient {"status": "sent"|"failed", "id"?, "error"?, "retryable"?} — never an
//            address, a header or a byte of the message
//     200 sent | partial (≥ 1 recipient sent) | duplicate (this exact body was already sent by this isolate: not resent)
//     401 auth_missing | auth_timestamp (outside ±300 s) | auth_signature        400 bad_request | bad_message
//     403 sender_not_allowed     404 not_found     409 in_progress     413 too_large     415 bad_content_type
//     422 bad_recipient | too_many_recipients | send_failed (every failure permanent)
//     429 / 503 send_failed (nothing sent, a retry may succeed)     500 not_configured | internal
//
// Security: constant-time HMAC check (crypto.subtle.verify) before the body is parsed; the timestamp window bounds
// replays to ±300 s, and inside it a body already sent by this isolate is answered `duplicate` without sending again
// (a retry of the bridge after a lost answer, or a replay, never sends twice there), a body being sent is answered 409.
// The caches live in one isolate (best effort): the window and HTTPS bound the rest — a replay can only resend the same
// message to the same recipients. Logs: one JSON line per request with counts and codes only.
//
// One EmailMessage per recipient, raw: the bridge relays real RFC 5322 messages (MIME parts, encodings, Message-ID of the
// outbox row) that must arrive unchanged, and Bcc recipients exist only in the envelope — rebuilding them with the
// structured builder would need a MIME parser (a dependency) and lose fidelity. Email Service still requires From and
// Message-ID in the raw message (E_FIELD_MISSING): the bridge guarantees both.
import { EmailMessage } from "cloudflare:email";

export const SEND_PATH = "/v1/send";
export const MAX_RECIPIENTS = 10;
export const MAX_RAW_BYTES = 1024 * 1024;
export const MAX_BODY_BYTES = Math.ceil(MAX_RAW_BYTES / 3) * 4 + 64 * 1024; // base64 of the raw message + JSON envelope
export const SKEW_SECONDS = 300;
const MIN_KEY_BYTES = 32;
const CACHE_LIMIT = 10000;

// Email Service error codes no retry can fix (developers.cloudflare.com/email-service/api/send-emails/workers-api/).
const PERMANENT = new Set([
  "E_VALIDATION_ERROR", "E_FIELD_MISSING", "E_TOO_MANY_RECIPIENTS", "E_TOO_MANY_ATTACHMENTS", "E_SENDER_NOT_VERIFIED",
  "E_SENDER_DOMAIN_NOT_AVAILABLE", "E_SENDER_DOMAIN_NOT_CONFIGURED", "E_RECIPIENT_NOT_ALLOWED",
  "E_RECIPIENT_PLAN_RESTRICTED", "E_RECIPIENT_SUPPRESSED", "E_ACCOUNT_SUSPENDED", "E_CONTENT_TOO_LARGE",
  "E_DELIVERY_FAILED", "E_HEADER_NOT_ALLOWED", "E_HEADER_USE_API_FIELD", "E_HEADER_VALUE_INVALID",
  "E_HEADER_VALUE_TOO_LONG", "E_HEADER_NAME_INVALID", "E_HEADERS_TOO_LARGE", "E_HEADERS_TOO_MANY",
]);
const RATE = new Set(["E_RATE_LIMIT_EXCEEDED", "E_DAILY_LIMIT_EXCEEDED"]);
const CODE_RE = /^E_[A-Z_]{1,40}$/;
const ADDRESS_RE = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

const sent = new Map(); // body digest → expiry (ms): bodies already sent by this isolate
const inflight = new Set(); // body digests being sent

export function resetCaches() {
  sent.clear();
  inflight.clear();
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch {
      log({ code: "internal" });
      return reply(500, { ok: false, code: "internal" });
    }
  },
};

async function handle(request, env) {
  const url = new URL(request.url);
  if (request.method !== "POST" || url.pathname !== SEND_PATH) {
    return reply(404, { ok: false, code: "not_found" });
  }
  const secret = typeof env.RELAY_HMAC_KEY === "string" ? env.RELAY_HMAC_KEY.trim() : "";
  const allowed = String(env.RELAY_ALLOWED_FROM || "").split(",").map((a) => a.trim().toLowerCase()).filter(Boolean);
  if (new TextEncoder().encode(secret).length < MIN_KEY_BYTES || allowed.length === 0 || !env.EMAIL) {
    log({ code: "not_configured" });
    return reply(500, { ok: false, code: "not_configured" });
  }
  const ts = request.headers.get("X-MG-Timestamp") || "";
  const sig = (request.headers.get("X-MG-Signature") || "").toLowerCase();
  if (!/^\d{1,12}$/.test(ts) || !/^[0-9a-f]{64}$/.test(sig)) {
    return reject(401, "auth_missing");
  }
  if (Math.abs(Math.floor(Date.now() / 1000) - Number(ts)) > SKEW_SECONDS) {
    return reject(401, "auth_timestamp");
  }
  const declared = Number(request.headers.get("Content-Length") || "0");
  if (declared > MAX_BODY_BYTES) {
    return reject(413, "too_large");
  }
  const body = await readLimited(request, MAX_BODY_BYTES);
  if (body === null) {
    return reject(413, "too_large");
  }
  const digest = hex(await crypto.subtle.digest("SHA-256", body));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" },
    false, ["verify"]);
  const ok = await crypto.subtle.verify("HMAC", key, unhex(sig), new TextEncoder().encode(`${ts}\n${digest}`));
  if (!ok) {
    return reject(401, "auth_signature");
  }
  // authenticated from here on
  if (!(request.headers.get("Content-Type") || "").toLowerCase().startsWith("application/json")) {
    return reject(415, "bad_content_type");
  }
  let msg;
  try {
    msg = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    return reject(400, "bad_request");
  }
  if (!msg || typeof msg !== "object" || Array.isArray(msg) || typeof msg.from !== "string" || !Array.isArray(msg.to) ||
      typeof msg.raw_b64 !== "string" || Object.keys(msg).some((k) => !["from", "to", "raw_b64"].includes(k))) {
    return reject(400, "bad_request");
  }
  const from = msg.from.trim().toLowerCase();
  if (!allowed.includes(from)) {
    return reject(403, "sender_not_allowed");
  }
  if (msg.to.length === 0 || msg.to.length > MAX_RECIPIENTS) {
    return reject(422, "too_many_recipients", { rcpt: msg.to.length });
  }
  const to = [];
  for (const r of msg.to) {
    if (typeof r !== "string" || r.length > 254 || !ADDRESS_RE.test(r) || r.startsWith(".") || r.includes("..") ||
        r.includes(".@")) {
      return reject(422, "bad_recipient", { rcpt: msg.to.length });
    }
    if (!to.includes(r.toLowerCase())) to.push(r.toLowerCase());
  }
  let raw;
  try {
    const bin = atob(msg.raw_b64);
    if (bin.length === 0) throw new Error("empty");
    if (bin.length > MAX_RAW_BYTES) {
      return reject(413, "too_large", { rcpt: to.length });
    }
    raw = new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
  } catch {
    return reject(400, "bad_message", { rcpt: to.length });
  }

  purge(Date.now());
  if (sent.has(digest)) {
    log({ code: "duplicate", rcpt: to.length });
    return reply(200, { ok: true, code: "duplicate", sent: 0, failed: 0, results: [] });
  }
  if (inflight.has(digest)) {
    return reject(409, "in_progress", { rcpt: to.length });
  }
  inflight.add(digest);
  const results = [];
  try {
    for (const r of to) {
      try {
        const res = await env.EMAIL.send(new EmailMessage(from, r, raw));
        const id = res && typeof res.messageId === "string" ? res.messageId.slice(0, 200) : undefined;
        results.push(id ? { status: "sent", id } : { status: "sent" });
      } catch (e) {
        const code = e && typeof e.code === "string" && CODE_RE.test(e.code) ? e.code
          : e instanceof TypeError ? "E_TYPE" : "E_UNKNOWN";
        results.push({ status: "failed", error: code, retryable: !PERMANENT.has(code) && code !== "E_TYPE" });
      }
    }
  } finally {
    inflight.delete(digest);
  }
  const nSent = results.filter((x) => x.status === "sent").length;
  const failed = results.filter((x) => x.status === "failed");
  const errors = [...new Set(failed.map((x) => x.error))];
  if (nSent > 0) {
    sent.set(digest, Date.now() + 2 * SKEW_SECONDS * 1000);
  }
  let status = 200;
  let code = failed.length === 0 ? "sent" : "partial";
  let retryable = false;
  if (nSent === 0) {
    code = "send_failed";
    retryable = failed.some((x) => x.retryable);
    status = !retryable ? 422 : failed.every((x) => RATE.has(x.error)) ? 429 : 503;
  }
  log({ code, rcpt: to.length, sent: nSent, failed: failed.length, errors, bytes: raw.length });
  return reply(status, { ok: nSent > 0, code, sent: nSent, failed: failed.length, retryable, results });
}

// readLimited reads the body, or returns null as soon as it exceeds limit (a missing or false Content-Length included).
async function readLimited(request, limit) {
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.length;
    if (n > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(n);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

function reject(status, code, extra = {}) {
  log({ code, ...extra });
  return reply(status, { ok: false, code });
}

function reply(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" },
  });
}

// One line per request: counts and codes only — never an address, a header, the message or a key.
function log(fields) {
  console.log(JSON.stringify({ event: "mailrelay", ...fields }));
}

function purge(now) {
  for (const [k, exp] of sent) {
    if (exp > now && sent.size <= CACHE_LIMIT) break; // insertion order ≈ expiry order
    sent.delete(k);
  }
}

function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function unhex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

// Tests of the Worker without Cloudflare: node's built-in runner, a fake EMAIL binding and a fake `cloudflare:email`
// (register.mjs). Run: npm test (= node --test test/), in the pinned node image of versions.lock in CI.
import "./register.mjs";
import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";

const { default: worker, resetCaches, MAX_RAW_BYTES, MAX_BODY_BYTES, SKEW_SECONDS } = await import("../src/index.js");
const { EmailMessage } = await import("cloudflare:email");

// keys built from a repeated word: no credential-like literal for the secret scan (gitleaks)
const KEY = "relay-test-".repeat(4);
const OTHER = "other-test-".repeat(4);
const FROM = "no-reply@example.com";
const RAW = "From: MeshGuard <no-reply@example.com>\r\nTo: a@example.org\r\nSubject: =?utf-8?q?Ch=C3=ADnh_s=C3=A1ch?=\r\n" +
  "Message-ID: <0190@example.com>\r\nMIME-Version: 1.0\r\n\r\nconfidential body\r\n";
const b64 = (s) => Buffer.from(s, "utf8").toString("base64");
const msg = (over = {}) => ({ from: FROM, to: ["a@example.org"], raw_b64: b64(RAW), ...over });

let logs = [];
const realLog = console.log;
test.beforeEach(() => {
  resetCaches();
  logs = [];
  console.log = (...a) => logs.push(a.join(" "));
});
test.afterEach(() => {
  console.log = realLog;
});

function fakeEmail(script = []) {
  const sent = [];
  return {
    sent,
    async send(m) {
      assert.ok(m instanceof EmailMessage, "the Worker passes an EmailMessage");
      const step = script.shift();
      if (typeof step === "function") await step();
      else if (step instanceof Error) throw step;
      else if (step) throw Object.assign(new Error(`failure for ${m.to}`), { code: step });
      sent.push(m);
      return { messageId: `cf-${sent.length}` };
    },
  };
}

const env = (email = fakeEmail(), extra = {}) => ({ RELAY_HMAC_KEY: KEY, RELAY_ALLOWED_FROM: FROM, EMAIL: email, ...extra });

function request(payload, o = {}) {
  const body = typeof payload === "string" ? payload : JSON.stringify(payload);
  const ts = String(o.ts ?? Math.floor(Date.now() / 1000));
  const digest = createHash("sha256").update(o.signedBody ?? body).digest("hex");
  const sig = createHmac("sha256", o.key ?? KEY).update(`${ts}\n${digest}`).digest("hex");
  const headers = { "Content-Type": o.ctype ?? "application/json", "X-MG-Timestamp": o.tsHeader ?? ts, "X-MG-Signature": o.sigHeader ?? sig };
  const method = o.method ?? "POST";
  return new Request(o.url ?? "https://relay.example.workers.dev/v1/send",
    { method, headers, body: method === "GET" || method === "HEAD" ? undefined : body });
}

async function call(req, e = env()) {
  const res = await worker.fetch(req, e);
  const text = await res.text();
  return { status: res.status, text, body: text ? JSON.parse(text) : null, headers: res.headers };
}

test("only POST /v1/send exists", async () => {
  for (const [method, url] of [["GET", "https://w/v1/send"], ["HEAD", "https://w/v1/send"], ["PUT", "https://w/v1/send"],
    ["POST", "https://w/v1/sendx"], ["POST", "https://w/"], ["POST", "https://w/v2/send"]]) {
    const r = await call(request(msg(), { method, url }));
    assert.equal(r.status, 404, `${method} ${url}`);
    if (method !== "HEAD") assert.equal(r.body.code, "not_found");
  }
});

test("one raw EmailMessage per recipient, message unchanged, nothing echoed", async () => {
  const email = fakeEmail();
  const r = await call(request(msg({ to: ["a@example.org", "B@Example.org", "a@example.org"] })), env(email));
  assert.equal(r.status, 200);
  assert.deepEqual({ ...r.body, results: undefined }, { ok: true, code: "sent", sent: 2, failed: 0, retryable: false, results: undefined });
  assert.deepEqual(r.body.results, [{ status: "sent", id: "cf-1" }, { status: "sent", id: "cf-2" }]);
  assert.deepEqual(email.sent.map((m) => [m.from, m.to, m.raw]), [[FROM, "a@example.org", RAW], [FROM, "b@example.org", RAW]]);
  assert.equal(r.headers.get("Cache-Control"), "no-store");
  for (const leak of ["@", "Subject", "confidential", KEY]) assert.ok(!r.text.includes(leak), `answer holds ${leak}`);
});

test("HMAC, timestamp window, constant-time check before parsing", async () => {
  const now = Math.floor(Date.now() / 1000);
  const cases = [
    [{ tsHeader: "" }, "auth_missing"],
    [{ sigHeader: "abc" }, "auth_missing"],
    [{ tsHeader: "12a" }, "auth_missing"],
    [{ key: OTHER }, "auth_signature"],
    [{ signedBody: "{}" }, "auth_signature"], // signature of another body
    [{ ts: now - SKEW_SECONDS - 2 }, "auth_timestamp"],
    [{ ts: now + SKEW_SECONDS + 2 }, "auth_timestamp"],
  ];
  const email = fakeEmail();
  for (const [o, code] of cases) {
    const r = await call(request(msg(), o), env(email));
    assert.equal(r.status, 401, JSON.stringify(o));
    assert.equal(r.body.code, code, JSON.stringify(o));
  }
  // garbage body with a wrong signature: refused as unauthenticated, never parsed
  const r = await call(request("not json", { key: OTHER }), env(email));
  assert.equal(r.body.code, "auth_signature");
  assert.equal(email.sent.length, 0);
  const ok = await call(request(msg(), { ts: now - SKEW_SECONDS + 5 }), env(email));
  assert.equal(ok.status, 200, "inside the window");
});

test("missing configuration fails closed", async () => {
  for (const e of [env(fakeEmail(), { RELAY_HMAC_KEY: "short" }), env(fakeEmail(), { RELAY_ALLOWED_FROM: "" }),
    env(null), env(fakeEmail(), { RELAY_HMAC_KEY: undefined })]) {
    const r = await call(request(msg()), e);
    assert.equal(r.status, 500);
    assert.equal(r.body.code, "not_configured");
  }
});

test("body validation", async () => {
  const email = fakeEmail();
  const cases = [
    [request("{not json"), 400, "bad_request"],
    [request(msg({ extra: 1 })), 400, "bad_request"],
    [request(JSON.stringify([1])), 400, "bad_request"],
    [request(msg({ to: "a@example.org" })), 400, "bad_request"],
    [request(msg({ from: "Other@Example.com" })), 403, "sender_not_allowed"],
    [request(msg({ to: [] })), 422, "too_many_recipients"],
    [request(msg({ to: Array.from({ length: 11 }, (_, i) => `r${i}@example.org`) })), 422, "too_many_recipients"],
    [request(msg({ to: ["a@example.org\r\nBcc: x@example.net"] })), 422, "bad_recipient"],
    [request(msg({ to: ["<a@example.org>"] })), 422, "bad_recipient"],
    [request(msg({ to: ["a@localhost"] })), 422, "bad_recipient"],
    [request(msg({ to: [42] })), 422, "bad_recipient"],
    [request(msg({ raw_b64: "%%%" })), 400, "bad_message"],
    [request(msg({ raw_b64: "" })), 400, "bad_message"],
    [request(msg({ raw_b64: Buffer.from([0xff, 0xfe, 0x41]).toString("base64") })), 400, "bad_message"], // not UTF-8
    [request(msg({ raw_b64: b64("x".repeat(MAX_RAW_BYTES + 1)) })), 413, "too_large"],
    [request(msg(), { ctype: "text/plain" }), 415, "bad_content_type"],
  ];
  for (const [req, status, code] of cases) {
    const r = await call(req, env(email));
    assert.equal(r.status, status, code);
    assert.equal(r.body.code, code);
  }
  const huge = JSON.stringify(msg({ raw_b64: "A".repeat(MAX_BODY_BYTES) }));
  const r = await call(request(huge), env(email));
  assert.equal(r.status, 413);
  assert.equal(email.sent.length, 0);
  const max = await call(request(msg({ raw_b64: b64(RAW + "x".repeat(MAX_RAW_BYTES - RAW.length)) })), env(email));
  assert.equal(max.status, 200, "exactly 1 MiB is accepted");
});

test("Email Service errors become stable answers", async () => {
  const cases = [
    [["E_RATE_LIMIT_EXCEEDED"], 429, "send_failed", true],
    [["E_DAILY_LIMIT_EXCEEDED", "E_RATE_LIMIT_EXCEEDED"], 429, "send_failed", true],
    [["E_RECIPIENT_SUPPRESSED"], 422, "send_failed", false],
    [["E_SENDER_NOT_VERIFIED"], 422, "send_failed", false],
    [["E_INTERNAL_SERVER_ERROR"], 503, "send_failed", true],
    [[new Error("no code")], 503, "send_failed", true],
    [[new TypeError("bad argument")], 422, "send_failed", false],
    [["E_RECIPIENT_SUPPRESSED", "E_RATE_LIMIT_EXCEEDED"], 503, "send_failed", true],
    [[null, "E_RECIPIENT_SUPPRESSED"], 200, "partial", false],
  ];
  for (const [script, status, code, retryable] of cases) {
    resetCaches();
    const to = script.length === 1 ? ["a@example.org"] : ["a@example.org", "b@example.org"];
    const r = await call(request(msg({ to })), env(fakeEmail([...script])));
    assert.equal(r.status, status, String(script));
    assert.equal(r.body.code, code);
    assert.equal(r.body.retryable, retryable, String(script));
    assert.ok(!r.text.includes("failure for"), "the error message (with an address) is never echoed");
  }
});

test("a body already sent is not sent again; a failed one is; one in progress is 409", async () => {
  const email = fakeEmail();
  const body = JSON.stringify(msg());
  const now = Math.floor(Date.now() / 1000);
  assert.equal((await call(request(body, { ts: now - 1 }), env(email))).body.code, "sent");
  const again = await call(request(body, { ts: now }), env(email)); // the bridge's retry: new signature, same body
  assert.equal(again.status, 200);
  assert.equal(again.body.code, "duplicate");
  const replay = await call(request(body, { ts: now - 1 }), env(email)); // exact replay of the first request
  assert.equal(replay.body.code, "duplicate");
  assert.equal(email.sent.length, 1);

  const failing = fakeEmail(["E_INTERNAL_SERVER_ERROR"]);
  const body2 = JSON.stringify(msg({ to: ["c@example.org"] }));
  assert.equal((await call(request(body2), env(failing))).status, 503);
  assert.equal((await call(request(body2), env(failing))).body.code, "sent", "a failed body is sent on retry");

  let release;
  const gate = new Promise((r) => { release = r; });
  const slow = fakeEmail([() => gate]);
  const body3 = JSON.stringify(msg({ to: ["d@example.org"] }));
  const first = call(request(body3), env(slow));
  await new Promise((r) => setTimeout(r, 20));
  const second = await call(request(body3), env(slow));
  assert.equal(second.status, 409);
  assert.equal(second.body.code, "in_progress");
  release();
  assert.equal((await first).body.code, "sent");
  assert.equal(slow.sent.length, 1);
});

test("logs hold counts and codes only", async () => {
  await call(request(msg({ to: ["secret.person@example.org", "b@example.org"] })), env(fakeEmail([null, "E_RECIPIENT_SUPPRESSED"])));
  await call(request(msg(), { key: OTHER }));
  await call(request(msg({ from: "intruder@example.net" })));
  assert.equal(logs.length, 3);
  const all = logs.join("\n");
  for (const leak of ["@", "secret.person", "Subject", "confidential", KEY, OTHER]) {
    assert.ok(!all.includes(leak), `log holds ${leak}: ${all}`);
  }
  assert.deepEqual(JSON.parse(logs[0]), { event: "mailrelay", code: "partial", rcpt: 2, sent: 1, failed: 1,
    errors: ["E_RECIPIENT_SUPPRESSED"], bytes: RAW.length });
  assert.equal(JSON.parse(logs[1]).code, "auth_signature");
  assert.equal(JSON.parse(logs[2]).code, "sender_not_allowed");
});

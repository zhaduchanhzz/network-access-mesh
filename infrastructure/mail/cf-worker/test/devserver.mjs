// Local server of the Worker without Cloudflare — the fake Worker of the dev/CI stack (service `fakeworker` of
// compose.yaml, cases E2E-82/83) and a local try-out: the real src/index.js behind node:http, with a fake EMAIL binding
// that records what Email Service would have been asked to send. Never deployed.
//
//   RELAY_HMAC_KEY_FILE   file holding the shared key (read at every request)
//   RELAY_ALLOWED_FROM    sender addresses, comma-separated (the binding's allowed_sender_addresses)
//   DEVSERVER_PORT        default 8787
//   DEVSERVER_OUT         directory of the records (default /tmp/mailrelay-devserver):
//     requests.jsonl  one line per request: method, path, status, code, the signed headers and sha256 of the body (so a
//                     test can verify the HMAC with its own copy of the key) — never the body
//     sent.jsonl      one line per EmailMessage: from, to, size, sha256 and the From/To/Subject/Message-ID headers —
//                     never the body (a Keycloak action e-mail holds a link with a token)
import "./register.mjs";
import { createHash } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

const { default: worker } = await import("../src/index.js");

const out = process.env.DEVSERVER_OUT || "/tmp/mailrelay-devserver";
const port = Number(process.env.DEVSERVER_PORT || 8787);
fs.mkdirSync(out, { recursive: true });
const append = (file, obj) => fs.appendFileSync(path.join(out, file), `${JSON.stringify(obj)}\n`);
const sha = (b) => createHash("sha256").update(b).digest("hex");

function header(raw, name) {
  const head = raw.split("\r\n\r\n", 1)[0];
  const m = head.match(new RegExp(`^${name}:[ \\t]*(.*(?:\\r\\n[ \\t].*)*)`, "im"));
  return m ? m[1].replace(/\r\n[ \t]+/g, " ") : null;
}

const EMAIL = {
  async send(m) {
    const id = `dev-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
    append("sent.jsonl", { id, from: m.from, to: m.to, bytes: m.raw.length, sha256: sha(m.raw),
      header_from: header(m.raw, "From"), header_to: header(m.raw, "To"), subject: header(m.raw, "Subject"),
      message_id: header(m.raw, "Message-ID") });
    return { messageId: id };
  },
};

function env() {
  let key = "";
  try {
    key = fs.readFileSync(process.env.RELAY_HMAC_KEY_FILE || "", "utf8");
  } catch {
    key = "";
  }
  return { RELAY_HMAC_KEY: key, RELAY_ALLOWED_FROM: process.env.RELAY_ALLOWED_FROM || "", EMAIL };
}

const PASS = ["content-type", "content-length", "x-mg-timestamp", "x-mg-signature"];

http.createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = Buffer.concat(chunks);
  const headers = new Headers();
  for (const h of PASS) if (typeof req.headers[h] === "string") headers.set(h, req.headers[h]);
  const request = new Request(`http://${req.headers.host || "localhost"}${req.url}`, { method: req.method, headers,
    body: req.method === "GET" || req.method === "HEAD" ? undefined : body });
  const response = await worker.fetch(request, env());
  const text = await response.text();
  let code = "";
  try {
    code = JSON.parse(text).code || "";
  } catch {
    code = "";
  }
  append("requests.jsonl", { at: new Date().toISOString(), method: req.method, path: req.url, status: response.status, code,
    ts: req.headers["x-mg-timestamp"] || "", sig: req.headers["x-mg-signature"] || "", body_sha256: sha(body) });
  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(text);
}).listen(port, "0.0.0.0", () => console.log(JSON.stringify({ event: "devserver", port, out })));

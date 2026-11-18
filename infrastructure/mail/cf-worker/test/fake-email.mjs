// Stand-in for `cloudflare:email` outside Cloudflare (register.mjs): the legacy raw-message constructor of Email Service,
// new EmailMessage(from, to, raw) — one sender, one recipient, the RFC 5322 message as a string.
export class EmailMessage {
  constructor(from, to, raw) {
    this.from = from;
    this.to = to;
    this.raw = raw;
  }
}

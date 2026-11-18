// Package mailrelay is the SMTP bridge of the outbound e-mail relay (P3-T05b-mail, owner decision 2026-11-18: Cloudflare
// Email Service through a Worker). It runs as `meshguard-worker mailrelay`, its own container from the worker image,
// listening only on the internal network `mail` (worker notifications, Keycloak, Alertmanager — SMTP mailrelay:587):
//
//	client ──SMTP + STARTTLS (internal CA)──▶ mailrelay ──HTTPS POST /v1/send, HMAC-SHA256──▶ Worker ──▶ Email Service
//
// The SMTP side is a minimal RFC 5321 server: EHLO/HELO, STARTTLS (required before MAIL once a certificate is
// configured — plain text only on the dev/CI stack), MAIL FROM limited to the configured sender addresses, RCPT TO (at
// most MaxRecipients), DATA (at most MaxMessageBytes, dot-unstuffed, bare LF normalised to CRLF), RSET, NOOP, QUIT. No
// AUTH: the network is internal and the sender is fixed; the From header must be an allowed sender too, and a missing
// Message-ID (required by Email Service for raw messages) is added.
//
// The message is relayed synchronously: the answer to DATA is the Worker's answer — 250 when it was sent, 4xx when a
// retry may succeed (Worker 5xx/429, network, timeout, wrong HMAC key or URL — a configuration fault the operator
// fixes), 5xx when it cannot (rejected sender, recipient, content). The SMTP clients keep their own retry logic (the
// notification.send job, Alertmanager); nothing is queued here. Forwarding is bounded: a few attempts with backoff,
// within a budget below the clients' own timeouts.
//
// The request to the Worker: JSON {from, to, raw_b64}, headers X-MG-Timestamp (Unix seconds) and X-MG-Signature =
// hex(HMAC-SHA256(key, timestamp + "\n" + hex(sha256(body)))); the key is a file secret read at every message (rotation
// without restart). Logs and metrics (meshguard_mailrelay_*) hold counts, codes and masked addresses — never a body,
// subject, key or full address.
//
// The package imports no other module (§13.6): apps/worker wires it from internal/config.
package mailrelay

package main

// `meshguard-worker admin mail-test --to <address>` — one test e-mail through the worker's own relay configuration
// (MG_SMTP_*: mailrelay:587, STARTTLS with the internal CA — P3-T05b-mail), with the very client of notification.send:
// worker → mailrelay → Cloudflare Worker → Cloudflare Email Service → the address. For the coordinator after deploying the
// relay and the Worker (the address is chosen by the owner):
//
//	docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin mail-test --to <address>
//
// Output: one JSON line — the address masked, the Message-ID, result sent | temporary | permanent and, when it failed,
// the relay's SMTP answer (a code and a stable reason, never a secret). Exit status: 0 sent (accepted by the Worker);
// 1 refused or failed; 2 usage or configuration error (no relay configured).

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/apps/internal/runner"
	"github.com/zhaduchanhzz/network-access-mesh/internal/config"
	"github.com/zhaduchanhzz/network-access-mesh/internal/kit/logx"
	"github.com/zhaduchanhzz/network-access-mesh/internal/mailrelay"
	"github.com/zhaduchanhzz/network-access-mesh/internal/notifications"
)

const mailTestUsage = `usage: meshguard-worker admin mail-test --to <address>
  runs inside the worker container: docker compose -p mg-app exec -T worker /usr/local/bin/meshguard admin mail-test --to …
  one test e-mail through MG_SMTP_* (the outbound relay of P3-T05b-mail)
`

// mailSender is what the command needs from the SMTP client (notifications.SMTPMailer; replaced in tests).
type mailSender interface {
	Send(ctx context.Context, m notifications.Message) error
}

type mailTestEnv struct {
	getenv  func(string) string
	environ []string
	open    func(config.SMTP) (mailSender, error)
}

func openMailer(c config.SMTP) (mailSender, error) { return runner.NewSMTPMailer(c) }

type mailTestOutput struct {
	To        string `json:"to"`
	MessageID string `json:"message_id"`
	Result    string `json:"result"`
	Error     string `json:"error,omitempty"`
}

func mailTest(ctx context.Context, args []string, stdout, stderr io.Writer, env mailTestEnv) int {
	fset := flag.NewFlagSet("mail-test", flag.ContinueOnError)
	fset.SetOutput(io.Discard) // flag errors may quote a value
	to := fset.String("to", "", "")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 || !mailrelay.ValidAddress(*to) {
		_, _ = io.WriteString(stderr, "meshguard-worker admin mail-test: --to <address> (plain ASCII local@domain) is required\n"+
			mailTestUsage)
		return 2
	}
	cfg, err := config.Load("worker", env.getenv, env.environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin mail-test: invalid configuration:\n%v\n", err)
		return 2
	}
	if cfg.SMTP.Addr == "" {
		_, _ = io.WriteString(stderr, "meshguard-worker admin mail-test: no relay configured (MG_SMTP_ADDR — MG_MAILRELAY_URL of the environment)\n")
		return 2
	}
	m, err := env.open(cfg.SMTP)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "meshguard-worker admin mail-test: %s\n", logx.RedactString(err.Error()))
		return 2
	}
	domain := "meshguard.invalid"
	if a, err := mail.ParseAddress(cfg.SMTP.From); err == nil { // checked by config.Load
		_, domain, _ = strings.Cut(a.Address, "@")
	}
	now := time.Now().UTC()
	out := mailTestOutput{To: mailrelay.Mask(strings.ToLower(*to)), MessageID: "<mail-test-" + uuid.NewString() + "@" + domain + ">",
		Result: "sent"}
	msg := notifications.Message{To: *to, MessageID: out.MessageID,
		Subject: "[MeshGuard] Thư thử của relay thư ra / Outbound mail relay test",
		Body: "Thư thử gửi bằng `meshguard-worker admin mail-test` lúc " + now.Format(time.RFC3339) + ".\n" +
			"Đường đi: worker → mailrelay (SMTP, STARTTLS) → Worker Cloudflare (HMAC) → Cloudflare Email Service.\n\n" +
			"Test message sent by `meshguard-worker admin mail-test` at " + now.Format(time.RFC3339) + ".\n" +
			"MeshGuard never asks for a password, a code or a key by e-mail.\n"}
	sctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	code := 0
	if err := m.Send(sctx, msg); err != nil {
		out.Result, out.Error, code = "temporary", logx.RedactString(err.Error()), 1
		if notifications.IsPermanent(err) {
			out.Result = "permanent"
		}
	}
	_ = json.NewEncoder(stdout).Encode(out)
	return code
}

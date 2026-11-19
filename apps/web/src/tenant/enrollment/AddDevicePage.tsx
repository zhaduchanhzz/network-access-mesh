// Thêm thiết bị (P4-T08, §7.4 luồng A bước 2–6, §12.3 "Device Enrollment"): wizard theo hệ điều hành —
//   1. chọn OS ⇒ hướng dẫn từ GET /enrollment/instructions (đúng `login_server` của tenant; Windows kèm MSI/LoginURL);
//   2. chọn phương thức: web-auth (mặc định cho thiết bị cá nhân có trình duyệt — không key nào để sao chép) hoặc pre-auth
//      key một lần (server, container, CI, di động — mobile không đặt được hostname ⇒ chỉ key);
//   3. POST /enrollment/requests (Idempotency-Key): `issued` ⇒ lệnh `tailscale up … --hostname mg-<mã>` (web-auth, theo dõi
//      trạng thái tới `verified`) hoặc key hiển thị MỘT lần; `pending_approval` (tenant bật duyệt, người gọi không có quyền
//      duyệt) ⇒ chờ duyệt rồi `/start` từ danh sách "Yêu cầu của bạn".
// Ô "dán link hoặc Auth ID" là phương án lùi của trang claim (P4-T07 §4) — cùng API claim, cùng cảnh báo.
// End User chỉ thấy/thao tác yêu cầu của mình (server lọc — ô ○ của §8.6); tenant suspended ⇒ mọi nút ghi khóa.
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { ApiError } from "../../api/problem";
import { can } from "../../auth/permissions";
import { Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { EmptyState, QueryBlock } from "../../ui/Data";
import { StatusBadge, useCodeText } from "../../ui/Status";
import { useTenant } from "../TenantScope";
import { createRequest, useEnrollmentList, useEnrollmentRequest, useIssueMutation, useMemberNames, type NewRequestBody } from "./api";
import { ClaimPanel } from "./ClaimPanel";
import { KeyRevealDialog, WebAuthCommand } from "./Credential";
import { InstructionsPanel, useInstructions } from "./Instructions";
import {
  DEVICE_LABEL_RE,
  ENROLL_OS,
  extractAuthId,
  guessOS,
  isMine,
  MOBILE_OS,
  TTL_MAX,
  type EnrollmentCredential,
  type EnrollmentIssue,
  type EnrollmentOS,
  type EnrollmentRequest,
} from "./model";
import { RequestTable } from "./RequestTable";

type Method = "web_auth" | "preauth_key";

export function AddDevicePage() {
  const { t } = useTranslation();
  const { tenantId, role, readOnly } = useTenant();
  const canRequest = can(role, "tenant.enrollment:request");
  // credential một lần: lệnh web-auth giữ tới khi yêu cầu rời `issued`; key chỉ trong hộp hiển thị một lần
  const [web, setWeb] = useState<{ request: EnrollmentRequest; credential: EnrollmentCredential | null } | null>(null);
  const [keyIssue, setKeyIssue] = useState<EnrollmentIssue | null>(null);
  const [waitingApproval, setWaitingApproval] = useState<EnrollmentRequest | null>(null);

  const onIssued = (issue: EnrollmentIssue) => {
    setWaitingApproval(null);
    const c = issue.credential;
    if (!c) {
      setWaitingApproval(issue.request);
      return;
    }
    if (c.kind === "preauth_key") setKeyIssue(issue);
    else setWeb({ request: issue.request, credential: c });
  };

  return (
    <Page title={t("nav.tenant.enroll")}>
      <p className="mb-4 text-sm text-muted">{t("enroll.intro")}</p>
      {readOnly && canRequest ? <p className="mb-3 text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
      <Wizard canRequest={canRequest} onIssued={onIssued} />
      {waitingApproval ? (
        <div role="status" className="mt-4 rounded-md border border-line bg-surface p-4 text-sm" data-testid="pending-approval">
          <p className="font-semibold">{t("enroll.pendingApproval.title")}</p>
          <p className="mt-1">{t("enroll.pendingApproval.body")}</p>
        </div>
      ) : null}
      {web ? (
        <IssuedWebAuth
          key={web.request.id}
          tenantId={tenantId}
          request={web.request}
          credential={web.credential}
          onSpent={() => {
            setWeb((w) => (w ? { ...w, credential: null } : w));
          }}
          onDismiss={() => {
            setWeb(null);
          }}
        />
      ) : null}
      {canRequest ? <PasteClaim /> : null}
      <section aria-labelledby="enroll-mine" className="mt-8">
        <h2 id="enroll-mine" className="mb-2 text-lg font-semibold">
          {t("enroll.mine.title")}
        </h2>
        <MyRequests onIssued={onIssued} poll={web === null} />
        {can(role, "tenant.enrollment:approve") ? (
          <p className="mt-2 text-sm">
            <Link to={`/t/${tenantId}/enrollment-keys`} className="link">
              {t("enroll.mine.allLink")}
            </Link>
          </p>
        ) : null}
      </section>
      <KeyRevealDialog
        issue={keyIssue}
        onClose={() => {
          setKeyIssue(null);
        }}
      />
    </Page>
  );
}

function Wizard({ canRequest, onIssued }: { canRequest: boolean; onIssued: (i: EnrollmentIssue) => void }) {
  const { t } = useTranslation();
  const { tenantId, readOnly } = useTenant();
  const [os, setOs] = useState<EnrollmentOS>(() => guessOS(navigator.userAgent));
  const [methodChoice, setMethod] = useState<Method | null>(null);
  const [label, setLabel] = useState("");
  const [ttl, setTtl] = useState(String(TTL_MAX));
  const instructions = useInstructions(tenantId, os);
  const webAvailable = !MOBILE_OS.has(os) && instructions.data?.web_auth_command != null;
  const method: Method = methodChoice === "preauth_key" || !webAvailable ? "preauth_key" : "web_auth";
  const labelBad = label !== "" && !DEVICE_LABEL_RE.test(label);
  const n = Number(ttl);
  const ttlBad = method === "preauth_key" && (!Number.isInteger(n) || n < 1 || n > TTL_MAX);

  const create = useIssueMutation(tenantId, (body: NewRequestBody, key: string) => createRequest(tenantId, body, key), onIssued);
  const submit = () => {
    if (labelBad || ttlBad || create.isPending || readOnly) return;
    const body: NewRequestBody = { method, ...(label ? { device_label: label } : {}), ...(method === "preauth_key" ? { ttl_minutes: n } : {}) };
    create.mutate(body);
  };

  return (
    <section aria-labelledby="enroll-wizard" className="rounded-lg border border-line bg-surface p-4" data-testid="enroll-wizard">
      <h2 id="enroll-wizard" className="text-lg font-semibold">
        {t("enroll.wizard.title")}
      </h2>
      <fieldset className="mt-3">
        <legend className="text-sm font-semibold">{t("enroll.wizard.os")}</legend>
        <div className="mt-2 flex flex-wrap gap-3">
          {ENROLL_OS.map((o) => (
            <label key={o} className="flex items-center gap-2 text-sm">
              <input
                type="radio"
                name="enroll-os"
                value={o}
                checked={os === o}
                onChange={() => {
                  setOs(o);
                }}
              />
              {t(`enroll.os.${o}.name`)}
            </label>
          ))}
        </div>
      </fieldset>
      <div className="mt-4">
        <InstructionsPanel tenantId={tenantId} os={os} />
      </div>
      {canRequest ? (
        <form
          className="mt-4 space-y-3"
          noValidate
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
        >
          <fieldset>
            <legend className="text-sm font-semibold">{t("enroll.wizard.method")}</legend>
            <div className="mt-2 space-y-2 text-sm">
              <label className="flex items-start gap-2">
                <input
                  type="radio"
                  name="enroll-method"
                  className="mt-1"
                  checked={method === "web_auth"}
                  disabled={!webAvailable}
                  onChange={() => {
                    setMethod("web_auth");
                  }}
                />
                <span>
                  <span className="font-medium">{t("enroll.method.web_auth")}</span>
                  <span className="block text-muted">{webAvailable ? t("enroll.wizard.webHint") : MOBILE_OS.has(os) ? t("enroll.wizard.webMobile") : t("enroll.wizard.webOff")}</span>
                </span>
              </label>
              <label className="flex items-start gap-2">
                <input
                  type="radio"
                  name="enroll-method"
                  className="mt-1"
                  checked={method === "preauth_key"}
                  onChange={() => {
                    setMethod("preauth_key");
                  }}
                />
                <span>
                  <span className="font-medium">{t("enroll.method.preauth_key")}</span>
                  <span className="block text-muted">{t("enroll.wizard.keyHint")}</span>
                </span>
              </label>
            </div>
          </fieldset>
          <LabelField value={label} onChange={setLabel} bad={labelBad} />
          {method === "preauth_key" ? <TtlField value={ttl} onChange={setTtl} bad={ttlBad} /> : null}
          {create.isError ? <WizardError error={create.error} /> : null}
          <button type="submit" className="btn-primary" disabled={labelBad || ttlBad || create.isPending || readOnly}>
            {create.isPending ? t("common.working") : t(method === "web_auth" ? "enroll.wizard.submitWeb" : "enroll.wizard.submitKey")}
          </button>
        </form>
      ) : (
        <p className="mt-4 text-sm text-muted">{t("enroll.wizard.noRequest")}</p>
      )}
    </section>
  );
}

export function LabelField({ value, onChange, bad }: { value: string; onChange: (v: string) => void; bad: boolean }) {
  const { t } = useTranslation();
  return (
    <div>
      <label htmlFor="enroll-label" className="label">
        {t("enroll.wizard.label")}
      </label>
      <input
        id="enroll-label"
        className="input font-mono"
        maxLength={63}
        autoComplete="off"
        spellCheck={false}
        value={value}
        aria-invalid={bad || undefined}
        aria-describedby="enroll-label-hint"
        onChange={(e) => {
          onChange(e.target.value.toLowerCase());
        }}
      />
      <p id="enroll-label-hint" className={bad ? "field-error" : "hint"}>
        {bad ? t("enroll.wizard.labelInvalid") : t("enroll.wizard.labelHint")}
      </p>
    </div>
  );
}

export function TtlField({ value, onChange, bad }: { value: string; onChange: (v: string) => void; bad: boolean }) {
  const { t } = useTranslation();
  return (
    <div>
      <label htmlFor="enroll-ttl" className="label">
        {t("enroll.wizard.ttl")}
      </label>
      <input
        id="enroll-ttl"
        className="input"
        type="number"
        min={1}
        max={TTL_MAX}
        value={value}
        aria-invalid={bad || undefined}
        aria-describedby="enroll-ttl-hint"
        onChange={(e) => {
          onChange(e.target.value);
        }}
      />
      <p id="enroll-ttl-hint" className={bad ? "field-error" : "hint"}>
        {t("enroll.wizard.ttlHint", { max: TTL_MAX })}
      </p>
    </div>
  );
}

/** Lỗi của bước tạo: mã chung (quota, rate limit, suspended…) + gợi ý cho 403 (tenant chưa cho tự thêm thiết bị). */
export function WizardError({ error }: { error: unknown }) {
  const { t } = useTranslation();
  return (
    <div className="space-y-2" data-testid="wizard-error">
      <ProblemAlert error={error} />
      {error instanceof ApiError && error.code === "forbidden" ? <p className="text-sm">{t("enroll.selfEnrollHint")}</p> : null}
    </div>
  );
}

/** Yêu cầu web-auth vừa phát: lệnh + trạng thái sống (poll) tới khi thiết bị được xác minh / thất bại / hết hạn. */
function IssuedWebAuth(props: {
  tenantId: string;
  request: EnrollmentRequest;
  credential: EnrollmentCredential | null;
  onSpent: () => void;
  onDismiss: () => void;
}) {
  const { t } = useTranslation();
  const codeText = useCodeText();
  const q = useEnrollmentRequest(props.tenantId, props.request.id, props.request);
  const r = q.data;
  const { credential, onSpent } = props;
  // yêu cầu rời `issued` ⇒ mã không còn dùng được: bỏ khỏi state
  const spent = credential !== null && r.status !== "issued";
  useEffect(() => {
    if (spent) onSpent();
  }, [spent, onSpent]);
  return (
    <section aria-labelledby="enroll-issued" className="mt-4 rounded-lg border border-line bg-surface p-4" data-testid="issued-web">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 id="enroll-issued" className="text-lg font-semibold">
          {t("enroll.issued.title", { label: r.device_label ?? t("enroll.noLabel") })}
        </h2>
        <span aria-live="polite" data-testid="issued-status">
          <StatusBadge status={r.status}>{t(`status.enrollment.${r.status}`)}</StatusBadge>
        </span>
      </div>
      {credential && r.status === "issued" ? (
        <div className="mt-3">
          <WebAuthCommand credential={credential} />
        </div>
      ) : null}
      {r.status === "verified" ? (
        <p role="status" className="mt-3 text-sm" data-testid="issued-verified">
          {t("enroll.claim.verified", { label: r.device_label ?? t("enroll.noLabel") })}{" "}
          <Link to={`/t/${props.tenantId}/devices`} className="link">
            {t("enroll.claim.toDevices")}
          </Link>
        </p>
      ) : null}
      {r.status === "failed" ? (
        <p role="alert" className="mt-3 text-sm text-danger">
          {codeText("enroll.failure", r.failure_code)}
        </p>
      ) : null}
      {r.status === "expired" || r.status === "revoked" ? <p className="mt-3 text-sm">{t(`enroll.issued.ended.${r.status}`)}</p> : null}
      {q.isError ? <ProblemAlert error={q.error} /> : null}
      <button type="button" className="btn-secondary mt-3" onClick={props.onDismiss}>
        {t("enroll.issued.dismiss")}
      </button>
    </section>
  );
}

/** Phương án lùi: dán link `/register/<auth_id>` mà client in ra (hoặc Auth ID, hoặc link trang claim). */
function PasteClaim() {
  const { t } = useTranslation();
  const { tenantId, membershipId, readOnly, slug } = useTenant();
  const instructions = useInstructions(tenantId, "linux");
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [authId, setAuthId] = useState<string | null>(null);
  const [round, setRound] = useState(0);
  const check = () => {
    const r = extractAuthId(text, { loginServer: instructions.data?.login_server, tenantSlug: slug });
    // giá trị đã dán không ở lại trong ô nhập
    setText("");
    if (!r.ok) {
      setError(t(`enroll.paste.errors.${r.reason}`));
      return;
    }
    setError(null);
    setAuthId(r.authId);
    setRound((n) => n + 1);
  };
  return (
    <section aria-labelledby="enroll-paste" className="mt-6 rounded-lg border border-line bg-surface p-4" data-testid="paste-claim">
      <h2 id="enroll-paste" className="text-lg font-semibold">
        {t("enroll.paste.title")}
      </h2>
      <p className="mt-1 text-sm text-muted">{t("enroll.paste.hint")}</p>
      <form
        className="mt-3 flex flex-wrap items-end gap-2"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          if (text.trim() !== "") check();
        }}
      >
        <div className="min-w-0 flex-1">
          <label htmlFor="enroll-paste-input" className="label">
            {t("enroll.paste.label")}
          </label>
          <input
            id="enroll-paste-input"
            className="input font-mono"
            autoComplete="off"
            spellCheck={false}
            value={text}
            aria-invalid={error !== null || undefined}
            aria-describedby={error ? "enroll-paste-err" : undefined}
            onChange={(e) => {
              setText(e.target.value);
              setError(null);
            }}
          />
          {error ? (
            <p id="enroll-paste-err" className="field-error">
              {error}
            </p>
          ) : null}
        </div>
        <button type="submit" className="btn-secondary" disabled={text.trim() === ""}>
          {t("enroll.paste.check")}
        </button>
      </form>
      {authId !== null || round > 0 ? (
        <div className="mt-4">
          <ClaimPanel
            key={round}
            tenantId={tenantId}
            membershipId={membershipId}
            authId={authId ?? ""}
            readOnly={readOnly}
            onSpent={() => {
              setAuthId(null);
            }}
          />
        </div>
      ) : null}
    </section>
  );
}

function MyRequests({ onIssued, poll }: { onIssued: (i: EnrollmentIssue) => void; poll: boolean }) {
  const { t } = useTranslation();
  const { tenantId, role, membershipId, readOnly } = useTenant();
  const list = useEnrollmentList(tenantId, {}, true, poll);
  const names = useMemberNames(tenantId, false);
  return (
    <QueryBlock query={list}>
      {(data) => {
        const mine = data.items.filter((r) => isMine(r, membershipId));
        return mine.length === 0 ? (
          <EmptyState>{t("enroll.mine.empty")}</EmptyState>
        ) : (
          <RequestTable
            tenantId={tenantId}
            role={role}
            membershipId={membershipId}
            readOnly={readOnly}
            items={mine}
            names={names}
            caption={t("enroll.mine.title")}
            testId="my-requests"
            onIssued={onIssued}
          />
        );
      }}
    </QueryBlock>
  );
}

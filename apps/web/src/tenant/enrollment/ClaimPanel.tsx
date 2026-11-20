// Xác nhận một đăng ký web-auth (P4-T08, §7.4 bước 6–8; T-06) — dùng chung cho trang claim (link client in ra, edge v10
// chuyển hướng — P4-T07) và ô "dán link hoặc Auth ID". Cảnh báo chống phishing + xác nhận TƯỜNG MINH trước khi gọi
// POST /enrollment/web-auth/claim {auth_id[, request_id]}; server mới là nơi quyết định (yêu cầu `issued` của chính thành
// viên trong cùng phiên, mã trong hostname, kiểm node sau AuthRegister). `request_id` chỉ gửi sau `422 request_id_required`:
// danh sách của client gồm cả yêu cầu của phiên Portal khác (API không cho biết phiên) — server tự chọn khi phiên này chỉ có
// một. Kết quả theo lý do ổn định của Problem.errors[0] (P4-T08): `no_pending_request` ⇒ trang cảnh báo phishing KHÔNG có
// nút xác nhận; `auth_id_already_claimed` ⇒ link đã dùng hoặc hết hạn; `auth_id_not_pending` và `502 upstream_rejected` /
// `503 instance_unavailable` ⇒ yêu cầu ĐÃ KẾT THÚC (server đã claim rồi đánh `failed` khi AuthRegister lỗi, giữ hash Auth
// ID — gửi lại cùng Auth ID chỉ nhận 409 replay, chạy lại lệnh cũ ⇒ 409 no_pending_request) ⇒ tạo yêu cầu mới; 200
// `failed` ⇒ `failure_code`; 200 `verified` ⇒ tên thiết bị + link. Thử lại cùng Auth ID chỉ với lỗi trước bước claim: 429,
// 503 `maintenance`, lỗi mạng/edge, 401 `reauth_required`. 429 ở lần xác nhận đầu (F-G4a-1 — bucket `enrollment` dùng chung
// cho các GET của trang và POST claim) ⇒ màn hình tự gửi lại MỘT lần sau `Retry-After` (≤ 60 s) với cùng thân (claim không
// có Idempotency-Key: 429 bị từ chối trước mọi xử lý nên gửi lại an toàn); người dùng bấm lại trước đó ⇒ hủy lượt tự động.
// Auth ID chỉ nằm trong props của màn hình (không useMutation — biến của mutation sẽ ở lại cache), được bỏ khi có kết quả
// cuối (`onSpent`), không bao giờ hiển thị.
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useEffectEvent, useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";
import { api, call } from "../../api/client";
import { ApiError } from "../../api/problem";
import { ProblemAlert } from "../../components/ProblemAlert";
import { useCodeText } from "../../ui/Status";
import { Timestamp, useNow } from "../../ui/time";
import { invalidateEnrollment, useEnrollmentList } from "./api";
import { pendingWebAuth, problemReason, type EnrollmentRequest } from "./model";

type Outcome =
  | { kind: "verified"; request: EnrollmentRequest }
  | { kind: "failed"; request: EnrollmentRequest }
  | { kind: "phishing" }
  | { kind: "used" }
  | { kind: "ended"; reason: "not_pending" | "upstream"; requestId: string | null }
  | { kind: "disabled" }
  | { kind: "invalid" }
  | { kind: "error"; error: unknown };

/** Trần của lần tự thử lại sau 429 (giây) — Retry-After dài hơn ⇒ chỉ người dùng bấm lại. */
export const CLAIM_AUTO_RETRY_MAX_S = 60;

export interface ClaimPanelProps {
  tenantId: string;
  membershipId: string | null;
  authId: string;
  readOnly: boolean;
  /** kết quả cuối đã có ⇒ chủ state bỏ Auth ID */
  onSpent: () => void;
}

export function ClaimPanel({ tenantId, membershipId, authId, readOnly, onSpent }: ClaimPanelProps) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const now = useNow();
  const ids = { ack: useId(), pick: useId() };
  // yêu cầu web-auth đang chờ của chính mình — chỉ để hiển thị ngữ cảnh và chọn request_id (server vẫn kiểm cùng phiên)
  const list = useEnrollmentList(tenantId, { status: "issued" }, true, false);
  const pending = pendingWebAuth(list.data?.items ?? [], membershipId, now);
  const [ack, setAck] = useState(false);
  const [picked, setPicked] = useState<string | null>(null);
  const [mustPick, setMustPick] = useState(false);
  const [busy, setBusy] = useState(false);
  const [retryable, setRetryable] = useState<unknown>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  // F-G4a-1: thời điểm (ms) của lần tự gửi lại duy nhất sau 429; đã dùng ⇒ không tự gửi nữa
  const [autoAt, setAutoAt] = useState<number | null>(null);
  const [autoUsed, setAutoUsed] = useState(false);

  // bộ chọn chỉ sau 422 request_id_required: chọn trước theo danh sách client có thể trỏ vào yêu cầu của phiên khác ⇒ 409
  const requestId = mustPick ? picked : null;
  const canConfirm = ack && !busy && !readOnly && (!mustPick || requestId !== null);

  const finish = (o: Outcome) => {
    setOutcome(o);
    onSpent();
    void invalidateEnrollment(queryClient, tenantId);
  };

  const confirm = async () => {
    if (!canConfirm) return;
    setAutoAt(null); // bấm tay trước hạn ⇒ hủy lượt tự động
    setBusy(true);
    setRetryable(null);
    try {
      const r = await call(
        api.POST("/tenants/{tenantId}/enrollment/web-auth/claim", {
          params: { path: { tenantId } },
          body: requestId ? { auth_id: authId, request_id: requestId } : { auth_id: authId },
        }),
      );
      finish(r.status === "verified" ? { kind: "verified", request: r } : { kind: "failed", request: r });
    } catch (e) {
      const conflict = problemReason(e, "conflict");
      const invalid = problemReason(e, "validation_failed");
      const requestIdOf = e instanceof ApiError ? e.requestId : null;
      if (conflict === "no_pending_request") finish({ kind: "phishing" });
      else if (conflict === "auth_id_already_claimed") finish({ kind: "used" });
      else if (conflict === "auth_id_not_pending") finish({ kind: "ended", reason: "not_pending", requestId: requestIdOf });
      else if (e instanceof ApiError && (e.code === "upstream_rejected" || e.code === "instance_unavailable")) {
        // chỉ phát sinh sau khi server đã claim yêu cầu (AuthRegister / control plane lỗi ⇒ yêu cầu `failed`, giữ hash Auth ID)
        finish({ kind: "ended", reason: "upstream", requestId: requestIdOf });
      } else if (invalid === "request_id_required") {
        setMustPick(true);
        void list.refetch();
        setRetryable(e);
      } else if (invalid === "web_auth_disabled") finish({ kind: "disabled" });
      else if (invalid === "invalid_auth_id") finish({ kind: "invalid" });
      else if (e instanceof ApiError && (e.status === 429 || e.status === 502 || e.status === 503 || e.code === "network_error" || e.code === "reauth_required")) {
        // trước bước claim (rate limit, bảo trì, edge/mạng, step-up) ⇒ thử lại được với cùng Auth ID (pending registration
        // sống 15 phút ở Headscale)
        setRetryable(e);
        const wait = e.status === 429 ? (e.retryAfter ?? 1) : null;
        if (wait !== null && !autoUsed && wait <= CLAIM_AUTO_RETRY_MAX_S) {
          setAutoUsed(true);
          setAutoAt(Date.now() + Math.max(1, wait) * 1000);
        }
      } else finish({ kind: "error", error: e });
    } finally {
      setBusy(false);
    }
  };

  // lượt tự động đọc state MỚI NHẤT (người dùng bỏ ô xác nhận trong lúc chờ ⇒ canConfirm sai ⇒ không gửi)
  const autoConfirm = useEffectEvent(() => {
    void confirm();
  });
  useEffect(() => {
    if (autoAt === null) return;
    const id = window.setTimeout(
      () => {
        setAutoAt(null);
        autoConfirm();
      },
      Math.max(0, autoAt - Date.now()),
    );
    return () => {
      window.clearTimeout(id);
    };
  }, [autoAt]);

  if (outcome) return <ClaimOutcome outcome={outcome} tenantId={tenantId} />;

  return (
    <div className="space-y-4" data-testid="claim-confirm">
      <div className="rounded-md border border-warn/50 bg-warn-bg p-4 text-sm" data-testid="phishing-caution">
        <h2 className="font-semibold text-warn">{t("enroll.claim.cautionTitle")}</h2>
        <p className="mt-1">{t("enroll.claim.caution")}</p>
        <p className="mt-1">{t("enroll.claim.cautionNever")}</p>
      </div>
      {list.isSuccess && pending.length === 0 && !mustPick ? (
        <p className="rounded-md border border-danger/40 bg-danger-bg p-3 text-sm" data-testid="no-pending-hint">
          {t("enroll.claim.noPendingSeen")}
        </p>
      ) : null}
      {pending.length === 1 && !mustPick ? (
        <p className="text-sm" data-testid="pending-context">
          {t("enroll.claim.pendingOne", { label: pending[0]?.device_label ?? t("enroll.noLabel") })}{" "}
          <Timestamp iso={pending[0]?.credential_expires_at} />
        </p>
      ) : null}
      {pending.length > 1 && !mustPick ? (
        <p className="text-sm" data-testid="pending-several">
          {t("enroll.claim.pendingSeveral")}
        </p>
      ) : null}
      {mustPick ? (
        <fieldset className="space-y-1 text-sm" data-testid="pick-request">
          <legend className="font-medium">{t("enroll.claim.pick")}</legend>
          {pending.map((r) => (
            <div key={r.id} className="flex items-center gap-2">
              <input
                id={`${ids.pick}-${r.id}`}
                type="radio"
                name={ids.pick}
                checked={picked === r.id}
                onChange={() => {
                  setPicked(r.id);
                }}
              />
              <label htmlFor={`${ids.pick}-${r.id}`}>
                {r.device_label ?? t("enroll.noLabel")} · <Timestamp iso={r.issued_at} relative />
              </label>
            </div>
          ))}
        </fieldset>
      ) : null}
      {readOnly ? <p className="text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
      <div className="flex items-start gap-2">
        <input
          id={ids.ack}
          type="checkbox"
          className="mt-1"
          checked={ack}
          onChange={(e) => {
            setAck(e.target.checked);
          }}
        />
        <label htmlFor={ids.ack} className="text-sm">
          {t("enroll.claim.ack")}
        </label>
      </div>
      {retryable ? <ProblemAlert error={retryable} /> : null}
      {autoAt !== null ? (
        <p role="status" className="text-sm" data-testid="claim-auto-retry">
          {t("enroll.claim.autoRetry")}
        </p>
      ) : null}
      <button type="button" className="btn-primary" disabled={!canConfirm} onClick={() => void confirm()}>
        {busy ? t("common.working") : t("enroll.claim.confirm")}
      </button>
    </div>
  );
}

function ClaimOutcome({ outcome, tenantId }: { outcome: Outcome; tenantId: string }) {
  const { t } = useTranslation();
  const codeText = useCodeText();
  switch (outcome.kind) {
    case "verified":
      return (
        <div role="status" className="space-y-2 rounded-md border border-line bg-surface p-4" data-testid="claim-verified">
          <p className="font-semibold">{t("enroll.claim.verified", { label: outcome.request.device_label ?? t("enroll.noLabel") })}</p>
          <p className="text-sm">{t("enroll.claim.verifiedHint")}</p>
          <Link to={`/t/${tenantId}/devices`} className="link">
            {t("enroll.claim.toDevices")}
          </Link>
        </div>
      );
    case "failed":
      return (
        <div role="alert" className="space-y-2 rounded-md border border-danger/40 bg-danger-bg p-4" data-testid="claim-failed">
          <p className="font-semibold text-danger">{t("enroll.claim.failed")}</p>
          <p className="text-sm">{codeText("enroll.failure", outcome.request.failure_code)}</p>
        </div>
      );
    case "phishing":
      return <PhishingWarning />;
    case "used":
      return (
        <div role="alert" className="rounded-md border border-line bg-surface p-4" data-testid="claim-used">
          <p className="font-semibold">{t("enroll.claim.usedTitle")}</p>
          <p className="mt-1 text-sm">{t("enroll.claim.used")}</p>
        </div>
      );
    case "ended":
      return (
        <div role="alert" className="space-y-2 rounded-md border border-danger/40 bg-danger-bg p-4" data-testid="claim-ended">
          <p className="font-semibold text-danger">{t("enroll.claim.endedTitle")}</p>
          <p className="text-sm">{t(outcome.reason === "not_pending" ? "enroll.claim.endedNotPending" : "enroll.claim.endedUpstream")}</p>
          <p className="text-sm">{t("enroll.claim.endedNext")}</p>
          {outcome.requestId ? (
            <p className="text-xs text-muted">
              {t("problem.requestId")} <code>{outcome.requestId}</code>
            </p>
          ) : null}
        </div>
      );
    case "disabled":
      return (
        <div role="alert" className="rounded-md border border-line bg-surface p-4" data-testid="claim-disabled">
          <p className="font-semibold">{t("enroll.claim.disabledTitle")}</p>
          <p className="mt-1 text-sm">{t("enroll.claim.disabled")}</p>
        </div>
      );
    case "invalid":
      return <InvalidLink />;
    case "error":
      return (
        <div className="space-y-2" data-testid="claim-error">
          <ProblemAlert error={outcome.error} />
          {outcome.error instanceof ApiError && outcome.error.code === "forbidden" ? <p className="text-sm">{t("enroll.selfEnrollHint")}</p> : null}
        </div>
      );
  }
}

/** §7.4 bước 6: không có yêu cầu đang chờ của bạn trong phiên này ⇒ cảnh báo, KHÔNG có nút xác nhận. */
export function PhishingWarning() {
  const { t } = useTranslation();
  return (
    <div role="alert" className="space-y-2 rounded-md border border-danger/40 bg-danger-bg p-4" data-testid="claim-phishing">
      <h2 className="font-semibold text-danger">{t("enroll.claim.phishingTitle")}</h2>
      <p className="text-sm">{t("enroll.claim.phishing")}</p>
      <p className="text-sm">{t("enroll.claim.phishingSession")}</p>
    </div>
  );
}

export function InvalidLink() {
  const { t } = useTranslation();
  return (
    <div role="alert" className="rounded-md border border-line bg-surface p-4" data-testid="claim-invalid">
      <p className="font-semibold">{t("enroll.claim.invalidTitle")}</p>
      <p className="mt-1 text-sm">{t("enroll.claim.invalid")}</p>
    </div>
  );
}

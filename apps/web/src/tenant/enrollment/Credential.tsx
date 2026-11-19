// Credential một lần (P4-T08, §7.4 phương thức A/B, `x-secret-once` của P4-T06): lệnh web-auth (mã enrollment trong
// hostname `mg-<mã>`) và pre-auth key. Giá trị chỉ nằm trong props/state của màn hình đang mở — không Web Storage, không
// URL, không cache của TanStack Query; hộp key xóa key khỏi state khi đóng (chủ của state đặt về null).
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { ModalDialog } from "../../ui/Dialog";
import { CodeLine, CopyButton } from "../../ui/Copy";
import { Timestamp } from "../../ui/time";
import type { EnrollmentCredential, EnrollmentIssue } from "./model";

/** Lệnh của yêu cầu web-auth vừa phát: chạy trên thiết bị, rồi mở link client in ra trong CHÍNH trình duyệt này. */
export function WebAuthCommand({ credential }: { credential: EnrollmentCredential }) {
  const { t } = useTranslation();
  return (
    <div className="space-y-2 text-sm" data-testid="web-auth-command">
      <p className="font-medium">{t("enroll.issued.runCommand")}</p>
      <CodeLine value={credential.command} copyLabel={t("enroll.issued.copyCommand")} testId="enroll-command" />
      {credential.hostname ? (
        <p>
          {t("enroll.issued.hostname")} <code>{credential.hostname}</code>
        </p>
      ) : null}
      <p>
        {t("enroll.issued.expires")} <Timestamp iso={credential.expires_at} />
      </p>
      <ol className="list-decimal space-y-1 ps-5">
        <li>{t("enroll.issued.next1")}</li>
        <li>{t("enroll.issued.next2")}</li>
        <li>{t("enroll.issued.next3")}</li>
      </ol>
    </div>
  );
}

/** Pre-auth key: cảnh báo một lần, sao chép, lệnh đọc key từ biến môi trường TS_AUTHKEY (không chép key vào lệnh). */
export function PreauthKeyView({ credential }: { credential: EnrollmentCredential }) {
  const { t } = useTranslation();
  const key = credential.preauth_key ?? "";
  return (
    <div className="space-y-3 text-sm" data-testid="preauth-key">
      <p className="rounded-md bg-warn-bg p-3 text-warn" data-testid="secret-once-warning">
        {t("enroll.key.onceWarning")}
      </p>
      <div>
        <p className="font-medium">{t("enroll.key.value")}</p>
        <div className="flex flex-wrap items-start gap-2">
          <code tabIndex={0} className="min-w-0 flex-1 rounded-md border border-line bg-bg p-2 font-mono text-xs break-all" data-testid="secret-value">
            {key}
          </code>
          <CopyButton value={key} label={t("enroll.key.copy")} testId="copy-key" />
        </div>
      </div>
      <p>
        {t("enroll.issued.expires")} <Timestamp iso={credential.expires_at} />
      </p>
      <div>
        <p className="font-medium">{t("enroll.key.command")}</p>
        <CodeLine value={credential.command} copyLabel={t("enroll.issued.copyCommand")} testId="key-command" />
        <p className="hint">{t("enroll.key.envHint")}</p>
      </div>
    </div>
  );
}

/**
 * Hộp hiển thị pre-auth key MỘT LẦN: người dùng xác nhận đã lưu rồi đóng; đóng (kể cả Esc) ⇒ `onClose` — chủ state bỏ
 * key. Mở lại không có cách nào xem lại key (server cũng không trả lại — thu hồi rồi cấp key mới).
 */
export function KeyRevealDialog({ issue, onClose }: { issue: EnrollmentIssue | null; onClose: () => void }) {
  const { t } = useTranslation();
  const credential = issue?.credential;
  return (
    <ModalDialog
      isOpen={credential?.kind === "preauth_key"}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={t("enroll.key.dialogTitle")}
    >
      {credential ? <KeyRevealBody credential={credential} onClose={onClose} /> : null}
    </ModalDialog>
  );
}

function KeyRevealBody({ credential, onClose }: { credential: EnrollmentCredential; onClose: () => void }) {
  const { t } = useTranslation();
  const [saved, setSaved] = useState(false);
  const id = useId();
  return (
    <div className="space-y-3">
      <PreauthKeyView credential={credential} />
      <div className="flex items-start gap-2">
        <input
          id={id}
          type="checkbox"
          className="mt-1"
          checked={saved}
          onChange={(e) => {
            setSaved(e.target.checked);
          }}
        />
        <label htmlFor={id} className="text-sm">
          {t("enroll.key.saved")}
        </label>
      </div>
      <div className="flex justify-end">
        <button type="button" className="btn-primary" disabled={!saved} onClick={onClose}>
          {t("enroll.key.close")}
        </button>
      </div>
    </div>
  );
}

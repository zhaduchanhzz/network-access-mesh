// Hướng dẫn cài client chính thức theo hệ điều hành (P4-T08, §9.4 — thay /apple, /windows của Headscale bị chặn ở edge):
// GET /tenants/{t}/enrollment/instructions?os= trả `login_server` (server_url của instance), mẫu lệnh web-auth / pre-auth
// key và biến môi trường cho cài đặt có quản lý (TS_NO_LOGS_NO_SUPPORT — HS-22). `steps`/`privacy_notice` của API chỉ có
// tiếng Anh (API không nhận locale) ⇒ màn hình hiển thị bản dịch vi/en của cùng nội dung (enroll.os.*, enroll.privacy);
// mọi giá trị máy (URL, lệnh, biến) lấy nguyên văn từ API — không URL/tên miền nào viết cứng trong mã.
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api, call } from "../../api/client";
import { ApiError } from "../../api/problem";
import { Loading } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { CodeLine } from "../../ui/Copy";
import { enrollmentRetry } from "./api";
import { enrollmentKeys, MOBILE_OS, type EnrollmentInstructions, type EnrollmentOS } from "./model";

export function useInstructions(tenantId: string, os: EnrollmentOS) {
  return useQuery({
    queryKey: enrollmentKeys.instructions(tenantId, os),
    queryFn: () => call(api.GET("/tenants/{tenantId}/enrollment/instructions", { params: { path: { tenantId }, query: { os } } })),
    staleTime: 60_000,
    retry: enrollmentRetry,
  });
}

/** Bước cài đặt theo OS (bản dịch; số bước cố định theo OS). */
const STEP_COUNT: Record<EnrollmentOS, number> = { linux: 3, windows: 3, macos: 3, ios: 3, android: 3 };

/** Lệnh cài MSI cho Windows với LoginURL của tenant (thuộc tính TS_LOGINURL = chính sách hệ thống LoginURL). */
export function windowsMsiCommand(loginServer: string): string {
  return `msiexec /i tailscale-setup-<version>-amd64.msi TS_LOGINURL=${loginServer}`;
}

export function windowsPolicyCommand(loginServer: string): string {
  return `reg add "HKLM\\SOFTWARE\\Policies\\Tailscale" /v LoginURL /t REG_SZ /d ${loginServer} /f`;
}

export function InstructionsPanel({ tenantId, os }: { tenantId: string; os: EnrollmentOS }) {
  const { t } = useTranslation();
  const q = useInstructions(tenantId, os);
  if (q.isPending) return <Loading />;
  if (q.isError) {
    if (q.error instanceof ApiError && q.error.code === "not_found") {
      return (
        <p className="rounded-md border border-line bg-surface p-3 text-sm" data-testid="no-instance">
          {t("enroll.instructions.noInstance")}
        </p>
      );
    }
    return <ProblemAlert error={q.error} onRetry={() => void q.refetch()} />;
  }
  return <InstructionsBody data={q.data} />;
}

function InstructionsBody({ data }: { data: EnrollmentInstructions }) {
  const { t } = useTranslation();
  const os = data.os;
  const steps = Array.from({ length: STEP_COUNT[os] }, (_, i) => t(`enroll.os.${os}.step${String(i + 1)}`));
  const env = Object.entries(data.managed_env);
  return (
    <div className="space-y-3 text-sm" data-testid="instructions" data-os={os}>
      <ol className="list-decimal space-y-1 ps-5">
        {steps.map((s, i) => (
          <li key={i}>{s}</li>
        ))}
      </ol>
      <div>
        <p className="font-medium">{t("enroll.instructions.loginServer")}</p>
        <CodeLine value={data.login_server} copyLabel={t("enroll.instructions.copyLoginServer")} testId="login-server" />
      </div>
      {os === "windows" ? (
        <div data-testid="windows-msi">
          <p className="font-medium">{t("enroll.instructions.windowsMsi")}</p>
          <CodeLine value={windowsMsiCommand(data.login_server)} copyLabel={t("enroll.instructions.copyMsi")} />
          <p className="mt-2 font-medium">{t("enroll.instructions.windowsPolicy")}</p>
          <CodeLine value={windowsPolicyCommand(data.login_server)} copyLabel={t("enroll.instructions.copyPolicy")} />
        </div>
      ) : null}
      {MOBILE_OS.has(os) ? <p className="text-muted">{t("enroll.instructions.mobileNote")}</p> : null}
      {env.length > 0 ? (
        <div>
          <p className="font-medium">{t("enroll.instructions.managedEnv")}</p>
          <ul className="font-mono text-xs" data-testid="managed-env">
            {env.map(([k, v]) => (
              <li key={k}>{`${k}=${v}`}</li>
            ))}
          </ul>
        </div>
      ) : null}
      <p className="rounded-md bg-warn-bg p-3 text-warn" data-testid="privacy-notice">
        {t("enroll.privacy")}
      </p>
    </div>
  );
}

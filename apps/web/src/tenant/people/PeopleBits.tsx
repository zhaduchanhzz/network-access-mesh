// Mảnh hiển thị dùng chung của Users / Groups / Invitations (P4-T09a): tên role, trạng thái membership + trạng thái hai
// pha của offboard, lỗi kèm nút step-up (401 reauth_required ngoài hộp thoại — trong hộp ConfirmDialog đã có sẵn).
import { useTranslation } from "react-i18next";
import { ApiError } from "../../api/problem";
import { useStepUp } from "../../components/Banners";
import { ProblemAlert } from "../../components/ProblemAlert";
import { StatusBadge, useCodeText } from "../../ui/Status";
import { membershipTone, offboardTone, type Membership } from "./model";

export function RoleName({ role }: { role: string }) {
  const text = useCodeText();
  return <>{text("roles", role)}</>;
}

/** Trạng thái membership; đã offboard ⇒ thêm trạng thái của job `member.offboard` (pending/applied/failed). */
export function MemberStatus({ member }: { member: Pick<Membership, "status" | "offboarding"> }) {
  const text = useCodeText();
  return (
    <span className="inline-flex flex-wrap gap-1">
      <StatusBadge tone={membershipTone(member.status)} status={member.status}>
        {text("people.status", member.status)}
      </StatusBadge>
      {member.offboarding ? (
        <StatusBadge tone={offboardTone(member.offboarding.state)} status={`offboard-${member.offboarding.state}`} testId="offboard-state">
          {text("people.offboard.state", member.offboarding.state)}
        </StatusBadge>
      ) : null}
    </span>
  );
}

/** Lỗi của một thao tác; 401 reauth_required ⇒ nút "Xác thực lại" ngay cạnh lỗi (quay về đúng trang sau khi đăng nhập). */
export function ActionError({ error }: { error: unknown }) {
  const { t } = useTranslation();
  const stepUp = useStepUp();
  if (!error) return null;
  return (
    <div className="mt-2 space-y-2">
      <ProblemAlert error={error} />
      {error instanceof ApiError && error.code === "reauth_required" ? (
        <button type="button" className="btn-secondary" onClick={stepUp}>
          {t("stepUp.action")}
        </button>
      ) : null}
    </div>
  );
}

// Policies (P4-T11, §12.3 Access Policies, §7.3): trạng thái hiện hành (version mong muốn; "đã áp dụng lên Headscale lúc
// …" — không phải "client đã hội tụ"; lần áp gần nhất; 4-eyes / step-up), lịch sử version (trạng thái, người soạn/gửi/
// duyệt, rollback), soạn bản nháp mới (Idempotency-Key; nội dung khởi đầu = version mong muốn, hoặc deny-all khi chưa có).
import { useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Link, useNavigate } from "react-router";
import { api, call } from "../../api/client";
import { useIdempotentMutation } from "../../api/idempotency";
import { useCursorPager } from "../../api/pagination";
import { can } from "../../auth/permissions";
import { Page } from "../../components/Page";
import { ProblemAlert } from "../../components/ProblemAlert";
import { EmptyState, Pager, QueryBlock } from "../../ui/Data";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { useTenant } from "../TenantScope";
import { policyKeys, usePolicyCurrent, usePolicyNames, usePolicyVersions } from "./api";
import { CurrentPanel } from "./AppliedState";
import { emptySource, toSourceBody } from "./model";

export function PoliciesPage() {
  const { t } = useTranslation();
  const { tenantId, role, readOnly } = useTenant();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const pager = useCursorPager("");
  const current = usePolicyCurrent(tenantId);
  const versions = usePolicyVersions(tenantId, pager.cursor);
  const names = usePolicyNames(tenantId, role);
  const who = (id: string | undefined) => (id ? (names.data?.identities.get(id) ?? id.slice(0, 8)) : t("common.none"));
  const create = useIdempotentMutation({
    mutationFn: (_: null, key: string) => {
      const base = current.data?.desired;
      const source = base?.kind === "user" && base.source ? base.source : emptySource();
      return call(api.POST("/tenants/{tenantId}/policies", { params: { path: { tenantId }, header: { "Idempotency-Key": key } }, body: { source: toSourceBody(source) } }));
    },
    fingerprint: () => `new:${current.data?.desired?.id ?? ""}`,
    onSuccess: (v) => {
      void queryClient.invalidateQueries({ queryKey: policyKeys.all(tenantId) });
      void navigate(`/t/${tenantId}/policies/${v.id}`);
    },
  });
  const canEdit = can(role, "tenant.policy:edit") && !readOnly;
  return (
    <Page
      title={t("nav.tenant.policies")}
      actions={
        canEdit ? (
          <button type="button" className="btn-primary" disabled={create.isPending || current.isPending} onClick={() => create.mutate(null)}>
            {t("policies.newVersion")}
          </button>
        ) : null
      }
    >
      {readOnly ? <p className="mb-3 text-sm text-muted">{t("ui.readOnlyActions")}</p> : null}
      {create.isError ? (
        <div className="mb-4">
          <ProblemAlert error={create.error} />
        </div>
      ) : null}
      <p className="mb-4 text-sm text-muted">{t("policies.intro")}</p>
      <div className="mb-6">
        <QueryBlock query={current}>{(c) => <CurrentPanel current={c} />}</QueryBlock>
      </div>
      <section aria-labelledby="pol-history">
        <h2 id="pol-history" className="mb-2 font-semibold">
          {t("policies.history")}
        </h2>
        <QueryBlock query={versions}>
          {(page) =>
            page.items.length === 0 ? (
              <EmptyState>{t("policies.noVersions")}</EmptyState>
            ) : (
              <>
                <div className="relative overflow-x-auto">
                  <table className="data-table" data-testid="policy-versions">
                    <thead>
                      <tr>
                        <th scope="col">{t("policies.col.version")}</th>
                        <th scope="col">{t("policies.col.state")}</th>
                        <th scope="col">{t("policies.col.kind")}</th>
                        <th scope="col">{t("policies.col.createdBy")}</th>
                        <th scope="col">{t("policies.col.review")}</th>
                        <th scope="col">{t("policies.col.updated")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {page.items.map((v) => (
                        <tr key={v.id} data-version={v.version} data-state={v.state}>
                          <td>
                            <Link className="link" to={`/t/${tenantId}/policies/${v.id}`}>
                              {t("policies.versionN", { n: v.version })}
                            </Link>
                            {v.desired ? <StatusBadge tone="ok">{t("policies.desiredBadge")}</StatusBadge> : null}
                            {v.rollback_of ? <span className="ms-1 badge">{t("policies.rollbackBadge")}</span> : null}
                          </td>
                          <td>
                            <StatusBadge status={v.state}>{t(`policies.states.${v.state}`)}</StatusBadge>
                          </td>
                          <td>{t(`policies.kinds.${v.kind}`)}</td>
                          <td>{who(v.created_by)}</td>
                          <td className="text-xs">
                            {v.submitted_by ? <div>{t("policies.col.submitted", { name: who(v.submitted_by) })}</div> : null}
                            {v.approved_by ? (
                              <div>
                                {t("policies.col.approved", { name: who(v.approved_by) })}
                                {v.review_mode ? ` (${t(`policies.reviewModes.${v.review_mode}`)})` : ""}
                              </div>
                            ) : null}
                            {v.rejected_by ? <div>{t("policies.col.rejected", { name: who(v.rejected_by) })}</div> : null}
                          </td>
                          <td>
                            <Timestamp iso={v.updated_at} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <Pager pager={pager} nextCursor={page.next_cursor} label={t("ui.pagination")} />
              </>
            )
          }
        </QueryBlock>
      </section>
    </Page>
  );
}

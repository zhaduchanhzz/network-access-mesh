// Báo cáo kiểm tra (validation_report: lint L1–L13 trên mô hình và đầu ra đã render + CheckPolicy dry-run trên instance)
// và diff (dòng của chuỗi đã render + `grants` thêm/bớt) của một version (P4-T11, §7.3). Diff render cả hai bên với bảng
// hiện tại — không phải what-if quyền hiệu lực (PL-05).
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { QueryBlock } from "../../ui/Data";
import { StatusBadge } from "../../ui/Status";
import { Timestamp } from "../../ui/time";
import { usePolicyDiff } from "./api";
import { FindingList } from "./FindingList";
import { shortSha, type PolicyReport, type PolicyVersion } from "./model";
import { useTenant } from "../TenantScope";

export function ReportPanel({ version }: { version: PolicyVersion }) {
  const { t } = useTranslation();
  const r = version.validation_report;
  return (
    <section
      className="card space-y-3"
      aria-labelledby="pol-report"
      data-testid="policy-report"
      data-result={r?.result}
      data-check={r?.check}
      data-revision={r?.revision}
    >
      <h2 id="pol-report" className="font-semibold">
        {t("policies.report.title")}
      </h2>
      {!r ? (
        <p className="text-sm text-muted">{t("policies.report.none")}</p>
      ) : (
        <>
          <dl className="grid gap-x-6 gap-y-1 text-sm md:grid-cols-[max-content_1fr]">
            <dt className="text-muted">{t("policies.report.result")}</dt>
            <dd>
              <StatusBadge tone={r.result === "passed" ? "ok" : "danger"} testId="report-result">
                {t(`policies.report.results.${r.result}`)}
              </StatusBadge>
            </dd>
            <dt className="text-muted">{t("policies.report.check")}</dt>
            <dd>
              {r.check ? (
                <StatusBadge tone={r.check === "passed" ? "ok" : r.check === "failed" ? "danger" : "neutral"} testId="report-check">
                  {t(`policies.report.checks.${r.check}`)}
                </StatusBadge>
              ) : (
                t("common.none")
              )}
            </dd>
            {r.rendered_sha256 ? (
              <>
                <dt className="text-muted">{t("policies.report.rendered")}</dt>
                <dd>
                  <code title={r.rendered_sha256}>{shortSha(r.rendered_sha256)}</code>
                </dd>
              </>
            ) : null}
            {r.validated_at ? (
              <>
                <dt className="text-muted">{t("policies.report.at")}</dt>
                <dd>
                  <Timestamp iso={r.validated_at} />
                </dd>
              </>
            ) : null}
          </dl>
          {r.revision !== undefined && r.revision !== version.revision ? <p className="text-sm text-warn">{t("policies.report.stale")}</p> : null}
          <FindingList findings={r.errors} label={t("policies.report.errors")} />
          <FindingList findings={r.warnings} label={t("policies.report.warnings")} />
          <FindingList findings={r.info} label={t("policies.report.info")} />
          {r.errors.length + r.warnings.length + r.info.length === 0 ? <p className="text-sm">{t("policies.report.clean")}</p> : null}
          <p className="hint">{t("policies.report.testsNote")}</p>
          <GeneratedTests tests={r.tests} />
        </>
      )}
    </section>
  );
}

type TestCase = PolicyReport["tests"][number];

/** tests sinh tự động của lần kiểm tra (P5-T01): các ca (nguồn, phải được phép / phải bị chặn) và luật không có ca. */
export function GeneratedTests({ tests }: { tests: readonly TestCase[] }) {
  const { t } = useTranslation();
  const id = useId();
  const made = tests.filter((c) => !c.skipped);
  const skipped = tests.filter((c) => c.skipped);
  return (
    <section aria-labelledby={`${id}-tests`} className="space-y-2" data-testid="generated-tests" data-count={made.length}>
      <h3 id={`${id}-tests`} className="label">
        {t("policies.testsGen.title")}
      </h3>
      <p className="hint">{t("policies.testsGen.intro")}</p>
      <p className="text-sm">
        {t("policies.testsGen.generated", { count: made.length })}
        {skipped.length > 0 ? ` · ${t("policies.testsGen.skippedCount", { count: skipped.length })}` : ""}
      </p>
      {made.length > 0 ? (
        <ul className="space-y-1 text-sm" aria-label={t("policies.testsGen.generated", { count: made.length })}>
          {made.map((c) => (
            <li key={`g${String(c.grant)}`} className="rounded-md border border-line p-2" data-grant={c.grant}>
              <span className="font-semibold">{t("policies.testsGen.rule", { n: c.grant + 1 })}</span>{" "}
              <code className="text-xs">{c.src}</code>
              {c.proto ? <span className="text-xs text-muted">{` · ${t("policies.testsGen.proto")} ${c.proto}`}</span> : null}
              {(c.accept ?? []).map((a) => (
                <span key={`a${a}`} className="block text-xs">
                  {`${t("policies.testsGen.accept")}: `}
                  <code>{a}</code>
                </span>
              ))}
              {(c.deny ?? []).map((d) => (
                <span key={`d${d}`} className="block text-xs">
                  {`${t("policies.testsGen.deny")}: `}
                  <code>{d}</code>
                </span>
              ))}
            </li>
          ))}
        </ul>
      ) : null}
      {skipped.length > 0 ? (
        <ul className="space-y-1 text-sm" aria-label={t("policies.testsGen.skippedCount", { count: skipped.length })}>
          {skipped.map((c) => (
            <li key={`s${String(c.grant)}`} data-grant={c.grant} data-skipped={c.skipped}>
              {`${t("policies.testsGen.rule", { n: c.grant + 1 })}: ${t(`policies.testsGen.skipped.${c.skipped ?? "capped"}`)}`}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}

export function DiffPanel({ version, others }: { version: PolicyVersion; others: readonly PolicyVersion[] }) {
  const { t } = useTranslation();
  const { tenantId } = useTenant();
  const id = useId();
  const [against, setAgainst] = useState("");
  const diff = usePolicyDiff(tenantId, version, against);
  const choices = others.filter((o) => o.id !== version.id);
  return (
    <section className="card space-y-3" aria-labelledby="pol-diff" data-testid="policy-diff">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <h2 id="pol-diff" className="font-semibold">
          {t("policies.diff.title")}
        </h2>
        <div>
          <label htmlFor={`${id}-against`} className="label">
            {t("policies.diff.against")}
          </label>
          <select
            id={`${id}-against`}
            className="select"
            value={against}
            onChange={(e) => {
              setAgainst(e.target.value);
            }}
          >
            <option value="">{t("policies.diff.desired")}</option>
            {choices.map((o) => (
              <option key={o.id} value={o.id}>
                {t("policies.versionN", { n: o.version })}
              </option>
            ))}
          </select>
        </div>
      </div>
      <QueryBlock query={diff}>
        {(d) => (
          <div className="space-y-3">
            {d.report_blocking ? <p className="text-sm text-danger">{t("policies.diff.blocking")}</p> : null}
            <div className="grid gap-3 md:grid-cols-2">
              <div>
                <h3 className="label">{t("policies.diff.grantsAdded", { count: d.grants_added.length })}</h3>
                <ul className="space-y-1 font-mono text-xs" data-testid="grants-added">
                  {d.grants_added.map((g) => (
                    <li key={g}>
                      <ins className="no-underline">{`+ ${g}`}</ins>
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <h3 className="label">{t("policies.diff.grantsRemoved", { count: d.grants_removed.length })}</h3>
                <ul className="space-y-1 font-mono text-xs" data-testid="grants-removed">
                  {d.grants_removed.map((g) => (
                    <li key={g}>
                      <del>{`- ${g}`}</del>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
            {d.lines_omitted ? (
              <p className="text-sm text-muted">{t("policies.diff.omitted")}</p>
            ) : (
              <pre tabIndex={0} className="max-h-96 overflow-auto rounded-md border border-line bg-bg p-2 font-mono text-xs" aria-label={t("policies.diff.lines")}>
                {d.lines.map((l, i) =>
                  l.op === "added" ? (
                    <ins key={i} className="block bg-accent/10 no-underline">{`+ ${l.text}`}</ins>
                  ) : l.op === "removed" ? (
                    <del key={i} className="block bg-danger-bg">{`- ${l.text}`}</del>
                  ) : (
                    <span key={i} className="block">{`  ${l.text}`}</span>
                  ),
                )}
              </pre>
            )}
            <p className="hint">{t("policies.diff.note", { from: shortSha(d.from_sha256) || t("policies.diff.empty"), to: shortSha(d.to_sha256) })}</p>
          </div>
        )}
      </QueryBlock>
    </section>
  );
}

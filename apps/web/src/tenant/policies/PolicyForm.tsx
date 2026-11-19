// Editor dạng form trên `PolicySource` (P4-T11, §7.2): luật grants (src/dst/ip/via; `app` chỉ hiển thị — sửa ở HuJSON),
// luật SSH (opt-in), autoApprovers, xác nhận luật (L4/L7/L10/L12/L13 kèm lý do). Phát hiện của báo cáo kiểm tra gần nhất
// hiện cạnh đúng luật (theo `path`). `onChange` undefined ⇒ chỉ đọc.
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import type { Catalog } from "./api";
import { FindingList } from "./FindingList";
import {
  ACK_RULES,
  emptyGrant,
  findingsAt,
  IP_PROTO_RE,
  MAX_ACK_REASON,
  MIN_ACK_REASON,
  OWNER_ACK_RULES,
  runeLength,
  splitTokens,
  SSH_USER_RE,
  type AckRule,
  type PolicyFinding,
  type PolicyGrant,
  type PolicyPrincipal,
  type PolicySSHRule,
  type PolicySource,
} from "./model";
import { PrincipalList } from "./PrincipalList";

export interface PolicyFormProps {
  source: PolicySource;
  onChange?: (next: PolicySource) => void;
  catalog: Catalog | undefined;
  extra: ReadonlyMap<string, string>;
  findings: readonly PolicyFinding[];
  /** luật mà báo cáo gần nhất đòi xác nhận */
  ackNeeded: readonly AckRule[];
}

export function PolicyForm({ source, onChange, catalog, extra, findings, ackNeeded }: PolicyFormProps) {
  const { t } = useTranslation();
  const grants = source.grants;
  const ssh = source.ssh ?? [];
  const set = (patch: Partial<PolicySource>) => onChange?.({ ...source, ...patch });
  const setGrant = (i: number, g: PolicyGrant) => {
    set({ grants: grants.map((x, j) => (j === i ? g : x)) });
  };
  const setRule = (i: number, r: PolicySSHRule) => {
    set({ ssh: ssh.map((x, j) => (j === i ? r : x)) });
  };
  return (
    <div className="space-y-4" data-testid="policy-form">
      <section aria-labelledby="pol-grants" className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 id="pol-grants" className="font-semibold">
            {t("policies.editor.grants")}
          </h3>
          {onChange ? (
            <button type="button" className="btn-secondary" onClick={() => set({ grants: [...grants, emptyGrant()] })}>
              {t("policies.editor.addGrant")}
            </button>
          ) : null}
        </div>
        {grants.length === 0 ? <p className="text-sm text-muted">{t("policies.editor.denyAll")}</p> : null}
        {grants.map((g, i) => (
          <GrantCard
            key={i}
            index={i}
            grant={g}
            onChange={onChange ? (next) => setGrant(i, next) : undefined}
            onRemove={onChange ? () => set({ grants: grants.filter((_, j) => j !== i) }) : undefined}
            catalog={catalog}
            extra={extra}
            findings={findingsAt(findings, `grants[${i}]`)}
          />
        ))}
      </section>

      <section aria-labelledby="pol-ssh" className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 id="pol-ssh" className="font-semibold">
            {t("policies.editor.ssh")}
          </h3>
          {onChange ? (
            <button type="button" className="btn-secondary" onClick={() => set({ ssh: [...ssh, { action: "accept", src: [], dst: [], users: [] }] })}>
              {t("policies.editor.addSsh")}
            </button>
          ) : null}
        </div>
        <p className="hint">{t("policies.editor.sshHint")}</p>
        {ssh.map((r, i) => (
          <SSHCard
            key={i}
            index={i}
            rule={r}
            onChange={onChange ? (next) => setRule(i, next) : undefined}
            onRemove={onChange ? () => set({ ssh: ssh.filter((_, j) => j !== i) }) : undefined}
            catalog={catalog}
            extra={extra}
            findings={findingsAt(findings, `ssh[${i}]`)}
          />
        ))}
      </section>

      <Approvers source={source} onChange={onChange ? set : undefined} catalog={catalog} extra={extra} findings={findingsAt(findings, "auto_approvers")} />

      <Acknowledgements source={source} onChange={onChange ? set : undefined} needed={ackNeeded} />
    </div>
  );
}

function GrantCard({
  index,
  grant,
  onChange,
  onRemove,
  catalog,
  extra,
  findings,
}: {
  index: number;
  grant: PolicyGrant;
  onChange?: (g: PolicyGrant) => void;
  onRemove?: () => void;
  catalog: Catalog | undefined;
  extra: ReadonlyMap<string, string>;
  findings: PolicyFinding[];
}) {
  const { t } = useTranslation();
  const n = index + 1;
  const p = `grants[${index}]`;
  const list = (k: "src" | "dst" | "via") => (onChange ? (ps: PolicyPrincipal[]) => onChange({ ...grant, [k]: ps }) : undefined);
  return (
    <section className="card space-y-3" aria-label={t("policies.editor.grantN", { n })} data-testid={`grant-${String(index)}`}>
      <div className="flex items-center justify-between gap-2">
        <h4 className="font-medium">{t("policies.editor.grantN", { n })}</h4>
        {onRemove ? (
          <button type="button" className="btn-secondary" onClick={onRemove} aria-label={t("policies.editor.removeGrant", { n })}>
            {t("policies.editor.remove")}
          </button>
        ) : null}
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        <PrincipalList label={t("policies.editor.srcN", { n })} position="grantSrc" value={grant.src} onChange={list("src")} catalog={catalog} extra={extra}
          invalid={findingsAt(findings, `${p}.src`).length > 0} />
        <PrincipalList label={t("policies.editor.dstN", { n })} position="grantDst" value={grant.dst} onChange={list("dst")} catalog={catalog} extra={extra}
          invalid={findingsAt(findings, `${p}.dst`).length > 0} />
      </div>
      <TokenField
        label={t("policies.editor.ipN", { n })}
        hint={t("policies.editor.ipHint")}
        value={grant.ip ?? []}
        valid={(x) => IP_PROTO_RE.test(x)}
        onChange={onChange ? (ip) => onChange({ ...grant, ip }) : undefined}
      />
      <PrincipalList label={t("policies.editor.viaN", { n })} position="via" value={grant.via ?? []} onChange={list("via")} catalog={catalog} extra={extra} />
      {grant.app && Object.keys(grant.app).length > 0 ? (
        <div>
          <p className="label">{t("policies.editor.app")}</p>
          <pre tabIndex={0} className="max-h-40 overflow-auto rounded-md border border-line bg-bg p-2 font-mono text-xs">
            {JSON.stringify(grant.app, null, 2)}
          </pre>
          <p className="hint">{t("policies.editor.appHint")}</p>
        </div>
      ) : null}
      <FindingList findings={findings} />
    </section>
  );
}

function SSHCard({
  index,
  rule,
  onChange,
  onRemove,
  catalog,
  extra,
  findings,
}: {
  index: number;
  rule: PolicySSHRule;
  onChange?: (r: PolicySSHRule) => void;
  onRemove?: () => void;
  catalog: Catalog | undefined;
  extra: ReadonlyMap<string, string>;
  findings: PolicyFinding[];
}) {
  const { t } = useTranslation();
  const id = useId();
  const n = index + 1;
  return (
    <section className="card space-y-3" aria-label={t("policies.editor.sshN", { n })}>
      <div className="flex items-center justify-between gap-2">
        <h4 className="font-medium">{t("policies.editor.sshN", { n })}</h4>
        {onRemove ? (
          <button type="button" className="btn-secondary" onClick={onRemove} aria-label={t("policies.editor.removeSsh", { n })}>
            {t("policies.editor.remove")}
          </button>
        ) : null}
      </div>
      <div>
        <label htmlFor={`${id}-action`} className="label">
          {t("policies.editor.sshAction")}
        </label>
        <select
          id={`${id}-action`}
          className="select"
          value={rule.action}
          disabled={!onChange}
          onChange={(e) => {
            const action = e.target.value as PolicySSHRule["action"];
            onChange?.(action === "check" ? { ...rule, action } : { action, src: rule.src, dst: rule.dst, users: rule.users });
          }}
        >
          <option value="accept">{t("policies.editor.sshActions.accept")}</option>
          <option value="check">{t("policies.editor.sshActions.check")}</option>
        </select>
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        <PrincipalList label={t("policies.editor.sshSrcN", { n })} position="sshSrc" value={rule.src} catalog={catalog} extra={extra}
          onChange={onChange ? (src) => onChange({ ...rule, src }) : undefined} />
        <PrincipalList label={t("policies.editor.sshDstN", { n })} position="sshDst" value={rule.dst} catalog={catalog} extra={extra}
          onChange={onChange ? (dst) => onChange({ ...rule, dst }) : undefined} />
      </div>
      <TokenField
        label={t("policies.editor.sshUsersN", { n })}
        hint={t("policies.editor.sshUsersHint")}
        value={rule.users}
        valid={(x) => SSH_USER_RE.test(x)}
        onChange={onChange ? (users) => onChange({ ...rule, users }) : undefined}
      />
      <FindingList findings={findings} />
    </section>
  );
}

function Approvers({
  source,
  onChange,
  catalog,
  extra,
  findings,
}: {
  source: PolicySource;
  onChange?: (patch: Partial<PolicySource>) => void;
  catalog: Catalog | undefined;
  extra: ReadonlyMap<string, string>;
  findings: PolicyFinding[];
}) {
  const { t } = useTranslation();
  const id = useId();
  const aa = source.auto_approvers ?? {};
  const routes = Object.entries(aa.routes ?? {});
  const [prefix, setPrefix] = useState("");
  const setAA = (next: typeof aa) => onChange?.({ auto_approvers: next });
  if (!onChange && routes.length === 0 && (aa.exit_node ?? []).length === 0) return null;
  return (
    <section aria-labelledby="pol-aa" className="card space-y-3">
      <h3 id="pol-aa" className="font-semibold">
        {t("policies.editor.autoApprovers")}
      </h3>
      <p className="hint">{t("policies.editor.autoApproversHint")}</p>
      {routes.map(([pf, ps]) => (
        <div key={pf} className="space-y-1">
          <PrincipalList
            label={t("policies.editor.routeApprovers", { prefix: pf })}
            position="approver"
            value={ps}
            catalog={catalog}
            extra={extra}
            onChange={onChange ? (next) => setAA({ ...aa, routes: { ...aa.routes, [pf]: next } }) : undefined}
          />
          {onChange ? (
            <button
              type="button"
              className="btn-secondary"
              onClick={() => {
                setAA({ ...aa, routes: Object.fromEntries(Object.entries(aa.routes ?? {}).filter(([k]) => k !== pf)) });
              }}
            >
              {t("policies.editor.removeRoute", { prefix: pf })}
            </button>
          ) : null}
        </div>
      ))}
      {onChange ? (
        <div className="flex flex-wrap items-end gap-2">
          <div>
            <label htmlFor={`${id}-prefix`} className="label">
              {t("policies.editor.routePrefix")}
            </label>
            <input
              id={`${id}-prefix`}
              className="input w-56 font-mono"
              value={prefix}
              spellCheck={false}
              placeholder="10.20.0.0/16"
              onChange={(e) => {
                setPrefix(e.target.value.trim());
              }}
            />
          </div>
          <button
            type="button"
            className="btn-secondary"
            disabled={!/^[0-9a-f.:]+\/\d{1,3}$/i.test(prefix) || (aa.routes ?? {})[prefix] !== undefined}
            onClick={() => {
              setAA({ ...aa, routes: { ...aa.routes, [prefix]: [] } });
              setPrefix("");
            }}
          >
            {t("policies.editor.addRoute")}
          </button>
        </div>
      ) : null}
      <PrincipalList
        label={t("policies.editor.exitApprovers")}
        position="approver"
        value={aa.exit_node ?? []}
        catalog={catalog}
        extra={extra}
        onChange={onChange ? (next) => setAA({ ...aa, exit_node: next }) : undefined}
      />
      <FindingList findings={findings} />
    </section>
  );
}

function Acknowledgements({ source, onChange, needed }: { source: PolicySource; onChange?: (patch: Partial<PolicySource>) => void; needed: readonly AckRule[] }) {
  const { t } = useTranslation();
  const id = useId();
  const acks = source.acknowledgements ?? [];
  const byRule = new Map(acks.map((a) => [a.rule, a.reason]));
  const setAck = (rule: AckRule, reason: string | null) => {
    const rest = acks.filter((a) => a.rule !== rule);
    const next = reason === null ? rest : [...rest, { rule, reason }].sort((a, b) => ACK_RULES.indexOf(a.rule) - ACK_RULES.indexOf(b.rule));
    onChange?.({ acknowledgements: next });
  };
  const shown = onChange ? ACK_RULES : ACK_RULES.filter((r) => byRule.has(r) || needed.includes(r));
  if (shown.length === 0) return null;
  return (
    <fieldset className="card space-y-3" data-testid="acks">
      <legend className="font-semibold">{t("policies.ack.title")}</legend>
      <p className="hint">{t("policies.ack.hint")}</p>
      {shown.map((rule) => {
        const on = byRule.has(rule);
        const reason = byRule.get(rule) ?? "";
        const short = runeLength(reason.trim()) < MIN_ACK_REASON;
        return (
          <div key={rule} className={needed.includes(rule) ? "rounded-md border border-warn/40 p-2" : "p-2"}>
            <label className="flex items-start gap-2">
              <input
                type="checkbox"
                checked={on}
                disabled={!onChange}
                onChange={(e) => {
                  setAck(rule, e.target.checked ? "" : null);
                }}
              />
              <span>
                <span className="font-medium">{t("policies.ack.rule", { rule })}</span>
                {" — "}
                {t(`policies.ack.desc.${rule}`)}
                {OWNER_ACK_RULES.includes(rule) ? <span className="ms-1 badge badge-warn">{t("policies.ack.ownerOnly")}</span> : null}
                {needed.includes(rule) ? <span className="ms-1 badge badge-warn">{t("policies.ack.needed")}</span> : null}
              </span>
            </label>
            {on ? (
              <div className="mt-2 ms-6">
                <label htmlFor={`${id}-${rule}`} className="label">
                  {t("policies.ack.reason", { rule })}
                </label>
                <textarea
                  id={`${id}-${rule}`}
                  className="input"
                  rows={2}
                  maxLength={MAX_ACK_REASON}
                  value={reason}
                  readOnly={!onChange}
                  aria-invalid={short}
                  aria-describedby={`${id}-${rule}-hint`}
                  onChange={(e) => {
                    setAck(rule, e.target.value);
                  }}
                />
                <p id={`${id}-${rule}-hint`} className={short ? "field-error" : "hint"}>
                  {t("policies.ack.reasonHint")}
                </p>
              </div>
            ) : null}
          </div>
        );
      })}
    </fieldset>
  );
}

/** Ô nhập danh sách token (cách nhau bởi dấu phẩy/khoảng trắng) — giữ văn bản đang gõ, đồng bộ lại khi giá trị đổi từ ngoài. */
export function TokenField({
  label,
  hint,
  value,
  valid,
  onChange,
}: {
  label: string;
  hint: string;
  value: readonly string[];
  valid: (token: string) => boolean;
  onChange?: (tokens: string[]) => void;
}) {
  const id = useId();
  const [text, setText] = useState(value.join(", "));
  const [shown, setShown] = useState(value.join("\u0000"));
  const joined = value.join("\u0000");
  if (joined !== shown && splitTokens(text).join("\u0000") !== joined) {
    // giá trị đổi từ ngoài (nhập HuJSON, tải lại) — điều chỉnh state trong lúc render
    setShown(joined);
    setText(value.join(", "));
  }
  const bad = splitTokens(text).filter((x) => !valid(x));
  return (
    <div>
      <label htmlFor={id} className="label">
        {label}
      </label>
      <input
        id={id}
        className="input font-mono"
        value={text}
        readOnly={!onChange}
        spellCheck={false}
        autoComplete="off"
        aria-invalid={bad.length > 0}
        aria-describedby={`${id}-hint`}
        onChange={(e) => {
          setText(e.target.value);
          const tokens = splitTokens(e.target.value);
          setShown(tokens.join("\u0000"));
          onChange?.(tokens);
        }}
      />
      <p id={`${id}-hint`} className={bad.length > 0 ? "field-error" : "hint"}>
        {hint}
        {bad.length > 0 ? <code className="ms-1">{bad.join(" ")}</code> : null}
      </p>
    </div>
  );
}

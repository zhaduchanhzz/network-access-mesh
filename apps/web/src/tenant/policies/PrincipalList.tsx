// Danh sách principal có kiểu của một vị trí (src/dst/via/SSH/autoApprovers — P4-T11): mỗi phần tử là {type, ref}
// chọn theo id từ danh mục của tenant (thành viên, group, tag; tài nguyên đã được tham chiếu), autogroup theo vị trí,
// hoặc địa chỉ/prefix gõ tay. Không bao giờ nhận chuỗi tự do cho user/group/tag/resource (§7.2).
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import type { Catalog } from "./api";
import { isCidrRef, POSITION_AUTOGROUPS, POSITION_TYPES, principalLabel, type PolicyPrincipal, type Position, type PrincipalType } from "./model";

export interface PrincipalListProps {
  label: string;
  position: Position;
  value: readonly PolicyPrincipal[];
  /** undefined ⇒ chỉ đọc */
  onChange?: (next: PolicyPrincipal[]) => void;
  catalog: Catalog | undefined;
  extra: ReadonlyMap<string, string>;
  invalid?: boolean;
}

const EMPTY_BOOK = { users: new Map<string, string>(), groups: new Map<string, string>(), tags: new Map<string, string>(), resources: new Map<string, string>() };

export function PrincipalList({ label, position, value, onChange, catalog, extra, invalid = false }: PrincipalListProps) {
  const { t } = useTranslation();
  const id = useId();
  const book = catalog?.book ?? EMPTY_BOOK;
  return (
    <fieldset className="min-w-0" aria-invalid={invalid || undefined} data-position={position}>
      <legend className="label">{label}</legend>
      {value.length === 0 ? (
        <p className="text-sm text-muted">{t("policies.editor.noPrincipal")}</p>
      ) : (
        <ul className="flex flex-wrap gap-1.5" aria-label={label}>
          {value.map((p, i) => {
            const name = principalLabel(p, book, extra);
            return (
              <li key={`${p.type}:${p.ref}:${String(i)}`} className="badge gap-1.5" data-principal-type={p.type}>
                <span className="font-mono">{name}</span>
                <span className="text-muted">{t(`policies.ptype.${p.type}`)}</span>
                {onChange ? (
                  <button
                    type="button"
                    className="rounded px-1 text-danger hover:bg-danger-bg"
                    aria-label={t("policies.editor.removePrincipal", { name, list: label })}
                    onClick={() => {
                      onChange(value.filter((_, j) => j !== i));
                    }}
                  >
                    {"×"}
                  </button>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
      {onChange ? <AddPrincipal id={id} label={label} position={position} value={value} onChange={onChange} catalog={catalog} extra={extra} /> : null}
    </fieldset>
  );
}

function AddPrincipal({
  id,
  label,
  position,
  value,
  onChange,
  catalog,
  extra,
}: Required<Pick<PrincipalListProps, "label" | "position" | "value" | "onChange" | "extra">> & { id: string; catalog: Catalog | undefined }) {
  const { t } = useTranslation();
  const types = POSITION_TYPES[position];
  const [type, setType] = useState<PrincipalType>(types[0] ?? "cidr");
  const [ref, setRef] = useState("");
  const options = choices(type, position, catalog, extra);
  const cidrBad = type === "cidr" && ref !== "" && !isCidrRef(ref.trim());
  const duplicate = value.some((p) => p.type === type && p.ref === ref.trim());
  const canAdd = ref.trim() !== "" && !cidrBad && !duplicate;
  const add = () => {
    if (!canAdd) return;
    onChange([...value, { type, ref: ref.trim() }]);
    setRef("");
  };
  return (
    <div className="mt-2 flex flex-wrap items-start gap-2">
      <select
        className="select"
        aria-label={t("policies.editor.principalType", { list: label })}
        value={type}
        onChange={(e) => {
          setType(e.target.value as PrincipalType);
          setRef("");
        }}
      >
        {types.map((x) => (
          <option key={x} value={x}>
            {t(`policies.ptype.${x}`)}
          </option>
        ))}
      </select>
      {type === "cidr" ? (
        <div>
          <input
            id={`${id}-cidr`}
            className="input w-56 font-mono"
            aria-label={t("policies.editor.principalValue", { list: label })}
            aria-invalid={cidrBad}
            aria-describedby={`${id}-cidr-hint`}
            value={ref}
            placeholder="10.0.0.0/24"
            spellCheck={false}
            autoComplete="off"
            onChange={(e) => {
              setRef(e.target.value);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                add();
              }
            }}
          />
          <p id={`${id}-cidr-hint`} className={cidrBad ? "field-error" : "hint"}>
            {t("policies.editor.cidrHint")}
          </p>
        </div>
      ) : options.length === 0 ? (
        <p className="pt-1 text-sm text-muted">{t(type === "resource" ? "policies.editor.noResources" : "policies.editor.noChoices")}</p>
      ) : (
        <select
          className="select max-w-full"
          aria-label={t("policies.editor.principalValue", { list: label })}
          value={ref}
          onChange={(e) => {
            setRef(e.target.value);
          }}
        >
          <option value="">{t("policies.editor.choose")}</option>
          {options.map((o) => (
            <option key={o.ref} value={o.ref}>
              {o.label}
            </option>
          ))}
        </select>
      )}
      <button type="button" className="btn-secondary" disabled={!canAdd} onClick={add} aria-label={t("policies.editor.addTo", { list: label })}>
        {t("policies.editor.add")}
      </button>
    </div>
  );
}

function choices(type: PrincipalType, position: Position, catalog: Catalog | undefined, extra: ReadonlyMap<string, string>) {
  switch (type) {
    case "user":
      return (catalog?.users ?? []).map((u) => ({ ref: u.id, label: u.label }));
    case "group":
      return (catalog?.groups ?? []).map((g) => ({ ref: g.id, label: `group:${g.name}` }));
    case "tag":
      return (catalog?.tags ?? []).map((g) => ({ ref: g.id, label: g.name }));
    case "resource":
      // danh mục tài nguyên chưa có API đọc (P4-T12): chỉ những tài nguyên đã được tham chiếu (tên do server trả)
      return [...extra.entries()].filter(([k]) => k.startsWith("resource/")).map(([k, name]) => ({ ref: k.slice("resource/".length), label: name }));
    case "autogroup":
      return (POSITION_AUTOGROUPS[position] ?? []).map((a) => ({ ref: a, label: `autogroup:${a}` }));
    case "cidr":
      return [];
  }
}

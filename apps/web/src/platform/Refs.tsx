// Tham chiếu tenant / host trong Platform Console (G4b-E12): hiện tên (kèm slug nhỏ) thay cho UUID — API trả
// `tenant_slug`/`tenant_name`/`host_name` cùng hàng; UUID vẫn ở tooltip và trong đích của link (người vận hành đối chiếu
// được). Thiếu nhãn (server cũ, tra không được) ⇒ UUID như trước.
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

export function TenantRef({ id, slug, name, block = false }: { id: string; slug?: string | null; name?: string | null; block?: boolean }) {
  const { t } = useTranslation();
  const label = name || slug;
  if (!label) {
    return (
      <Link to={`/platform/tenants/${id}`} className={`link font-mono text-xs${block ? " block" : ""}`}>
        {id}
      </Link>
    );
  }
  return (
    <span className={block ? "block" : undefined} data-testid="tenant-ref">
      <Link to={`/platform/tenants/${id}`} className="link" title={t("platform.idTooltip", { id })}>
        {label}
      </Link>
      {name && slug ? <code className="hint block">{slug}</code> : null}
    </span>
  );
}

export function HostRef({ id, name }: { id: string; name?: string | null }) {
  const { t } = useTranslation();
  return name ? (
    <Link to={`/platform/hosts/${id}`} className="link" title={t("platform.idTooltip", { id })} data-testid="host-ref">
      <code>{name}</code>
    </Link>
  ) : (
    <Link to={`/platform/hosts/${id}`} className="link font-mono text-xs">
      {id}
    </Link>
  );
}

// Trường form dùng chung (wizard tạo tenant của P4-T02 — chuyển ra đây ở P4-T03 để các form của Platform Console dùng
// một bản): nhãn gắn với ô, gợi ý và lỗi nối vào aria-describedby, aria-invalid khi có lỗi (§12.4 a11y). Lỗi là chuỗi đã
// dịch; kiểm tra phía client chỉ để hướng dẫn — server quyết định (422 kèm lỗi theo trường hiển thị trong ProblemAlert).
import { useId, type ReactNode } from "react";

function describedBy(id: string, hint?: string, error?: string): string | undefined {
  return [hint ? `${id}-hint` : "", error ? `${id}-err` : ""].filter(Boolean).join(" ") || undefined;
}

function Messages({ id, hint, error }: { id: string; hint?: string; error?: string }) {
  return (
    <>
      {hint ? (
        <p id={`${id}-hint`} className="hint">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={`${id}-err`} className="field-error">
          {error}
        </p>
      ) : null}
    </>
  );
}

export function TextField(props: {
  label: string;
  hint?: string;
  value: string;
  onChange: (v: string) => void;
  error?: string;
  type?: "text" | "email" | "url" | "password";
  /** bàn phím số trên thiết bị di động (giá trị vẫn là chuỗi — kiểm ở chỗ gọi) */
  numeric?: boolean;
  mono?: boolean;
  autoFocus?: boolean;
  /** textarea với số dòng này */
  rows?: number;
  maxLength?: number;
  readOnly?: boolean;
}): ReactNode {
  const id = useId();
  const common = {
    id,
    className: props.mono ? "input font-mono" : "input",
    value: props.value,
    spellCheck: false,
    autoFocus: props.autoFocus,
    maxLength: props.maxLength,
    readOnly: props.readOnly,
    "aria-invalid": props.error ? true : undefined,
    "aria-describedby": describedBy(id, props.hint, props.error),
  } as const;
  return (
    <div>
      <label htmlFor={id} className="label">
        {props.label}
      </label>
      {props.rows ? (
        <textarea
          {...common}
          rows={props.rows}
          onChange={(e) => {
            props.onChange(e.target.value);
          }}
        />
      ) : (
        <input
          {...common}
          type={props.type ?? "text"}
          inputMode={props.numeric ? "numeric" : undefined}
          autoComplete={props.type === "password" ? "new-password" : "off"}
          onChange={(e) => {
            props.onChange(e.target.value);
          }}
        />
      )}
      <Messages id={id} hint={props.hint} error={props.error} />
    </div>
  );
}

export function SelectField<V extends string>(props: {
  label: string;
  hint?: string;
  value: V;
  onChange: (v: V) => void;
  options: readonly { value: V; label: string }[];
  error?: string;
  autoFocus?: boolean;
}): ReactNode {
  const id = useId();
  return (
    <div>
      <label htmlFor={id} className="label">
        {props.label}
      </label>
      <select
        id={id}
        className="select w-full py-2"
        value={props.value}
        autoFocus={props.autoFocus}
        aria-invalid={props.error ? true : undefined}
        aria-describedby={describedBy(id, props.hint, props.error)}
        onChange={(e) => {
          const v = props.options.find((o) => o.value === e.target.value);
          if (v) props.onChange(v.value);
        }}
      >
        {props.options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <Messages id={id} hint={props.hint} error={props.error} />
    </div>
  );
}

export function CheckboxField(props: { label: string; checked: boolean; onChange: (v: boolean) => void; hint?: string }): ReactNode {
  const id = useId();
  return (
    <div>
      <div className="flex items-start gap-2">
        <input
          id={id}
          type="checkbox"
          className="mt-1"
          checked={props.checked}
          aria-describedby={props.hint ? `${id}-hint` : undefined}
          onChange={(e) => {
            props.onChange(e.target.checked);
          }}
        />
        <label htmlFor={id} className="text-sm">
          {props.label}
        </label>
      </div>
      <Messages id={id} hint={props.hint} />
    </div>
  );
}

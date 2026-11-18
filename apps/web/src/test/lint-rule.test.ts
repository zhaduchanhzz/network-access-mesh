// Rule meshguard/no-literal-ui-string bắt đúng chuỗi giao diện hardcode và bỏ qua ký hiệu/thuộc tính kỹ thuật.
import { RuleTester } from "eslint";
import { describe, it } from "vitest";
import rule from "../../eslint-rules/no-literal-ui-string.js";

RuleTester.describe = describe;
RuleTester.it = it;
RuleTester.itOnly = it.only;

const tester = new RuleTester({
  languageOptions: { ecmaVersion: 2024, sourceType: "module", parserOptions: { ecmaFeatures: { jsx: true } } },
});

tester.run("no-literal-ui-string", rule, {
  valid: [
    "<p>{t('a.b')}</p>",
    '<p>{" · "}</p>',
    '<p className="text-sm" id="x" data-testid="y">{": "}—</p>',
    '<a href="/login" aria-label={t("x")}>{t("y")}</a>',
    "<p>{`${a}:${b}`}</p>",
    "<p>123 · 4</p>",
  ],
  invalid: [
    { code: "<p>Xin chào</p>", errors: [{ messageId: "literal" }] },
    { code: '<p>{"Hello"}</p>', errors: [{ messageId: "literal" }] },
    { code: "<p>{ok ? 'Có' : t('x')}</p>", errors: [{ messageId: "literal" }] },
    { code: '<button aria-label="Đóng" />', errors: [{ messageId: "literal" }] },
    { code: '<input placeholder="Tìm kiếm" />', errors: [{ messageId: "literal" }] },
    { code: "<img alt={`Logo ${x}`} />", errors: [{ messageId: "literal" }] },
    { code: '<span title={"Tip"} />', errors: [{ messageId: "literal" }] },
  ],
});

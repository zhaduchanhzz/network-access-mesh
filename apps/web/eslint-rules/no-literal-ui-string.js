// Rule ESLint cục bộ meshguard/no-literal-ui-string (§12.4 "không hardcode chuỗi"): mọi chữ người dùng thấy phải đi
// qua i18n (t("…")). Báo lỗi khi có chữ cái (\p{L}) trong:
//   - JSXText:                       <p>Xin chào</p>
//   - chuỗi/template làm con JSX:    <p>{"Xin chào"}</p>, <p>{`Xin chào`}</p>, <p>{ok ? "Có" : "Không"}</p>
//   - thuộc tính hiển thị:           aria-label, aria-description, aria-valuetext, title, placeholder, alt, label
// Ký hiệu không có chữ cái (" · ", ": ", "—") được phép.
const LETTER = /\p{L}/u;
const UI_ATTRS = new Set(["aria-label", "aria-description", "aria-valuetext", "aria-roledescription", "title", "placeholder", "alt", "label"]);

function literalTexts(node) {
  if (!node) return [];
  switch (node.type) {
    case "Literal":
      return typeof node.value === "string" ? [node.value] : [];
    case "TemplateLiteral":
      return node.quasis.map((q) => q.value.cooked ?? "");
    case "ConditionalExpression":
      return [...literalTexts(node.consequent), ...literalTexts(node.alternate)];
    case "LogicalExpression":
      return [...literalTexts(node.left), ...literalTexts(node.right)];
    default:
      return [];
  }
}

export default {
  meta: {
    type: "problem",
    docs: { description: "Chuỗi giao diện phải đi qua i18n (react-i18next)" },
    messages: { literal: "Chuỗi giao diện hardcode {{text}} — dùng t(\"…\") với khóa trong src/i18n/locales/*.json" },
    schema: [],
  },
  create(context) {
    const report = (node, text) =>
      context.report({ node, messageId: "literal", data: { text: JSON.stringify(text.trim().slice(0, 40)) } });
    return {
      JSXText(node) {
        if (LETTER.test(node.value)) report(node, node.value);
      },
      JSXExpressionContainer(node) {
        if (node.parent?.type === "JSXAttribute") return;
        for (const s of literalTexts(node.expression)) if (LETTER.test(s)) report(node, s);
      },
      JSXAttribute(node) {
        const name = node.name.type === "JSXIdentifier" ? node.name.name : null;
        if (!name || !UI_ATTRS.has(name) || !node.value) return;
        const texts = node.value.type === "Literal" ? literalTexts(node.value) : literalTexts(node.value.expression);
        for (const s of texts) if (LETTER.test(s)) report(node, s);
      },
    };
  },
};

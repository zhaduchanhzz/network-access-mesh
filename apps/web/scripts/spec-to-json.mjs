// In api/openapi.yaml dưới dạng JSON do js-yaml (CORE_SCHEMA) đọc — CI so với cách tools/openapi_lint.py đọc cùng file
// (python3 tools/openapi_lint.py --compare-json …), để spec-lint không bao giờ kiểm một nội dung khác với nội dung mà
// openapi-typescript và oapi-codegen nhận được (P2-T02).
import { readFileSync } from "node:fs";
import yaml from "js-yaml";

const file = new URL("../../../api/openapi.yaml", import.meta.url);
const spec = yaml.load(readFileSync(file, "utf8"), { schema: yaml.CORE_SCHEMA });
process.stdout.write(JSON.stringify(spec));

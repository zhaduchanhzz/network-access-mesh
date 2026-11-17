#!/usr/bin/env python3
"""Spec-lint of the SaaS API contract api/openapi.yaml (task P2-T02) and of the RBAC seed generated from the
permission matrices (task P2-T07).

    python tools/openapi_lint.py                      # lint api/openapi.yaml against the master plan; exit 0 = pass
    python tools/openapi_lint.py --spec F --master M  # lint other files
    python tools/openapi_lint.py --partial --spec F   # lint a spec fragment (no row coverage, no generated files)
    python tools/openapi_lint.py --write              # regenerate database/seeds/rbac.sql and
                                                      #   internal/authz/operations_gen.go, then lint
    python tools/openapi_lint.py --list               # also list the operations and the coverage of §8.5/§8.6, §13.2
    python tools/openapi_lint.py --dump-json          # print the spec as parsed here (canonical JSON)
    python tools/openapi_lint.py --compare-json F     # fail unless F (the spec as JSON from another YAML parser) is equal

Rules, with their source in docs/planning/implementation-master-plan.md:
  - every operation has a unique lowerCamelCase operationId, exactly one x-permission, an x-task, an x-audit-action (§13.1)
  - x-permission is either a permission of the §8.5/§8.6 matrices whose "API action" column lists this method + path
    (and no other permission's row does), or a special value of §13.1 on an operation §13.1 allows it for; platform
    permissions only on /platform/..., tenant permissions only under /tenants/{tenantId}
  - the other direction (§13.1 "every row maps to at least one operationId"; a row is a permission key — rows that
    repeat a key are merged and must agree): a row without an operation fails once every task the §13.2
    traceability table assigns to its API actions is done in §20 ("**đã thực hiện…**"); before that it is reported
    by --list as coverage
  - x-own-resource: true <=> the permission row has a ○ cell; x-dual-control: true <=> 2P cells (§13.1)
  - x-permission-secondary on at most one operation (§13.1, §8.4 invariant 4)
  - the RBAC seed: every cell of §8.5/§8.6 is a known grant (✔, ○, 2P, G, G (Admin), —, or a listed conditional
    cell), the role columns are the roles of §8.4, platform roles hold only platform permissions (§8.4 invariant 2),
    a role that may give roles gives only roles strictly below it that hold nothing it lacks (§8.4 invariant 3, 3a),
    and database/seeds/rbac.sql + internal/authz/operations_gen.go equal what the master and the spec generate
  - x-task is a task ID of §20 and agrees with the endpoint -> task traceability table of §13.2
  - path rule: no segment mixes {param} with text and no ':' — actions are child segments /.../{id}/<action> (§13.1)
  - the tenant comes only from the path /tenants/{tenantId} (UUID): no tenant parameter in query, header or cookie, no
    tenant field in request bodies of tenant-scoped operations (§13.1); the only exception is the login slug of
    GET /auth/login (§8.3 step 1)
  - error responses (4xx, 5xx, default) are RFC 9457 application/problem+json with the Problem schema of §13.3, and
    every operation declares the error responses its kind needs (401, 403, 404, 422, 429, default)
  - public operations declare security: []; the others need the session cookie, unsafe methods also X-CSRF-Token (§8.3)
  - 202 responses carry Location; a POST answering 201/202 requires the Idempotency-Key header (§13.1)
  - list operations take limit (<= 200) + cursor and answer {items, next_cursor} (§13.1)

Standard library only. The spec is read with the small YAML subset parser below: block mappings and sequences, flow
collections on one line, plain/quoted scalars on one line, literal and folded block scalars. Anything else (anchors,
aliases, tags, directives, multi-line plain or quoted scalars, complex keys) is rejected with a line number, so the lint
never silently reads something different from what the code generators read; CI also compares the parse with js-yaml
(--compare-json).
"""
from __future__ import annotations

import argparse
import difflib
import json
import math
import pathlib
import re
import sys
from dataclasses import dataclass, field

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = ROOT / "api" / "openapi.yaml"
MASTER = ROOT / "docs" / "planning" / "implementation-master-plan.md"

# ====================================================================== YAML subset parser


class YamlError(ValueError):
    """The text is not in the YAML subset this parser accepts."""


_BLOCK_SCALARS = ("|", "|-", ">", ">-")
_BAD_PLAIN_START = set("&*!%@`|>")
_ESCAPES = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v", "f": "\f", "r": "\r",
            "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0", "L": " ",
            "P": " "}
_KEY = re.compile(r"(.*?):(?:[ \t]+|$)")


def _indent_of(line: str, lineno: int) -> int:
    n = len(line) - len(line.lstrip(" "))
    if line[n:n + 1] == "\t":
        raise YamlError(f"line {lineno}: tab in indentation")
    return n


def _is_blank(line: str) -> bool:
    s = line.strip()
    return not s or s.startswith("#")


def _strip_comment(text: str) -> str:
    """Drop a trailing comment (' #...') that is outside quoted scalars."""
    quote = None
    i = 0
    while i < len(text):
        c = text[i]
        if quote:
            if quote == '"' and c == "\\":
                i += 2
                continue
            if c == quote:
                if quote == "'" and text[i + 1:i + 2] == "'":
                    i += 2
                    continue
                quote = None
        elif c in "'\"" and (i == 0 or text[i - 1] in " \t[{,:"):
            quote = c
        elif c == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
        i += 1
    return text.rstrip()


def _quoted(text: str, pos: int, lineno: int) -> tuple[str, int]:
    """Parse the quoted scalar starting at text[pos]; return (value, index after the closing quote)."""
    q = text[pos]
    out: list[str] = []
    i = pos + 1
    while i < len(text):
        c = text[i]
        if q == "'":
            if c == "'":
                if text[i + 1:i + 2] == "'":
                    out.append("'")
                    i += 2
                    continue
                return "".join(out), i + 1
        elif c == '"':
            return "".join(out), i + 1
        elif c == "\\":
            e = text[i + 1:i + 2]
            if e in _ESCAPES:
                out.append(_ESCAPES[e])
                i += 2
                continue
            n = {"x": 2, "u": 4, "U": 8}.get(e)
            if n and re.fullmatch(r"[0-9A-Fa-f]{%d}" % n, text[i + 2:i + 2 + n]):
                out.append(chr(int(text[i + 2:i + 2 + n], 16)))
                i += 2 + n
                continue
            raise YamlError(f"line {lineno}: invalid escape \\{e} in double-quoted scalar")
        out.append(c)
        i += 1
    raise YamlError(f"line {lineno}: unterminated quoted scalar (multi-line quoted scalars are not supported)")


def _resolve(s: str):
    """YAML 1.2 core schema for plain scalars."""
    if s in ("", "~", "null", "Null", "NULL"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if re.fullmatch(r"[-+]?[0-9]+", s):
        return int(s)
    if re.fullmatch(r"0o[0-7]+", s):
        return int(s[2:], 8)
    if re.fullmatch(r"0x[0-9a-fA-F]+", s):
        return int(s[2:], 16)
    if re.fullmatch(r"[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?", s):
        return float(s)
    if s in (".inf", ".Inf", ".INF", "+.inf", "+.Inf", "+.INF"):
        return math.inf
    if s in ("-.inf", "-.Inf", "-.INF"):
        return -math.inf
    if s in (".nan", ".NaN", ".NAN"):
        return math.nan
    return s


def _plain(text: str, lineno: int):
    if text[0] in _BAD_PLAIN_START or text in ("-", "?", ":") or text.startswith(("- ", "? ", ": ")):
        raise YamlError(f"line {lineno}: unsupported plain scalar {text[:20]!r} (quote it)")
    if ": " in text or text.endswith(":"):
        raise YamlError(f"line {lineno}: ': ' inside a plain scalar (quote the value or use a block scalar)")
    return _resolve(text)


def _skip_ws(text: str, pos: int) -> int:
    while pos < len(text) and text[pos] in " \t":
        pos += 1
    return pos


def _flow_plain(text: str, pos: int, key: bool) -> tuple[str, int]:
    """Plain scalar inside a flow collection: ends at , [ ] { } or at ': ' (and at ':' for keys)."""
    i = pos
    while i < len(text):
        c = text[i]
        if c in ",[]{}":
            break
        if c == ":" and (key or i + 1 == len(text) or text[i + 1] in " \t,[]{}"):
            break
        if c == "#" and i > pos and text[i - 1] in " \t":
            break
        i += 1
    return text[pos:i].strip(), i


def _flow(text: str, pos: int, lineno: int):
    """Parse the flow node at text[pos] (one line); return (value, index after it)."""
    pos = _skip_ws(text, pos)
    c = text[pos:pos + 1]
    if c == "[":
        items: list = []
        pos = _skip_ws(text, pos + 1)
        while text[pos:pos + 1] != "]":
            v, pos = _flow(text, pos, lineno)
            items.append(v)
            pos = _skip_ws(text, pos)
            if text[pos:pos + 1] == ",":
                pos = _skip_ws(text, pos + 1)
            elif text[pos:pos + 1] != "]":
                raise YamlError(f"line {lineno}: expected ',' or ']' in flow sequence")
        return items, pos + 1
    if c == "{":
        obj: dict = {}
        pos = _skip_ws(text, pos + 1)
        while text[pos:pos + 1] != "}":
            if text[pos:pos + 1] in ("'", '"'):
                k, pos = _quoted(text, pos, lineno)
            else:
                k, pos = _flow_plain(text, pos, key=True)
                if not k or k[0] in _BAD_PLAIN_START:
                    raise YamlError(f"line {lineno}: unsupported key in flow mapping")
            pos = _skip_ws(text, pos)
            if text[pos:pos + 1] != ":":
                raise YamlError(f"line {lineno}: expected ':' after flow mapping key {k!r}")
            v, pos = _flow(text, pos + 1, lineno)
            if k in obj:
                raise YamlError(f"line {lineno}: duplicate key {k!r}")
            obj[k] = v
            pos = _skip_ws(text, pos)
            if text[pos:pos + 1] == ",":
                pos = _skip_ws(text, pos + 1)
            elif text[pos:pos + 1] != "}":
                raise YamlError(f"line {lineno}: expected ',' or '}}' in flow mapping")
        return obj, pos + 1
    if c in ("'", '"'):
        return _quoted(text, pos, lineno)
    if c == "":
        raise YamlError(f"line {lineno}: unexpected end of flow collection")
    s, pos = _flow_plain(text, pos, key=False)
    if s and (s[0] in _BAD_PLAIN_START or s.startswith(("- ", "? "))):
        raise YamlError(f"line {lineno}: unsupported plain scalar {s[:20]!r} in flow collection")
    return _resolve(s), pos


def _fold(lines: list[str]) -> str:
    """Folded block scalar: breaks between normal lines become spaces, n empty lines become n newlines."""
    out = ""
    started = prev_more = False
    empties = 0
    for ln in lines:
        if ln == "":
            empties += 1
            continue
        more = ln[:1] in (" ", "\t")
        if not started:
            out, started = "\n" * empties + ln, True
        elif more or prev_more:
            out += "\n" * (empties + 1) + ln
        elif empties:
            out += "\n" * empties + ln
        else:
            out += " " + ln
        empties, prev_more = 0, more
    return out


class _Parser:
    def __init__(self, text: str):
        self.lines = text.split("\n")
        self.i = 0

    def peek(self):
        j = self.i
        while j < len(self.lines) and _is_blank(self.lines[j]):
            j += 1
        return j if j < len(self.lines) else None

    def parse(self):
        j = self.peek()
        if j is None:
            return None
        if self.lines[j].strip().startswith(("%", "---", "...")):
            raise YamlError(f"line {j + 1}: directives and document markers are not supported")
        if _indent_of(self.lines[j], j + 1) != 0:
            raise YamlError(f"line {j + 1}: the top-level node must not be indented")
        value = self.node(0)
        j = self.peek()
        if j is not None:
            raise YamlError(f"line {j + 1}: unexpected content (check the indentation)")
        return value

    def node(self, indent: int):
        j = self.peek()
        text = self.lines[j].strip()
        if text == "-" or text.startswith("- "):
            return self.sequence(indent)
        return self.mapping(indent)

    def mapping(self, indent: int, first: tuple[str, int] | None = None) -> dict:
        out: dict = {}
        if first is not None:
            self.entry(out, first[0], indent, first[1])
        while True:
            j = self.peek()
            if j is None:
                break
            line = self.lines[j]
            ind = _indent_of(line, j + 1)
            if ind < indent:
                break
            if ind > indent:
                raise YamlError(f"line {j + 1}: unexpected indentation (multi-line plain scalars are not supported)")
            text = line[ind:]
            if text == "-" or text.startswith("- "):
                raise YamlError(f"line {j + 1}: sequence item where a mapping key was expected")
            self.i = j + 1
            self.entry(out, text, indent, j + 1)
        return out

    def entry(self, out: dict, text: str, indent: int, lineno: int) -> None:
        if text[0] in ("'", '"'):
            key, pos = _quoted(text, 0, lineno)
            rest = text[pos:]
            if not (rest == ":" or rest.startswith((": ", ":\t"))):
                raise YamlError(f"line {lineno}: expected ': ' after the quoted key")
            rest = rest[1:]
        else:
            m = _KEY.match(text)
            if not m or not m.group(1).strip() or text[0] in "?[{&*!|>@`%" or " #" in m.group(1):
                raise YamlError(f"line {lineno}: expected 'key: value'")
            key, rest = m.group(1).strip(), text[m.end():]
        if key in out:
            raise YamlError(f"line {lineno}: duplicate key {key!r}")
        out[key] = self.value(rest, indent, lineno)

    def value(self, rest: str, indent: int, lineno: int):
        rest = _strip_comment(rest.strip())
        if rest == "":
            j = self.peek()
            if j is None:
                return None
            ind = _indent_of(self.lines[j], j + 1)
            text = self.lines[j].strip()
            if ind > indent:
                return self.node(ind)
            if ind == indent and (text == "-" or text.startswith("- ")):
                return self.sequence(indent)
            return None
        if rest in _BLOCK_SCALARS:
            return self.block_scalar(rest, indent)
        return self.inline(rest, lineno)

    def inline(self, rest: str, lineno: int):
        if rest[0] in "[{":
            v, pos = _flow(rest, 0, lineno)
            if rest[pos:].strip():
                raise YamlError(f"line {lineno}: unexpected text after a flow collection")
            return v
        if rest[0] in ("'", '"'):
            v, pos = _quoted(rest, 0, lineno)
            if rest[pos:].strip():
                raise YamlError(f"line {lineno}: unexpected text after a quoted scalar")
            return v
        return _plain(rest, lineno)

    def sequence(self, indent: int) -> list:
        out: list = []
        while True:
            j = self.peek()
            if j is None:
                break
            line = self.lines[j]
            ind = _indent_of(line, j + 1)
            if ind < indent:
                break
            if ind > indent:
                raise YamlError(f"line {j + 1}: unexpected indentation in a sequence")
            text = line[ind:]
            if not (text == "-" or text.startswith("- ")):
                break
            self.i = j + 1
            item = text[1:].lstrip(" ")
            col = ind + len(text) - len(item)
            bare = _strip_comment(item)
            if bare == "":
                k = self.peek()
                nested = k is not None and _indent_of(self.lines[k], k + 1) > indent
                out.append(self.node(_indent_of(self.lines[k], k + 1)) if nested else None)
            elif bare == "-" or bare.startswith("- "):
                raise YamlError(f"line {j + 1}: nested compact sequences are not supported")
            elif bare in _BLOCK_SCALARS:
                out.append(self.block_scalar(bare, indent))
            elif self.is_key(bare):
                out.append(self.mapping(col, first=(item, j + 1)))
            else:
                out.append(self.inline(bare, j + 1))
        return out

    @staticmethod
    def is_key(text: str) -> bool:
        if text[0] in ("'", '"'):
            try:
                _, pos = _quoted(text, 0, 0)
            except YamlError:
                return False
            rest = text[pos:]
            return rest == ":" or rest.startswith((": ", ":\t"))
        return text[0] not in "[{" and _KEY.match(text) is not None

    def block_scalar(self, indicator: str, parent_indent: int) -> str:
        raw: list[str] = []
        block_indent = None
        while self.i < len(self.lines):
            line = self.lines[self.i]
            if line.strip() == "":
                raw.append("")
                self.i += 1
                continue
            ind = len(line) - len(line.lstrip(" "))
            if block_indent is None:
                if ind <= parent_indent:
                    break
                block_indent = ind
            elif ind < block_indent:
                break
            raw.append(line[block_indent:])
            self.i += 1
        while raw and raw[-1] == "":
            raw.pop()
        if not raw:
            return ""
        text = "\n".join(raw) if indicator[0] == "|" else _fold(raw)
        return text if indicator.endswith("-") else text + "\n"


def load_yaml(text: str):
    """Parse text in the supported YAML subset (raises YamlError)."""
    if text.startswith("﻿"):
        text = text[1:]
    return _Parser(text.replace("\r\n", "\n")).parse()


# ====================================================================== master plan: §8.5, §8.6, §13.2, §20


class MasterError(ValueError):
    """The master plan no longer has the shape this lint reads (a table or section moved)."""


TASK_RE = re.compile(r"\bP\d-T\d+[a-z]?\b")
PERM_RE = re.compile(r"(platform|tenant)\.[a-z_]+:[a-z_]+")
DONE_RE = re.compile(r"\*\*đã thực hiện")


def entry_path(scope: str, segs: tuple[str, ...]) -> str:
    """Full API path of a matrix entry: tenant rows are relative to /tenants/{tenantId}; '{}' becomes '{id}'."""
    tail = "".join("/" + ("{id}" if s == "{}" else s) for s in segs)
    return "/tenants/{tenantId}" + tail if scope == "tenant" else tail or "/"


def _row(line: str) -> list[str]:
    return [c.strip() for c in re.split(r"(?<!\\)\|", line.strip())[1:-1]]


def _split_top(text: str, sep: str) -> list[str]:
    """Split on sep outside `code spans` and (parentheses)."""
    parts, depth, code, start, i = [], 0, False, 0, 0
    while i < len(text):
        c = text[i]
        if c == "`":
            code = not code
        elif not code and c == "(":
            depth += 1
        elif not code and c == ")":
            depth = max(0, depth - 1)
        elif not code and depth == 0 and text.startswith(sep, i):
            parts.append(text[start:i])
            i += len(sep)
            start = i
            continue
        i += 1
    parts.append(text[start:])
    return parts


def _sections(lines: list[str]) -> dict[str, tuple[int, int]]:
    heads = [(i, ln) for i, ln in enumerate(lines) if re.match(r"#{2,3} (\d+(?:\.\d+)?)[. ]", ln)]
    out: dict[str, tuple[int, int]] = {}
    for k, (i, ln) in enumerate(heads):
        level = len(ln.split(" ", 1)[0])
        end = len(lines)
        for j, ln2 in heads[k + 1:]:
            if len(ln2.split(" ", 1)[0]) <= level:
                end = j
                break
        out.setdefault(re.match(r"#+ (\d+(?:\.\d+)?)", ln).group(1), (i, end))
    return out


def _table_with_header(lines: list[str], rng: tuple[int, int], header: str) -> tuple[list[str], list]:
    """(header cells, [(line number, cells)]) of the first table in rng whose header line starts with header."""
    start, end = rng
    for i in range(start, end):
        if lines[i].startswith(header):
            rows = []
            for n in range(i + 2, end):
                if not lines[n].startswith("|"):
                    break
                rows.append((n + 1, _row(lines[n])))
            return _row(lines[i]), rows
    raise MasterError(f"table with header {header!r} not found in lines {start + 1}-{end}")


def _table(lines: list[str], rng: tuple[int, int], header: str) -> list[tuple[int, list[str]]]:
    return _table_with_header(lines, rng, header)[1]


def _segments(path: str, tenant_relative: bool, keep_tenants: bool = False) -> tuple[str, ...]:
    """'/tenants/{tenantId}/devices/{id}' -> ('devices', '{}'): parameters become '{}'.

    tenant_relative strips the '/tenants/{tenantId}' prefix (the tenant root becomes () — or ('tenants',) when
    keep_tenants, the convention of the §13.2 traceability table)."""
    segs = [s for s in path.split("/") if s]
    if tenant_relative and segs[:1] == ["tenants"] and len(segs) >= 2 and segs[1].startswith("{"):
        segs = segs[2:] or (["tenants"] if keep_tenants else [])
    elif keep_tenants and segs == ["tenants"]:
        segs = ["tenants"]
    return tuple("{}" if s.startswith("{") else s for s in segs)


def _expand_optional(path: str) -> list[str]:
    m = re.fullmatch(r"(.*)\[(.*)\](.*)", path)
    return [m.group(1) + m.group(3), m.group(1) + m.group(2) + m.group(3)] if m else [path]


def _api_entries(cell: str, tenant_relative: bool) -> list[list[tuple[str, tuple[str, ...]]]]:
    """Parse the 'API action' cell of a permission row into (METHOD, segments) per ' / '-separated part.

    Handles '`GET` / `POST,PATCH /x`' (a bare method takes the next path), '`GET/POST /x`', '`/x[/{id}]`' (optional
    suffix), '`POST /x/{id}/approve`, `/reject`' (a one-segment continuation is a POST action next to the previous
    one) and '`GET /a`, `/a/b`' (a longer continuation keeps the previous method). Text in (parentheses) and after
    ' — ' is commentary."""
    text = cell
    while True:
        new = re.sub(r"\([^()]*\)", "", text)
        if new == text:
            break
        text = new
    text = text.split(" — ")[0]
    parts_text = _split_top(text, " / ")
    parts: list[list[tuple[str, tuple[str, ...]]]] = [[] for _ in parts_text]
    pending = None
    prev_segs: tuple[str, ...] | None = None
    prev_methods: set[str] | None = None
    for pi, pt in enumerate(parts_text):
        for tok in re.findall(r"`([^`]+)`", pt):
            m = re.fullmatch(r"([A-Z]+(?:[,/][A-Z]+)*)?\s*(/\S*)?", tok.strip())
            if not m or not (m.group(1) or m.group(2)):
                continue
            methods = set(re.split(r"[,/]", m.group(1))) if m.group(1) else None
            if m.group(2) is None:
                pending = (methods, pi)
                continue
            for p in _expand_optional(m.group(2)):
                segs = _segments(p, tenant_relative)
                if methods is not None:
                    ms = methods
                elif len([s for s in p.split("/") if s]) == 1 and prev_segs is not None:
                    base = prev_segs if prev_segs[-1:] == ("{}",) else prev_segs[:-1]
                    segs, ms = base + segs, {"POST"}
                else:
                    ms = prev_methods or {"GET"}
                if pending:
                    parts[pending[1]] += [(pm, segs) for pm in sorted(pending[0])]
                    pending = None
                parts[pi] += [(mm, segs) for mm in sorted(ms)]
                prev_segs, prev_methods = segs, ms
    return parts


def _expand_keys(cell: str) -> list[str]:
    keys, base = [], None
    for tok in re.findall(r"`([^`]+)`", cell):
        if tok.startswith(":") and base:
            keys.append(base + tok)
        elif PERM_RE.fullmatch(tok):
            base = tok.split(":")[0]
            keys.append(tok)
    return keys


@dataclass
class Permission:
    key: str
    scope: str
    lines: list[int] = field(default_factory=list)
    entries: set = field(default_factory=set)
    cells: list[str] = field(default_factory=list)
    columns: list[dict] = field(default_factory=list)   # {role column: cell} for every matrix row naming the key

    @property
    def own(self) -> bool:
        return any("○" in c for c in self.cells)

    def _allowed(self) -> list[str]:
        return [c.strip() for c in self.cells if c.strip() not in ("—", "-", "")]

    @property
    def dual_any(self) -> bool:
        return any("2P" in c for c in self._allowed())

    @property
    def dual_all(self) -> bool:
        allowed = self._allowed()
        return bool(allowed) and all(c.startswith("2P") for c in allowed)


@dataclass
class TraceRow:
    line: int
    text: str
    tasks: set
    selectors: list


ALIASES = {"idp": "identity-provider"}   # group names of §13.2 that differ from the path segment
WRITES = {"POST", "PUT", "PATCH", "DELETE"}
WRITE_WORDS = {"ghi", "tạo", "xóa", "suspend", "resume", "rename", "expire", "delete", "sync"}


def _selectors(seg: str) -> list[tuple[set | None, tuple[str, ...]]]:
    """Endpoint selectors named by one group of the §13.2 traceability table: `code` paths and the leading word.

    A group annotated '(đọc)' (read) only selects GET; '(ghi, …)' or a list of write verbs only selects writes."""
    sels: list[tuple[set | None, tuple[str, ...]]] = []
    m = re.match(r"\s*([a-z][\w-]*):\s", seg)
    prefix = m.group(1) if m else None
    restrict = None
    paren = re.search(r"\(([^()]*)\)", seg)
    if paren:
        words = [w.strip().strip("`") for w in paren.group(1).split(",")]
        if words == ["đọc"]:
            restrict = {"GET"}
        elif words[0] == "ghi" or all(w in WRITE_WORDS for w in words):
            restrict = WRITES
    prev: tuple[str, ...] | None = None
    for tok in re.findall(r"`([^`]+)`", seg):
        mm = re.fullmatch(r"(?:([A-Z]+(?:[,/][A-Z]+)*)\s+)?(\S+)", tok.strip())
        if not mm:
            continue
        methods = set(re.split(r"[,/]", mm.group(1))) if mm.group(1) else restrict
        path = mm.group(2)
        if path.startswith("/") and prev and len([s for s in path.split("/") if s]) == 1:
            segs = (prev if prev[-1:] == ("{}",) else prev[:-1]) + (path.strip("/"),)
        else:
            segs = _segments(path, tenant_relative=True, keep_tenants=True)
        prev = segs
        sels.append((methods, segs))
        if prefix and segs[:1] != (prefix,):
            sels.append((methods, (prefix,) + segs))
    lead = re.match(r"\s*([^`(:]*)", seg).group(1).strip()
    for alt in lead.split("/"):
        word = alt.strip().lower().replace(" ", "-")
        if word:
            sels.append((restrict, (ALIASES.get(word, word),)))
    return sels


def _selector_len(sel, method: str, segs: tuple[str, ...]) -> int:
    methods, s = sel
    if (methods and method not in methods) or len(s) > len(segs):
        return 0
    for a, b in zip(s, segs):
        if a == "<action>":
            if b == "{}":
                return 0
        elif a != b:
            return 0
    return len(s)


class Master:
    """The parts of the master plan the lint checks against."""

    def __init__(self, text: str):
        lines = text.splitlines()
        secs = _sections(lines)
        for need in ("8.4", "8.5", "8.6", "13.2", "20"):
            if need not in secs:
                raise MasterError(f"section §{need} not found")
        start, end = secs["20"]
        self.tasks = {_row(ln)[0] for ln in lines[start:end] if ln.startswith("| P") and TASK_RE.fullmatch(_row(ln)[0])}
        if len(self.tasks) < 50:
            raise MasterError(f"only {len(self.tasks)} task IDs parsed from §20 — parser out of date?")
        # a task is done when its Task cell carries the marker "**đã thực hiện…**" (partial markers such as
        # "**phần 1 đã thực hiện**" or "**một phần**" do not count)
        self.done = {_row(ln)[0] for ln in lines[start:end]
                     if ln.startswith("| P") and TASK_RE.fullmatch(_row(ln)[0]) and DONE_RE.search(_row(ln)[1])}
        # §8.4 role table: (scope, name, abbreviation, line)
        self.roles: list[tuple[str, str, str, int]] = []
        for lineno, cells in _table(lines, secs["8.4"], "| Phạm vi | Role |"):
            m = re.fullmatch(r"\*\*(.+?) \(([A-Z]{2})\)\*\*", cells[1])
            if not m:
                raise MasterError(f"line {lineno}: §8.4 role cell {cells[1]!r} is not '**Name (XY)**'")
            self.roles.append((cells[0].strip().lower(), m.group(1), m.group(2), lineno))
        self.staff_text = "\n".join(lines[secs["8.6"][0]:secs["8.6"][1]])
        self.columns: dict[str, list[str]] = {}
        self.perms: dict[str, Permission] = {}
        self._matrix(lines, secs["8.5"], "platform")
        self._matrix(lines, secs["8.6"], "tenant")
        self.trace: list[TraceRow] = []
        for lineno, cells in _table(lines, secs["13.2"], "| Nhóm endpoint |"):
            groups = _split_top(cells[0], ";")
            lists = [set(TASK_RE.findall(x)) for x in _split_top(cells[2], ";")]
            for k, g in enumerate(groups):
                tasks = lists[k] if len(lists) == len(groups) else set().union(*lists)
                self.trace.append(TraceRow(lineno, g.strip(), tasks, _selectors(g)))
        if len(self.trace) < 30:
            raise MasterError(f"only {len(self.trace)} groups parsed from the §13.2 traceability table")

    def _matrix(self, lines: list[str], rng: tuple[int, int], scope: str) -> None:
        header, rows = _table_with_header(lines, rng, "| Permission |")
        cols = header[2:]
        self.columns[scope] = cols
        for lineno, cells in rows:
            keys = _expand_keys(cells[0])
            parts = _api_entries(cells[1], tenant_relative=scope == "tenant")
            if len(cells) != len(header):
                raise MasterError(f"line {lineno}: {len(cells)} cells, the header of the {scope} matrix has {len(header)}")
            for idx, key in enumerate(keys):
                if not key.startswith(scope + "."):
                    raise MasterError(f"line {lineno}: {key} in the {scope} matrix")
                p = self.perms.setdefault(key, Permission(key, scope))
                p.lines.append(lineno)
                p.entries |= set(parts[idx] if len(parts) == len(keys) else [e for q in parts for e in q])
                colmap = {}
                for col, cell in zip(cols, cells[2:]):
                    sub = _split_top(cell, " / ")
                    value = sub[idx] if len(keys) > 1 and len(sub) == len(keys) else cell
                    p.cells.append(value)
                    colmap[col] = value.strip()
                p.columns.append(colmap)
        if len(rows) < 20:
            raise MasterError(f"only {len(rows)} rows parsed from the {scope} permission matrix")

    def row_tasks(self, p: Permission) -> set[str]:
        """Tasks that the §13.2 traceability table assigns to the API actions of a permission row."""
        out: set[str] = set()
        for method, segs in p.entries:
            out |= self.trace_candidates(method, entry_path(p.scope, segs))
        return out

    def permissions_for(self, scope: str, method: str, segs: tuple[str, ...]) -> set[str]:
        """Permissions whose API action column lists method + path (a collection row also covers its items)."""
        out = set()
        for key, p in self.perms.items():
            if p.scope != scope:
                continue
            for m, e in p.entries:
                if m == method and (segs == e or (segs[-1:] == ("{}",) and segs[:-1] == e and e[-1:] != ("{}",))):
                    out.add(key)
        return out

    def trace_candidates(self, method: str, path: str) -> set[str]:
        """Tasks of the §13.2 traceability groups whose most specific selector matches the endpoint."""
        segs = _segments(path, tenant_relative=True, keep_tenants=True)
        best, out = 0, set()
        for row in self.trace:
            n = max((_selector_len(s, method, segs) for s in row.selectors), default=0)
            if n and n > best:
                best, out = n, set(row.tasks)
            elif n and n == best:
                out |= row.tasks
        return out


# ====================================================================== spec checks

METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
UNSAFE = {"post", "put", "patch", "delete"}
PROBLEM = "application/problem+json"
PROBLEM_FIELDS = {"type", "title", "status", "detail", "instance", "code", "request_id", "errors"}   # §13.3
OPERATION_ID = re.compile(r"[a-z][A-Za-z0-9]*")
AUDIT_ACTION = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+")
SEGMENT = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
PARAM_SEGMENT = re.compile(r"\{([a-z][A-Za-z0-9]*)\}")
TENANTISH = re.compile(r"tenant", re.I)
# §13.1: `public` for auth/login and auth/callback; `authenticated` for auth/session, auth/sessions, auth/logout and
# GET /tenants; `internal` for routes that never pass the edge (healthz, readyz, metrics, internal/*)
SPECIAL = {
    "public": {("get", ("auth", "login")), ("get", ("auth", "callback", "{}"))},
    "authenticated": {("get", ("auth", "session")), ("get", ("auth", "sessions")),
                      ("delete", ("auth", "sessions", "{}")), ("post", ("auth", "logout")), ("get", ("tenants",))},
}
LOGIN_SLUG = ("get", "/auth/login", "query", "tenant")   # §8.3 step 1: the slug only routes the login


def operations(spec: dict):
    """(path, method, operation, path item) for every operation of the spec."""
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method in METHODS:
            if isinstance(item.get(method), dict):
                yield path, method, item[method], item


def _resolve_ref(spec: dict, node, seen=None):
    """Follow local $refs (#/...); non-local refs are reported by the caller as unresolvable (None)."""
    seen = seen or set()
    while isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/") or ref in seen:
            return None
        seen.add(ref)
        node = spec
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
    return node


def _schema_props(spec: dict, schema, seen: set) -> set[str]:
    """Every property name reachable from a schema (through $ref, allOf/anyOf/oneOf, items, properties)."""
    names: set[str] = set()
    if isinstance(schema, dict) and "$ref" in schema:
        if schema["$ref"] in seen:
            return names
        seen.add(schema["$ref"])
    schema = _resolve_ref(spec, schema)
    if not isinstance(schema, dict):
        return names
    for k, v in (schema.get("properties") or {}).items():
        names.add(k)
        names |= _schema_props(spec, v, seen)
    for k in ("allOf", "anyOf", "oneOf"):
        for s in schema.get(k) or []:
            names |= _schema_props(spec, s, seen)
    for k in ("items", "additionalProperties", "not"):
        if isinstance(schema.get(k), dict):
            names |= _schema_props(spec, schema[k], seen)
    return names


def lint(spec: dict, master: Master, coverage: bool = True) -> list[str]:
    """All problems of the spec, as 'where: message' strings (empty = pass). coverage=False skips the row -> operation
    direction (for a spec fragment that is not meant to contain every operation)."""
    errs: list[str] = []

    def err(where: str, msg: str) -> None:
        errs.append(f"{where}: {msg}")

    if not isinstance(spec, dict):
        return ["spec: not a mapping"]
    if not str(spec.get("openapi", "")).startswith("3.1."):
        err("openapi", "must be 3.1.x (§13.1)")
    if "/api/v1" not in [s.get("url") for s in spec.get("servers") or [] if isinstance(s, dict)]:
        err("servers", "must contain the url /api/v1 (§13.1)")
    comps = spec.get("components") or {}
    schemes = comps.get("securitySchemes") or {}
    session = {n for n, s in schemes.items()
               if s.get("type") == "apiKey" and s.get("in") == "cookie" and s.get("name") == "__Host-mg_session"}
    csrf = {n for n, s in schemes.items()
            if s.get("type") == "apiKey" and s.get("in") == "header" and s.get("name") == "X-CSRF-Token"}
    if not session:
        err("components.securitySchemes", "no apiKey scheme for the cookie __Host-mg_session (§8.3)")
    if not csrf:
        err("components.securitySchemes", "no apiKey scheme for the header X-CSRF-Token (§8.3 step 5)")
    problem = (comps.get("schemas") or {}).get("Problem")
    if not isinstance(problem, dict) or set(problem.get("properties") or {}) != PROBLEM_FIELDS:
        err("components.schemas.Problem", f"must have exactly the properties {sorted(PROBLEM_FIELDS)} (§13.1, §13.3)")

    seen_ids: dict[str, str] = {}
    secondary: list[str] = []
    count = 0
    for path, method, op, item in operations(spec):
        count += 1
        oid = op.get("operationId")
        where = f"{method.upper()} {path} ({oid or 'no operationId'})"

        # ---- operationId
        if not isinstance(oid, str) or not OPERATION_ID.fullmatch(oid):
            err(where, "operationId missing or not lowerCamelCase")
        elif oid in seen_ids:
            err(where, f"duplicate operationId (also {seen_ids[oid]})")
        else:
            seen_ids[oid] = where

        # ---- path grammar (§13.1: actions are child segments)
        raw_segs = path.strip("/").split("/") if path != "/" else []
        names: list[str] = []
        if not path.startswith("/") or (path != "/" and path.endswith("/")):
            err(where, "path must start with '/' and must not end with '/'")
        for seg in raw_segs:
            pm = PARAM_SEGMENT.fullmatch(seg)
            if pm:
                names.append(pm.group(1))
            elif "{" in seg or "}" in seg:
                err(where, f"segment {seg!r} mixes a {{param}} with text — an action is a child segment "
                           f"/…/{{id}}/<action> (§13.1)")
            elif ":" in seg:
                err(where, f"segment {seg!r} contains ':' — an action is a child segment /…/{{id}}/<action> (§13.1)")
            elif not SEGMENT.fullmatch(seg):
                err(where, f"segment {seg!r} is not lowercase kebab-case")
        if len(set(names)) != len(names):
            err(where, "duplicate path parameter names")

        # ---- parameters (path item + operation; the operation wins on the same name+in)
        params: dict[tuple[str, str], dict] = {}
        for raw in (item.get("parameters") or []) + (op.get("parameters") or []):
            p = _resolve_ref(spec, raw)
            if not isinstance(p, dict) or "name" not in p or "in" not in p:
                err(where, f"unresolvable or malformed parameter {raw!r}")
                continue
            params[(p["in"], p["name"])] = p
        declared = {n: p for (loc, n), p in params.items() if loc == "path"}
        for n in names:
            if n not in declared:
                err(where, f"path parameter {{{n}}} is not declared")
        for n, p in declared.items():
            if n not in names:
                err(where, f"declared path parameter {n!r} is not in the path")
            if p.get("required") is not True:
                err(where, f"path parameter {n!r} must be required")
            sch = _resolve_ref(spec, p.get("schema")) or {}
            if n.endswith("Id") and (sch.get("type") != "string" or sch.get("format") != "uuid"):
                err(where, f"path parameter {n!r} must be a UUID string (§13.1, §13.2)")

        # ---- tenant context only from the path (§13.1)
        tenant_scoped = raw_segs[:1] == ["tenants"] and len(raw_segs) >= 2
        if tenant_scoped and raw_segs[1] != "{tenantId}":
            err(where, "the tenant segment must be the path parameter {tenantId} (§13.1)")
        for (loc, n), p in params.items():
            if loc in ("query", "header", "cookie") and TENANTISH.search(n) and (method, path, loc, n) != LOGIN_SLUG:
                err(where, f"tenant taken from the {loc} parameter {n!r} — the tenant comes only from the path "
                           f"{{tenantId}} (§13.1)")
        body = _resolve_ref(spec, op.get("requestBody"))
        if op.get("requestBody") is not None and not isinstance(body, dict):
            err(where, "unresolvable requestBody")
            body = None
        if tenant_scoped and body:
            for ct, media in (body.get("content") or {}).items():
                bad = sorted(n for n in _schema_props(spec, (media or {}).get("schema"), set()) if TENANTISH.search(n))
                if bad:
                    err(where, f"request body ({ct}) carries tenant field(s) {bad} — the tenant comes only from "
                               f"the path (§13.1)")

        # ---- x-permission (§13.1, §8.4 invariant 4, §8.5, §8.6)
        perm = op.get("x-permission")
        msegs = _segments(path, tenant_relative=tenant_scoped)
        nsegs = _segments(path, tenant_relative=False, keep_tenants=True)
        own, dual = op.get("x-own-resource"), op.get("x-dual-control")
        for flag, v in (("x-own-resource", own), ("x-dual-control", dual)):
            if v is not None and v is not True:
                err(where, f"{flag} must be true when present")
        if perm is None:
            err(where, "missing x-permission — every operation declares exactly one (§13.1, §8.4 invariant 4)")
        elif not isinstance(perm, str):
            err(where, f"x-permission must be exactly one permission, got {perm!r}")
            perm = None   # the remaining checks treat it as missing
        elif perm in SPECIAL or perm == "internal":
            if perm == "internal":
                if raw_segs[:1] in (["tenants"], ["platform"], ["auth"]):
                    err(where, "x-permission internal is only for routes that never pass the edge (§13.1)")
            elif (method, nsegs) not in SPECIAL[perm]:
                err(where, f"x-permission {perm} is not allowed on this operation (§13.1 allows it only on "
                           f"{sorted('/'.join(s) for _, s in SPECIAL[perm])})")
            if own or dual:
                err(where, "x-own-resource/x-dual-control only apply to permissions of §8.5/§8.6")
        elif perm not in master.perms:
            err(where, f"x-permission {perm!r} is not a permission of the §8.5/§8.6 matrices")
        else:
            p = master.perms[perm]
            in_scope = (p.scope == "platform" and raw_segs[:1] == ["platform"]) or (p.scope == "tenant" and tenant_scoped)
            if not in_scope:
                err(where, f"{p.scope} permission {perm} on a path outside "
                           f"{'/platform' if p.scope == 'platform' else '/tenants/{tenantId}'}")
            else:
                listed = master.permissions_for(p.scope, method.upper(), msegs)
                shown = "/" + "/".join(msegs)
                if perm not in listed:
                    err(where, f"{method.upper()} {shown} is not in the API action column of {perm} "
                               f"(master line {', '.join(map(str, p.lines))})")
                if listed - {perm}:
                    err(where, f"{method.upper()} {shown} is also listed under {sorted(listed - {perm})} — an "
                               f"operation belongs to exactly one row of §8.5/§8.6")
            if p.own and own is not True:
                err(where, f"x-own-resource: true required — the row of {perm} has a ○ cell (§13.1)")
            if own is True and not p.own:
                err(where, f"x-own-resource set but the row of {perm} has no ○ cell (§13.1)")
            if p.dual_all and dual is not True:
                err(where, f"x-dual-control: true required — {perm} is 2P (§13.1)")
            if dual is True and not p.dual_any:
                err(where, f"x-dual-control set but {perm} has no 2P cell (§13.1)")
        if op.get("x-permission-secondary") is not None:
            secondary.append(where)
            if op["x-permission-secondary"] not in master.perms:
                err(where, f"x-permission-secondary {op['x-permission-secondary']!r} is not a permission of §8.5/§8.6")

        # ---- x-task (§20, §13.2 traceability)
        task = op.get("x-task")
        if task is None:
            err(where, "missing x-task (a task ID of §20 that builds this operation)")
        elif not isinstance(task, str) or task not in master.tasks:
            err(where, f"x-task {task!r} is not a task ID of §20")
        else:
            cands = master.trace_candidates(method.upper(), path)
            if not cands:
                err(where, "no group of the §13.2 traceability table covers this endpoint")
            elif task not in cands:
                err(where, f"x-task {task} does not match the §13.2 traceability table (expected one of "
                           f"{', '.join(sorted(cands))})")

        # ---- x-audit-action (§13.1)
        aa = op.get("x-audit-action")
        if not isinstance(aa, str) or not AUDIT_ACTION.fullmatch(aa):
            err(where, f"x-audit-action missing or not a dotted lowercase action like device.rename (got {aa!r})")

        # ---- security (§8.3)
        reqs = op["security"] if "security" in op else spec.get("security")
        if perm == "public":
            if op.get("security") != []:
                err(where, "a public operation must declare security: []")
        elif perm != "internal":
            if not reqs:
                err(where, "must require the session cookie (security) — §8.3")
            for req in reqs or []:
                if not set(req or {}) & session:
                    err(where, "every security requirement must include the session cookie (§8.3)")
                elif method in UNSAFE and not set(req) & csrf:
                    err(where, "an unsafe method must also require the X-CSRF-Token header (§8.3 step 5)")

        # ---- responses: problem+json errors, 202 Location (§13.1)
        responses = op.get("responses") or {}
        codes = {str(c) for c in responses}
        if not responses:
            err(where, "no responses")
        for code, raw in responses.items():
            code = str(code)
            r = _resolve_ref(spec, raw)
            if not isinstance(r, dict):
                err(where, f"response {code} is unresolvable")
                continue
            content = r.get("content") or {}
            if code == "default" or code[:1] in ("4", "5"):
                if set(content) != {PROBLEM}:
                    err(where, f"error response {code} must be {PROBLEM} only (RFC 9457, §13.1), got "
                               f"{sorted(content) or 'no content'}")
                elif (content[PROBLEM] or {}).get("schema", {}).get("$ref") != "#/components/schemas/Problem":
                    err(where, f"error response {code} must use the schema #/components/schemas/Problem")
            elif PROBLEM in content:
                err(where, f"success response {code} must not be {PROBLEM}")
            if code == "202" and "Location" not in (r.get("headers") or {}):
                err(where, "a 202 response must carry Location of the job (§13.1)")
        needed = {"429", "default"}
        if perm not in ("public", "internal"):
            needed.add("401")
        if perm in master.perms or (method in UNSAFE and perm == "authenticated"):
            needed.add("403")
        if names:
            needed.add("404")
        if body or any(loc in ("query", "header") for loc, _ in params):
            needed.add("422")
        if needed - codes:
            err(where, f"missing error response(s) {sorted(needed - codes)}")

        # ---- Idempotency-Key (§13.1)
        if method == "post" and codes & {"201", "202"}:
            key = params.get(("header", "Idempotency-Key"))
            if not key or key.get("required") is not True:
                err(where, "a POST that creates a resource or job must require the Idempotency-Key header (§13.1)")

        # ---- cursor pagination (§13.1)
        query = {n: p for (loc, n), p in params.items() if loc == "query"}
        if "cursor" in query or "limit" in query:
            if not {"cursor", "limit"} <= set(query):
                err(where, "a list operation takes both limit and cursor (§13.1)")
            else:
                lim = _resolve_ref(spec, query["limit"].get("schema")) or {}
                if not isinstance(lim.get("maximum"), int) or lim["maximum"] > 200:
                    err(where, "limit must have maximum <= 200 (§13.1)")
            ok = _resolve_ref(spec, responses.get("200")) or {}
            sch = _resolve_ref(spec, ((ok.get("content") or {}).get("application/json") or {}).get("schema")) or {}
            if not {"items", "next_cursor"} <= set(sch.get("required") or []):
                err(where, "a list operation answers {items, next_cursor} (§13.1)")

    if len(secondary) > 1:
        err("x-permission-secondary", f"allowed on at most one operation (§13.1), found on {secondary}")
    if count == 0:
        err("paths", "no operations")
    if coverage:
        errs += row_coverage(spec, master)[0]
    return errs


def _used_permissions(spec: dict) -> set[str]:
    """x-permission values of the spec's operations (malformed values are reported by lint(), not here)."""
    return {p for _, _, op, _ in operations(spec) if isinstance(p := op.get("x-permission"), str)}


def coverage(spec: dict, master: Master) -> tuple[list[str], list[str]]:
    """Permissions of §8.5/§8.6 and §13.2 traceability groups that no operation uses yet (later phases)."""
    used_perms = _used_permissions(spec)
    perms = sorted(k for k in master.perms if k not in used_perms)
    groups = []
    for row in master.trace:
        hit = any(_selector_len(s, m.upper(), _segments(p, True, True)) for p, m, _, _ in operations(spec)
                  for s in row.selectors)
        if not hit:
            groups.append(f"{row.text} ({', '.join(sorted(row.tasks))})")
    return perms, groups


def row_coverage(spec: dict, master: Master) -> tuple[list[str], list[str]]:
    """Second direction of §13.1 ("every row maps to at least one operationId"), row = permission key.

    Returns (errors, notes): a row without an operation is an error only when the §13.2 traceability table assigns
    its API actions to tasks that are ALL done in §20 (nothing left that could still build it); otherwise it is a
    coverage note — pending work of a later task, or an API action no traceability group covers (a master gap)."""
    used = _used_permissions(spec)
    errors, notes = [], []
    for key, p in sorted(master.perms.items()):
        if key in used:
            continue
        tasks = master.row_tasks(p)
        where = f"§8.5/§8.6 {key} (master line {', '.join(map(str, p.lines))})"
        if not tasks:
            notes.append(f"{where}: no §13.2 traceability group covers its API actions — task unknown")
        elif tasks <= master.done:
            errors.append(f"{where}: no operation declares this permission although every task building it "
                          f"({', '.join(sorted(tasks))}) is done in §20 — §13.1: every row maps to at least one "
                          f"operationId")
        else:
            notes.append(f"{where}: no operation yet — {', '.join(sorted(tasks - master.done))} pending")
    return errors, notes


# ====================================================================== RBAC seed and authz table (P2-T07)
#
# The roles, permissions and grants of the database are generated from §8.4–§8.6 (database/seeds/rbac.sql) and the
# authorization contract of every operation from the spec (internal/authz/operations_gen.go): `--write` regenerates
# both, every other run fails when the committed files differ from what the master and the spec generate.

SEED_FILE = "database/seeds/rbac.sql"
OPS_FILE = "internal/authz/operations_gen.go"
# roles.key of the §8.4 roles (the master names roles, P2-T07 fixes the keys); internal/authz has the same constants
ROLE_KEYS = {"SA": "super_admin", "PO": "platform_operator", "PS": "platform_support", "PV": "platform_viewer",
             "TO": "tenant_owner", "TA": "tenant_admin", "TP": "tenant_operator", "TV": "tenant_viewer",
             "EU": "end_user"}
# the two system roles of scope support named in §8.6 (column Staff): key, name, rank
SUPPORT_ROLES = (("support_admin", "Support Admin", 2), ("support_operator", "Support Operator", 1))
STAFF_CELLS = {"G": ("support_operator", "support_admin"), "G (Admin)": ("support_admin",)}
NO_GRANT = {"—", "-"}
# matrix cell -> (role_permissions.scope, role_permissions.condition). 2P is an ordinary grant: the second person
# is demanded by the operation (x-dual-control, §13.1). A conditional cell becomes a grant with a condition that
# internal/authz refuses until the operation declares it handles it. Any other cell text is an error.
CELL_GRANTS = {
    "✔": ("any", None),
    "2P": ("any", None),
    "○": ("own", None),
    "✔ (nếu tenant cho phép self-enroll)": ("any", "self_enroll"),
    "✔ (không gồm role SA)": ("any", "excludes_super_admin"),
    "✔ (IdP của tenant: 2P)": ("any", "tenant_idp_dual_control"),
    "chỉ cho restore": ("any", "restore_only"),
}
# permissions that let a role give roles to others (§8.4 invariant 3, 3a)
ASSIGN_PERMISSIONS = {"tenant": {"tenant.user:manage", "tenant.membership:assign", "tenant.invitation:manage"},
                      "platform": {"platform.user:assign"}}
SCOPE_ORDER = {"platform": 0, "tenant": 1, "support": 2}


@dataclass(frozen=True)
class Role:
    scope: str
    key: str
    name: str
    rank: int          # higher = more senior within the scope (column order of §8.5/§8.6)


@dataclass(frozen=True)
class Grant:
    role: str          # roles.key
    permission: str
    scope: str = "any"
    condition: str | None = None


@dataclass
class RbacModel:
    roles: list        # [Role] sorted by scope, rank descending
    permissions: list  # [(key, scope, description)] sorted by key
    grants: list       # [Grant] sorted like the seed

    def role(self, key: str) -> Role:
        return next(r for r in self.roles if r.key == key)

    def grants_of(self, key: str) -> dict[str, Grant]:
        return {g.permission: g for g in self.grants if g.role == key}


def rbac_model(master: Master) -> tuple[RbacModel, list[str]]:
    """The seed implied by §8.4–§8.6, and the problems that make it ambiguous (unknown cells, contradicting rows)."""
    problems: list[str] = []
    roles: list[Role] = []
    by_abbr: dict[str, Role] = {}
    for scope in ("platform", "tenant"):
        listed = [(name, abbr, line) for s, name, abbr, line in master.roles if s == scope]
        for i, (name, abbr, line) in enumerate(listed):
            if abbr not in ROLE_KEYS:
                problems.append(f"§8.4 line {line}: role {abbr} has no roles.key in ROLE_KEYS of tools/openapi_lint.py")
                continue
            by_abbr[abbr] = Role(scope, ROLE_KEYS[abbr], name, len(listed) - i)
            roles.append(by_abbr[abbr])
    for key, name, rank in SUPPORT_ROLES:
        if f"`{key}`" not in master.staff_text:
            problems.append(f"§8.6 no longer names the support role `{key}` (column Staff)")
        roles.append(Role("support", key, name, rank))
    for scope, section in (("platform", "§8.5"), ("tenant", "§8.6")):
        want = [a for s, _, a, _ in master.roles if s == scope] + (["Staff"] if scope == "tenant" else [])
        if master.columns.get(scope) != want:
            problems.append(f"{section}: role columns {master.columns.get(scope)} differ from the roles of §8.4 {want}")

    grants: list[Grant] = []
    permissions = []
    for key, p in sorted(master.perms.items()):
        desc = ", ".join(sorted(f"{m} {entry_path(p.scope, segs)}" for m, segs in p.entries))
        permissions.append((key, p.scope, desc))
        merged: dict[str, set] = {}
        for colmap in p.columns:
            for col, cell in colmap.items():
                merged.setdefault(col, set()).add(cell)
        where = f"{key} (master line {', '.join(map(str, p.lines))})"
        for col in master.columns[p.scope]:
            cells = merged.get(col, set())
            if len(cells) != 1:
                problems.append(f"{where}: the rows of this permission disagree in column {col}: {sorted(cells)}")
                continue
            cell = next(iter(cells))
            if cell in NO_GRANT:
                continue
            if col == "Staff":
                if cell not in STAFF_CELLS:
                    problems.append(f"{where}: unknown cell {cell!r} in column Staff (expected G, G (Admin) or —)")
                    continue
                grants += [Grant(k, key) for k in STAFF_CELLS[cell]]
            elif col in by_abbr:
                if cell not in CELL_GRANTS:
                    problems.append(f"{where}: unknown cell {cell!r} in column {col} — add its meaning to CELL_GRANTS "
                                    f"of tools/openapi_lint.py")
                    continue
                scope, cond = CELL_GRANTS[cell]
                grants.append(Grant(by_abbr[col].key, key, scope, cond))
    rank = {r.key: r for r in roles}
    grants.sort(key=lambda g: (SCOPE_ORDER[rank[g.role].scope], -rank[g.role].rank, g.permission))
    roles.sort(key=lambda r: (SCOPE_ORDER[r.scope], -r.rank))
    return RbacModel(roles, permissions, grants), problems


def _covers(have: Grant | None, need: Grant) -> bool:
    """have grants at least what need grants: scope any covers own; an unconditional grant covers a conditional one."""
    return (have is not None and (have.scope == "any" or need.scope == "own")
            and (have.condition is None or have.condition == need.condition))


def lattice_problems(model: RbacModel) -> list[str]:
    """§8.4 invariant 3 on the seed: a role that may give roles (ASSIGN_PERMISSIONS) may give only roles strictly
    below it (3a), and none of those may hold a grant the giver does not hold — no role can grant more than it has.
    Grants of one scope never cross into another (invariant 2: platform roles hold no tenant permission)."""
    problems = []
    for g in model.grants:
        r = model.role(g.role)
        perm_scope = g.permission.split(".", 1)[0]
        if (r.scope == "platform") != (perm_scope == "platform"):
            problems.append(f"{r.key} ({r.scope}) holds {g.permission}: §8.4 invariant 2 — platform roles hold only "
                            f"platform permissions, tenant and support roles only tenant permissions")
        if g.scope == "own" and r.scope != "tenant":
            problems.append(f"{r.key} holds {g.permission} on own resources: ○ exists only for tenant roles")
    for scope, assign in ASSIGN_PERMISSIONS.items():
        roles = [r for r in model.roles if r.scope == scope]
        for giver in roles:
            have = model.grants_of(giver.key)
            if not assign & set(have):
                continue
            for r in roles:
                if r.rank >= giver.rank:
                    continue
                extra = sorted(k for k, g in model.grants_of(r.key).items() if not _covers(have.get(k), g))
                if extra:
                    problems.append(f"§8.4 invariant 3: {giver.key} may give {r.key} (strictly lower) but {r.key} "
                                    f"holds {extra} beyond {giver.key} — no role can grant more than it has")
    return problems


def _sql(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return "'" + str(v).replace("'", "''") + "'"


def _values(rows: list[tuple]) -> str:
    return ",\n".join("    (" + ", ".join(_sql(v) for v in row) + ")" for row in rows)


def render_seed_sql(model: RbacModel) -> str:
    """database/seeds/rbac.sql: idempotent, one transaction (store.Seed), run by mg_migrator after the migrations."""
    roles = [(r.scope, r.key, r.name, r.rank) for r in model.roles]
    scope_of = {r.key: r.scope for r in model.roles}
    grants = [(scope_of[g.role], g.role, g.permission, g.scope, g.condition) for g in model.grants]
    return f"""\
-- Code generated by tools/openapi_lint.py --write from docs/planning/implementation-master-plan.md. DO NOT EDIT.
--
-- Seed RBAC (P2-T07) sinh từ §8.4 (role) và ma trận §8.5/§8.6 — không sửa tay: sửa master rồi chạy
-- `make authz-gen`; spec-lint trong CI fail khi file này lệch với nội dung master sinh ra. store.Migrate áp file
-- này sau migration, bằng mg_migrator, trong một transaction, idempotent: role hệ thống, permission và grant của
-- chúng sau khi chạy đúng bằng các bảng dưới. Ô của ma trận: ✔ và 2P = grant scope any (người thứ hai của 2P do
-- operation đòi qua x-dual-control — §13.1); ○ = grant scope own; G / G (Admin) = grant cho support_operator và
-- support_admin / chỉ support_admin (§8.6); ô có điều kiện = grant kèm condition, internal/authz từ chối grant đó
-- cho tới khi operation khai báo xử lý điều kiện (fail-closed).

-- permissions ({len(model.permissions)}): mọi khóa của §8.5/§8.6; khóa đã rời ma trận bị xóa cùng grant của nó
WITH seed (key, scope, description) AS (VALUES
{_values(model.permissions)}
), stale AS (
    DELETE FROM permissions p WHERE NOT EXISTS (SELECT 1 FROM seed s WHERE s.key = p.key)
)
INSERT INTO permissions (key, scope, description)
SELECT key, scope, description FROM seed
ON CONFLICT (key) DO UPDATE SET scope = EXCLUDED.scope, description = EXCLUDED.description;

-- roles ({len(roles)}): §8.4 + hai role support của §8.6; rank = thứ bậc trong cùng phạm vi (lớn hơn = cao hơn)
INSERT INTO roles (scope, key, name, rank, is_system) VALUES
{_values([r + (True,) for r in roles])}
ON CONFLICT (scope, key) DO UPDATE SET name = EXCLUDED.name, rank = EXCLUDED.rank, is_system = true;

-- Role hệ thống đã rời seed có thể còn được membership tham chiếu: gỡ role cần migration riêng ⇒ dừng.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM roles r WHERE r.is_system AND (r.scope, r.key) NOT IN (VALUES
{_values([(s, k) for s, k, _, _ in roles])})) THEN
    RAISE EXCEPTION 'seed RBAC: có role hệ thống không còn trong §8.4–§8.6 — gỡ role cần migration riêng';
  END IF;
END
$$;

-- role_permissions ({len(grants)}): grant của mỗi role hệ thống đúng bằng bảng này (grant thừa bị xóa)
WITH seed (role_scope, role_key, permission_key, scope, condition) AS (VALUES
{_values(grants)}
), want AS (
    SELECT r.id AS role_id, r.scope AS role_scope, p.key AS permission_key, p.scope AS permission_scope,
           s.scope, s.condition
    FROM seed s
    JOIN roles r ON r.scope = s.role_scope AND r.key = s.role_key
    JOIN permissions p ON p.key = s.permission_key
), stale AS (
    DELETE FROM role_permissions rp USING roles r
    WHERE r.id = rp.role_id AND r.is_system
      AND NOT EXISTS (SELECT 1 FROM want w WHERE w.role_id = rp.role_id AND w.permission_key = rp.permission_key)
)
INSERT INTO role_permissions (role_id, role_scope, permission_key, permission_scope, scope, condition)
SELECT role_id, role_scope, permission_key, permission_scope, scope, condition FROM want
ON CONFLICT (role_id, permission_key) DO UPDATE SET scope = EXCLUDED.scope, condition = EXCLUDED.condition;

DO $$
BEGIN
  IF (SELECT count(*) FROM role_permissions rp JOIN roles r ON r.id = rp.role_id WHERE r.is_system) <> {len(grants)}
     OR (SELECT count(*) FROM permissions) <> {len(model.permissions)} THEN
    RAISE EXCEPTION 'seed RBAC: grant hoặc permission trong database khác bảng seed';
  END IF;
END
$$;
"""


def render_operations_go(spec: dict) -> str:
    """internal/authz/operations_gen.go: x-permission, x-own-resource, x-dual-control and x-permission-secondary of
    every operation, sorted by operationId (gofmt-clean: one composite literal per line, nothing to align)."""
    rows = []
    for path, method, op, _ in sorted(operations(spec), key=lambda t: str(t[2].get("operationId"))):
        fields = [f"ID: {json.dumps(str(op.get('operationId', '')))}", f'Method: "{method.upper()}"',
                  f"Path: {json.dumps(path)}", f"Permission: {json.dumps(str(op.get('x-permission', '')))}"]
        if op.get("x-permission-secondary") is not None:
            fields.append(f"Secondary: {json.dumps(str(op['x-permission-secondary']))}")
        if op.get("x-own-resource") is True:
            fields.append("OwnResource: true")
        if op.get("x-dual-control") is True:
            fields.append("DualControl: true")
        rows.append("\t{" + ", ".join(fields) + "},")
    body = "\n".join(rows)
    return f"""\
// Code generated by tools/openapi_lint.py --write from api/openapi.yaml. DO NOT EDIT.

package authz

// specOperations is the authorization contract of every operation of api/openapi.yaml (§13.1): x-permission,
// x-own-resource, x-dual-control and x-permission-secondary, sorted by operationId.
var specOperations = []Operation{{
{body}
}}
"""


def generated_files(spec: dict, model: RbacModel) -> dict[str, str]:
    return {SEED_FILE: render_seed_sql(model), OPS_FILE: render_operations_go(spec)}


def generated_problems(expected: dict[str, str], root: pathlib.Path = ROOT) -> list[str]:
    """Committed generated files that differ from what the master and the spec generate."""
    errs = []
    for rel, want in expected.items():
        try:
            got = (root / rel).read_text(encoding="utf-8").replace("\r\n", "\n")
        except OSError:
            errs.append(f"{rel}: missing — run `python3 tools/openapi_lint.py --write` (make authz-gen)")
            continue
        if got != want:
            diff = list(difflib.unified_diff(got.splitlines(), want.splitlines(), "committed", "generated",
                                             lineterm="", n=0))
            errs.append(f"{rel}: differs from what §8.4–§8.6 and api/openapi.yaml generate — run `make authz-gen`\n    "
                        + "\n    ".join(diff[:24]))
    return errs


def write_generated(expected: dict[str, str], root: pathlib.Path = ROOT) -> list[str]:
    written = []
    for rel, content in expected.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        old = path.read_text(encoding="utf-8").replace("\r\n", "\n") if path.exists() else None
        if old != content:
            path.write_text(content, encoding="utf-8", newline="\n")
            written.append(rel)
    return written


# ====================================================================== CLI


def _diff(a, b, where: str):
    if isinstance(a, bool) or isinstance(b, bool):
        if a is not b:
            yield f"{where}: {a!r} != {b!r}"
    elif isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                yield f"{where}.{k}: only in {'this parser' if k in a else 'the other parser'}"
            else:
                yield from _diff(a[k], b[k], f"{where}.{k}")
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            yield f"{where}: {len(a)} items != {len(b)} items"
        for i, (x, y) in enumerate(zip(a, b)):
            yield from _diff(x, y, f"{where}[{i}]")
    elif type(a) is not type(b) and not (isinstance(a, (int, float)) and isinstance(b, (int, float))):
        yield f"{where}: {a!r} != {b!r}"
    elif a != b:
        yield f"{where}: {a!r} != {b!r}"


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")   # Windows consoles default to a legacy code page
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--spec", default=str(SPEC))
    ap.add_argument("--master", default=str(MASTER))
    ap.add_argument("--list", action="store_true", help="list operations and coverage")
    ap.add_argument("--dump-json", action="store_true", help="print the parsed spec as JSON")
    ap.add_argument("--compare-json", metavar="FILE", help="compare with the spec parsed by another YAML parser")
    ap.add_argument("--write", action="store_true", help=f"regenerate {SEED_FILE} and {OPS_FILE}, then lint")
    ap.add_argument("--partial", action="store_true",
                    help="lint a spec fragment: skip the row -> operation coverage and the generated files")
    args = ap.parse_args(argv)
    if args.write and args.partial:
        ap.error("--write and --partial exclude each other")
    try:
        spec = load_yaml(pathlib.Path(args.spec).read_text(encoding="utf-8"))
    except (OSError, YamlError) as e:
        print(f"openapi-lint: cannot read {args.spec}: {e}")
        return 2
    if args.dump_json:
        print(json.dumps(spec, ensure_ascii=False, sort_keys=True, indent=1))
        return 0
    if args.compare_json:
        other = json.loads(pathlib.Path(args.compare_json).read_text(encoding="utf-8"))
        diffs = list(_diff(spec, other, "$"))
        for d in diffs[:30]:
            print(f"DIFF {d}")
        print(f"openapi-lint: YAML parse {'differs from' if diffs else 'identical to'} {args.compare_json}")
        return 1 if diffs else 0
    try:
        master = Master(pathlib.Path(args.master).read_text(encoding="utf-8"))
    except (OSError, MasterError) as e:
        print(f"openapi-lint: cannot read the master plan {args.master}: {e}")
        return 2
    errs = lint(spec, master, coverage=not args.partial)
    model, problems = rbac_model(master)
    errs += problems + lattice_problems(model)
    if not args.partial:
        expected = generated_files(spec, model)
        if args.write:
            if problems:
                print("openapi-lint: the matrices are ambiguous — nothing written")
            else:
                for rel in write_generated(expected):
                    print(f"wrote {rel}")
        errs += generated_problems(expected)
    ops = list(operations(spec))
    if args.list:
        for path, method, op, _ in ops:
            print(f"  {method.upper():6} {path:48} {op.get('operationId', '?'):26} {op.get('x-permission', '?'):24} "
                  f"{op.get('x-task', '?')}")
        perms, groups = coverage(spec, master)
        print(f"permissions of §8.5/§8.6 without an operation yet ({len(perms)}): {', '.join(perms)}")
        print(f"§13.2 traceability groups without an operation yet ({len(groups)}):")
        for g in groups:
            print(f"  - {g}")
        _, notes = row_coverage(spec, master)
        print(f"rows of §8.5/§8.6 without an operation ({len(notes)}; an error once all their tasks are done in §20):")
        for n in notes:
            print(f"  - {n}")
        dup = sorted(k for k, p in master.perms.items() if len(p.lines) > 1)
        print(f"permissions on more than one matrix row (merged; their cells must agree): {', '.join(dup) or '—'}")
        print(f"seed: {len(model.roles)} roles, {len(model.permissions)} permissions, {len(model.grants)} grants; "
              f"conditional grants: {', '.join(f'{g.role}/{g.permission}={g.condition}' for g in model.grants if g.condition)}")
    for e in errs:
        print(f"ERROR {e}")
    print(f"openapi-lint: {len(ops)} operations, {len(errs)} problem(s) — "
          f"{'OK' if not errs else 'FAILED'} ({pathlib.Path(args.spec).name})")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())

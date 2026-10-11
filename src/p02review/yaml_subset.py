"""Parser for a documented, strict SUBSET of YAML (see docs/adr/ADR-0001 section 3).

Produces a tree of YMap / YSeq / YScalar nodes with 1-based line spans. Scalars keep their
source text and style; no implicit typing is applied here (rules interpret values, and
YAML 1.1-only booleans such as ``yes`` are left for rules to treat as ambiguous).

Unsupported constructs (anchors, aliases, tags, merge keys, explicit keys, directives,
multi-line plain/quoted scalars, multi-line flow collections, indentation indicators,
unrendered template delimiters) raise ``YamlUnsupported``. Malformed structure (tabs in
indentation, duplicate keys, bad indentation) raises ``YamlSyntaxError``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union

MAX_DEPTH = 64
_ODD_WHITESPACE = re.compile("[\u00a0\u180e\u2000-\u200f\u202f\u205f\u2060\u3000\ufeff]")


class YamlSyntaxError(Exception):
    def __init__(self, message: str, line: int):
        super().__init__(message)
        self.message, self.line = message, line


class YamlUnsupported(Exception):
    def __init__(self, message: str, line: int):
        super().__init__(message)
        self.message, self.line = message, line


@dataclass
class YScalar:
    text: str
    style: str               # plain | single | double | literal | folded
    line_start: int
    line_end: int

    @property
    def is_null(self) -> bool:
        return self.style == "plain" and self.text in ("", "~", "null", "Null", "NULL")


@dataclass
class YSeq:
    items: List["YNode"]
    line_start: int
    line_end: int


@dataclass
class YMap:
    items: List[Tuple[str, int, "YNode"]]   # (key text, key line, value)
    line_start: int
    line_end: int

    def get(self, key: str) -> Optional["YNode"]:
        for k, _, v in self.items:
            if k == key:
                return v
        return None


YNode = Union[YScalar, YSeq, YMap]


@dataclass
class YDocument:
    root: Optional[YNode]
    line_start: int
    line_end: int


@dataclass
class _Line:
    indent: int
    text: str        # content after indentation (raw, comments not yet removed)
    no: int          # 1-based physical line number


_DQ_ESCAPES = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v", "f": "\f",
               "r": "\r", "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\", "N": "\x85",
               "_": "\xa0", "L": "\u2028", "P": "\u2029"}
_FLOW_END = ",]}"


def _is_blank_or_comment(text: str) -> bool:
    s = text.strip()
    return s == "" or s.startswith("#")


# ----------------------------------------------------------------------------- inline scalars
class _Inline:
    """Parses a single-line value: scalar or flow collection. Tracks position within ``s``."""

    def __init__(self, s: str, line: int, depth: int):
        self.s, self.i, self.line, self.depth = s, 0, line, depth

    def ws(self):
        while self.i < len(self.s) and self.s[self.i] == " ":
            self.i += 1

    def at_end(self) -> bool:
        """End of line, or only a comment remains."""
        self.ws()
        return self.i >= len(self.s) or self.s[self.i] == "#"

    def check_indicator(self):
        c = self.s[self.i] if self.i < len(self.s) else ""
        if c == "&":
            raise YamlUnsupported("anchors are not supported", self.line)
        if c == "*":
            raise YamlUnsupported("aliases are not supported", self.line)
        if c == "!":
            raise YamlUnsupported("tags are not supported", self.line)
        if c in "?:":
            raise YamlUnsupported("scalars starting with '?' or ':' are not supported (explicit-key ambiguity)",
                                  self.line)
        if c in "@`":
            raise YamlSyntaxError("reserved indicator at start of scalar", self.line)

    def double(self) -> str:
        out, i, s = [], self.i + 1, self.s
        while i < len(s):
            c = s[i]
            if c == '"':
                self.i = i + 1
                return "".join(out)
            if c == "\\":
                if i + 1 >= len(s):
                    raise YamlUnsupported("multi-line double-quoted scalar", self.line)
                e = s[i + 1]
                if e in _DQ_ESCAPES:
                    out.append(_DQ_ESCAPES[e])
                    i += 2
                    continue
                width = {"x": 2, "u": 4, "U": 8}.get(e)
                if width is None:
                    raise YamlSyntaxError("invalid escape in double-quoted scalar", self.line)
                hexpart = s[i + 2:i + 2 + width]
                if len(hexpart) != width or any(h not in "0123456789abcdefABCDEF" for h in hexpart):
                    raise YamlSyntaxError("invalid escape in double-quoted scalar", self.line)
                cp = int(hexpart, 16)
                if cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF:
                    raise YamlSyntaxError("invalid escape in double-quoted scalar", self.line)
                out.append(chr(cp))
                i += 2 + width
                continue
            out.append(c)
            i += 1
        raise YamlUnsupported("multi-line double-quoted scalar", self.line)

    def single(self) -> str:
        out, i, s = [], self.i + 1, self.s
        while i < len(s):
            c = s[i]
            if c == "'":
                if i + 1 < len(s) and s[i + 1] == "'":
                    out.append("'")
                    i += 2
                    continue
                self.i = i + 1
                return "".join(out)
            out.append(c)
            i += 1
        raise YamlUnsupported("multi-line single-quoted scalar", self.line)

    def plain(self, in_flow: bool) -> str:
        s, i, start = self.s, self.i, self.i
        while i < len(s):
            c = s[i]
            if c == "#" and i > start and s[i - 1] == " ":
                break
            if c == ":" and (i + 1 >= len(s) or s[i + 1] == " " or (in_flow and s[i + 1] in _FLOW_END)):
                break
            if in_flow and c in _FLOW_END + "[{":
                break
            i += 1
        self.i = i
        text = s[start:i].rstrip(" ")
        if "\t" in text:
            raise YamlUnsupported("tab characters in plain scalars or separators", self.line)
        return text

    def scalar_or_flow(self, in_flow: bool) -> YNode:
        self.ws()
        if self.i >= len(self.s):
            return YScalar("", "plain", self.line, self.line)
        self.check_indicator()
        c = self.s[self.i]
        if c == '"':
            return YScalar(self.double(), "double", self.line, self.line)
        if c == "'":
            return YScalar(self.single(), "single", self.line, self.line)
        if c in "[{":
            return self.flow()
        if c in "|>":
            raise YamlSyntaxError("block scalar indicator is not valid here", self.line)
        if not in_flow and c == "-" and (self.i + 1 >= len(self.s) or self.s[self.i + 1] == " "):
            raise YamlSyntaxError("sequence entry is not valid as an inline value", self.line)
        text = self.plain(in_flow)
        if text.startswith("<<"):
            raise YamlUnsupported("merge keys are not supported", self.line)
        return YScalar(text, "plain", self.line, self.line)

    def flow(self) -> YNode:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise YamlUnsupported(f"nesting deeper than {MAX_DEPTH}", self.line)
        opener = self.s[self.i]
        closer = "]" if opener == "[" else "}"
        self.i += 1
        if opener == "[":
            items: list = []
        else:
            pairs: list = []
            keys = set()
        while True:
            self.ws()
            if self.i >= len(self.s) or self.s[self.i] == "#":
                raise YamlUnsupported("multi-line flow collection", self.line)
            if self.s[self.i] == closer:
                self.i += 1
                break
            if opener == "[":
                node = self.scalar_or_flow(in_flow=True)
                self.ws()
                if self.i < len(self.s) and self.s[self.i] == ":":
                    raise YamlUnsupported("single-pair mappings inside flow sequences", self.line)
                items.append(node)
            else:
                key_node = self.scalar_or_flow(in_flow=True)
                if not isinstance(key_node, YScalar):
                    raise YamlUnsupported("complex flow mapping keys", self.line)
                self.ws()
                if self.i < len(self.s) and self.s[self.i] == ":":
                    self.i += 1
                    value = self.scalar_or_flow(in_flow=True)
                else:
                    value = YScalar("", "plain", self.line, self.line)
                if key_node.text in keys:
                    raise YamlSyntaxError("duplicate key in flow mapping", self.line)
                keys.add(key_node.text)
                pairs.append((key_node.text, self.line, value))
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == ",":
                self.i += 1
            elif self.i < len(self.s) and self.s[self.i] == closer:
                continue
            else:
                raise YamlSyntaxError("expected ',' or closing bracket in flow collection", self.line)
        self.depth -= 1
        if opener == "[":
            return YSeq(items, self.line, self.line)
        return YMap(pairs, self.line, self.line)


def _split_key(text: str, line: int) -> Optional[Tuple[str, str, str]]:
    """If ``text`` is a block mapping entry, return (key, key_style, rest-after-colon); else None."""
    if not text:
        return None
    c = text[0]
    if c in "?:":
        raise YamlUnsupported("keys or scalars starting with '?' or ':' are not supported", line)
    if c in "&*!":
        p = _Inline(text, line, 0)
        p.check_indicator()
    if c in "\"'":
        p = _Inline(text, line, 0)
        key = p.double() if c == '"' else p.single()
        rest = text[p.i:]
        stripped = rest.lstrip(" ")
        if stripped.startswith(":") and (len(stripped) == 1 or stripped[1] == " "):
            return key, "quoted", stripped[1:]
        return None
    if c in "[{":
        # a flow collection followed by ':' would be a complex key
        return None
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\t":
            raise YamlUnsupported("tab characters in plain keys or separators", line)
        if ch == "#" and i > 0 and text[i - 1] == " ":
            return None
        if ch == ":" and (i + 1 == len(text) or text[i + 1] == " "):
            key = text[:i].rstrip(" ")
            if key == "<<":
                raise YamlUnsupported("merge keys are not supported", line)
            return key, "plain", text[i + 1:]
        i += 1
    return None


# ----------------------------------------------------------------------------- block parser
class _Block:
    def __init__(self, lines: List[_Line]):
        self.lines, self.p = lines, 0

    def skip(self):
        while self.p < len(self.lines) and _is_blank_or_comment(self.lines[self.p].text):
            self.p += 1

    def cur(self) -> Optional[_Line]:
        self.skip()
        return self.lines[self.p] if self.p < len(self.lines) else None

    def node(self, indent: int, depth: int) -> YNode:
        line = self.cur()
        if line is None:
            raise YamlSyntaxError("unexpected end of document", self.lines[-1].no if self.lines else 1)
        if depth > MAX_DEPTH:
            raise YamlUnsupported(f"nesting deeper than {MAX_DEPTH}", line.no)
        if line.text == "-" or line.text.startswith("- "):
            return self.sequence(line.indent, depth)
        if _split_key(line.text, line.no) is not None:
            return self.mapping(line.indent, depth)
        # a bare scalar or flow collection occupying a whole node
        self.p += 1
        value = self.inline_value(line.text, line, line.indent, depth)
        nxt = self.cur()
        if nxt is not None and nxt.indent > indent and isinstance(value, YScalar) and value.style == "plain":
            raise YamlUnsupported("multi-line plain scalar", nxt.no)
        return value

    def inline_value(self, text: str, line: _Line, parent_indent: int, depth: int) -> YNode:
        stripped = text.lstrip(" ")
        if stripped[:1] in ("|", ">"):
            return self.block_scalar(stripped, line, parent_indent)
        p = _Inline(text, line.no, depth)
        node = p.scalar_or_flow(in_flow=False)
        if not p.at_end():
            raise YamlSyntaxError("unexpected content after value", line.no)
        return node

    def block_scalar(self, header: str, line: _Line, parent_indent: int) -> YScalar:
        style = "literal" if header[0] == "|" else "folded"
        rest = header[1:]
        chomp = "clip"
        if rest[:1] in "+-" and rest[:1]:
            chomp = "keep" if rest[0] == "+" else "strip"
            rest = rest[1:]
        if rest[:1].isdigit():
            raise YamlUnsupported("block scalar indentation indicators are not supported", line.no)
        if rest.strip() and not rest.strip().startswith("#"):
            raise YamlSyntaxError("unexpected content after block scalar indicator", line.no)
        content: List[_Line] = []
        content_indent = None
        while self.p < len(self.lines):
            ln = self.lines[self.p]
            if ln.text.strip() == "":
                content.append(ln)
                self.p += 1
                continue
            if content_indent is None:
                if ln.indent <= parent_indent:
                    break
                content_indent = ln.indent
            if ln.indent < content_indent:
                break
            content.append(ln)
            self.p += 1
        # Split off trailing blank lines: they matter only for "keep" chomping.
        trailing = 0
        while content and content[-1].text.strip() == "":
            content.pop()
            trailing += 1
        ci = content_indent or 0
        texts = [(" " * (c.indent - ci) + c.text) if c.text.strip() else "" for c in content]
        if style == "literal":
            core = "\n".join(texts)
        else:  # simplified folding (documented): affects scalar text only, never structure
            out, prev_blank = [], True
            for t in texts:
                if t == "":
                    out.append("\n")
                    prev_blank = True
                elif t.startswith(" "):
                    out.append(("" if prev_blank else "\n") + t + "\n")
                    prev_blank = True
                else:
                    out.append(("" if prev_blank else " ") + t)
                    prev_blank = False
            core = "".join(out).rstrip("\n")
        if not core:
            body = ""
        elif chomp == "strip":
            body = core
        elif chomp == "clip":
            body = core + "\n"
        else:
            body = core + "\n" + "\n" * trailing
        end_line = content[-1].no if content else line.no
        return YScalar(body, style, line.no, end_line)

    def mapping(self, indent: int, depth: int) -> YMap:
        items, keys = [], set()
        start = self.cur().no
        end = start
        while True:
            line = self.cur()
            if line is None or line.indent < indent:
                break
            if line.indent > indent:
                raise YamlSyntaxError("unexpected indentation", line.no)
            split = _split_key(line.text, line.no)
            if split is None:
                if line.text == "-" or line.text.startswith("- "):
                    raise YamlSyntaxError("sequence entry where a mapping key was expected", line.no)
                raise YamlSyntaxError("expected 'key: value'", line.no)
            key, _style, rest = split
            if key in keys:
                raise YamlSyntaxError("duplicate mapping key", line.no)
            keys.add(key)
            self.p += 1
            if rest.strip() == "" or rest.strip().startswith("#"):
                nxt = self.cur()
                if nxt is not None and nxt.indent > indent:
                    value = self.node(nxt.indent, depth + 1)
                elif nxt is not None and nxt.indent == indent and (nxt.text == "-" or nxt.text.startswith("- ")):
                    value = self.sequence(indent, depth + 1)
                else:
                    value = YScalar("", "plain", line.no, line.no)
            else:
                value = self.inline_value(rest, line, indent, depth + 1)
                nxt = self.cur()
                if nxt is not None and nxt.indent > indent and not (isinstance(value, YScalar)
                                                                    and value.style in ("literal", "folded")):
                    raise YamlUnsupported("multi-line scalar continuation", nxt.no)
            items.append((key, line.no, value))
            end = max(end, value.line_end, line.no)
        return YMap(items, start, end)

    def sequence(self, indent: int, depth: int) -> YSeq:
        items = []
        start = self.cur().no
        end = start
        while True:
            line = self.cur()
            if line is None or line.indent < indent:
                break
            if line.indent > indent:
                raise YamlSyntaxError("unexpected indentation in sequence", line.no)
            if not (line.text == "-" or line.text.startswith("- ")):
                break
            rest = line.text[1:]
            spaces = len(rest) - len(rest.lstrip(" "))
            rest = rest.lstrip(" ")
            if rest.startswith("\t"):
                raise YamlUnsupported("tab characters as separators", line.no)
            if rest == "" or rest.startswith("#"):
                self.p += 1
                nxt = self.cur()
                if nxt is not None and nxt.indent > indent:
                    value = self.node(nxt.indent, depth + 1)
                else:
                    value = YScalar("", "plain", line.no, line.no)
            else:
                # Re-read the remainder as a virtual line at its own column (compact notation).
                col = indent + 1 + spaces
                self.lines[self.p] = _Line(col, rest, line.no)
                if rest[:1] in ("|", ">"):
                    self.p += 1
                    value = self.block_scalar(rest, line, indent)
                else:
                    value = self.node(col, depth + 1)
                    nxt = self.cur()
                    if (isinstance(value, YScalar) and value.style in ("plain", "single", "double")
                            and nxt is not None and nxt.indent > indent):
                        raise YamlUnsupported("multi-line scalar continuation", nxt.no)
            items.append(value)
            end = max(end, value.line_end, line.no)
        return YSeq(items, start, end)


def _physical_lines(text: str, first_no: int) -> List[_Line]:
    out = []
    for offset, raw in enumerate(text.split("\n")):
        raw = raw[:-1] if raw.endswith("\r") else raw
        no = first_no + offset
        stripped = raw.lstrip(" ")
        lead = raw[:len(raw) - len(stripped)]
        if stripped.startswith("\t") or "\t" in lead:
            if stripped.strip() != "":
                raise YamlSyntaxError("tab characters are not allowed in indentation", no)
        out.append(_Line(len(lead), stripped, no))
    return out


def parse_documents(text: str) -> List[YDocument]:
    """Parse all documents. Raises YamlSyntaxError / YamlUnsupported."""
    for ch in ("\u2028", "\u2029"):  # line breaks for YAML 1.1 readers, not for 1.2: a parser differential
        if ch in text:
            raise YamlUnsupported("Unicode line/paragraph separator characters",
                                  text.count("\n", 0, text.index(ch)) + 1)
    odd = _ODD_WHITESPACE.search(text)
    if odd:  # invisible or non-ASCII whitespace can make keys look identical but differ (or vice versa)
        raise YamlUnsupported("invisible or non-ASCII whitespace characters",
                              text.count("\n", 0, odd.start()) + 1)
    raw_lines = text.split("\n")
    if raw_lines and raw_lines[-1] == "":
        raw_lines.pop()
    docs: List[Tuple[int, List[str]]] = []
    current: List[str] = []
    current_start = 1
    explicit_end = False
    for idx, raw in enumerate(raw_lines):
        no = idx + 1
        body = raw[:-1] if raw.endswith("\r") else raw
        if body.startswith("%"):
            raise YamlUnsupported("directives are not supported", no)
        if body == "---" or body.startswith("--- ") or body.startswith("---\t"):
            tail = body[3:].strip()
            if tail and not tail.startswith("#"):
                raise YamlUnsupported("content on the document-start line", no)
            if current or idx > 0:
                docs.append((current_start, current))
            current, current_start, explicit_end = [], no + 1, False
            continue
        if body == "..." or body.startswith("... "):
            docs.append((current_start, current))
            current, current_start, explicit_end = [], no + 1, True
            continue
        if ("{{" in body or "{%" in body) and not body.lstrip(" ").startswith("#"):
            raise YamlUnsupported("unrendered template delimiters", no)
        current.append(raw)
    if current or not docs:
        docs.append((current_start, current))
    result = []
    for start, lines_txt in docs:
        lines = _physical_lines("\n".join(lines_txt), start) if lines_txt else []
        parser = _Block(lines)
        first = parser.cur()
        if first is None:
            result.append(YDocument(None, start, start + max(len(lines_txt) - 1, 0)))
            continue
        root = parser.node(first.indent, 0)
        leftover = parser.cur()
        if leftover is not None:
            raise YamlSyntaxError("unexpected content after document root", leftover.no)
        result.append(YDocument(root, start, root.line_end))
    return result


def to_plain(node: Optional[YNode]):
    """Structure as plain Python with scalars as text (comparable with yaml.BaseLoader)."""
    if node is None:
        return None
    if isinstance(node, YScalar):
        return node.text
    if isinstance(node, YSeq):
        return [to_plain(i) for i in node.items]
    return {k: to_plain(v) for k, _, v in node.items}

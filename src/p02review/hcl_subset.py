"""Tokenizer and recursive-descent parser for a documented SUBSET of HCL native syntax.

This is not a full HCL implementation (see docs/adr/ADR-0001 section 2). Literal values are
evaluated; every other expression is kept as an opaque ``Dyn`` node with its line span, so rules
can report ``insufficient_evidence`` instead of guessing. Constructs outside the subset raise
``HclUnsupported``; malformed input raises ``HclSyntaxError``. Nothing is executed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union

MAX_TOKENS = 200_000
MAX_DEPTH = 64


class HclSyntaxError(Exception):
    def __init__(self, message: str, line: int):
        super().__init__(message)
        self.message, self.line = message, line


class HclUnsupported(Exception):
    def __init__(self, message: str, line: int):
        super().__init__(message)
        self.message, self.line = message, line


# ----------------------------------------------------------------------------- AST
@dataclass
class Lit:
    value: object            # str | int | float | bool | None
    line_start: int
    line_end: int
    via_jsonencode: bool = False
    from_heredoc: bool = False


@dataclass
class Tuple_:
    items: List["Node"]
    line_start: int
    line_end: int


@dataclass
class Obj:
    items: List[Tuple[object, "Node"]]   # key is str, or Dyn for a computed key
    line_start: int
    line_end: int

    def get(self, key: str) -> Optional["Node"]:
        for k, v in self.items:
            if k == key:
                return v
        return None


@dataclass
class Dyn:
    text: str                # compact token rendering (for reference matching only; never output raw)
    line_start: int
    line_end: int


Node = Union[Lit, Tuple_, Obj, Dyn]


@dataclass
class Attribute:
    name: str
    expr: Node
    line_start: int
    line_end: int


@dataclass
class Block:
    type: str
    labels: List[str]
    body: List[Union["Attribute", "Block"]]
    line_start: int
    line_end: int

    def attr(self, name: str) -> Optional[Attribute]:
        for item in self.body:
            if isinstance(item, Attribute) and item.name == name:
                return item
        return None

    def blocks(self, type_: str) -> List["Block"]:
        return [b for b in self.body if isinstance(b, Block) and b.type == type_]


@dataclass
class Tok:
    type: str
    value: object
    line: int
    end_line: int
    templated: bool = False


# ----------------------------------------------------------------------------- tokenizer
_DIGITS = frozenset("0123456789")
_IDENT_START = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_IDENT_CHARS = _IDENT_START | set("0123456789-")
_SINGLE = {"{": "LBRACE", "}": "RBRACE", "[": "LBRACK", "]": "RBRACK", "(": "LPAREN", ")": "RPAREN",
           ",": "COMMA", ":": "COLON"}
_MULTI_OPS = ("=>", "==", "!=", "<=", ">=", "&&", "||", "...")
_OP_CHARS = set(".?!+-*/%<>")
_OPERAND_END = frozenset(("NUMBER", "STRING", "HEREDOC", "IDENT", "RBRACK", "RPAREN", "RBRACE"))
_OPERAND_START = frozenset(("NUMBER", "STRING", "HEREDOC", "IDENT", "LBRACE"))
_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}


class _Lexer:
    def __init__(self, text: str):
        self.s, self.i, self.line, self.toks = text, 0, 1, []

    def add(self, type_, value, line, end_line=None, templated=False):
        self.toks.append(Tok(type_, value, line, end_line or line, templated))
        if len(self.toks) > MAX_TOKENS:
            raise HclUnsupported(f"more than {MAX_TOKENS} tokens", line)

    def run(self) -> List[Tok]:
        s = self.s
        while self.i < len(s):
            c = s[self.i]
            if c == "\n":
                self.add("NEWLINE", None, self.line)
                self.line += 1
                self.i += 1
            elif c in " \t\r":
                self.i += 1
            elif c == "#" or s.startswith("//", self.i):
                while self.i < len(s) and s[self.i] != "\n":
                    self.i += 1
            elif s.startswith("/*", self.i):
                end = s.find("*/", self.i + 2)
                if end < 0:
                    raise HclSyntaxError("unterminated block comment", self.line)
                newlines = s.count("\n", self.i, end)
                if newlines:
                    self.add("NEWLINE", None, self.line)
                self.line += newlines
                self.i = end + 2
            elif c == '"':
                self.string()
            elif s.startswith("<<", self.i) and self._heredoc_start():
                self.heredoc()
            elif c in _DIGITS:
                self.number()
            elif c in _IDENT_START:
                j = self.i
                while j < len(s) and s[j] in _IDENT_CHARS:
                    j += 1
                if j < len(s) and ord(s[j]) > 127 and s[j].isalpha():
                    raise HclUnsupported("non-ASCII identifier", self.line)
                self.add("IDENT", s[self.i:j], self.line)
                self.i = j
            elif ord(c) > 127 and c.isalpha():
                raise HclUnsupported("non-ASCII identifier", self.line)
            elif c in _SINGLE:
                self.add(_SINGLE[c], c, self.line)
                self.i += 1
            elif c == "=" and not s.startswith("==", self.i) and not s.startswith("=>", self.i):
                self.add("EQ", "=", self.line)
                self.i += 1
            else:
                for op in _MULTI_OPS:
                    if s.startswith(op, self.i):
                        self.add("OP", op, self.line)
                        self.i += len(op)
                        break
                else:
                    if c in _OP_CHARS:
                        self.add("OP", c, self.line)
                        self.i += 1
                    else:
                        raise HclSyntaxError("unexpected character", self.line)
        self.add("EOF", None, self.line)
        return self.toks

    def _heredoc_start(self) -> bool:
        j = self.i + 2
        if j < len(self.s) and self.s[j] == "-":
            j += 1
        return j < len(self.s) and self.s[j] in _IDENT_START

    def number(self):
        s, j = self.s, self.i
        while j < len(s) and s[j] in _DIGITS:
            j += 1
        is_float = False
        if j + 1 < len(s) and s[j] == "." and s[j + 1] in _DIGITS:
            is_float = True
            j += 1
            while j < len(s) and s[j] in _DIGITS:
                j += 1
        if j < len(s) and s[j] in "eE":
            k = j + 1
            if k < len(s) and s[k] in "+-":
                k += 1
            if k < len(s) and s[k] in _DIGITS:
                is_float = True
                j = k
                while j < len(s) and s[j] in _DIGITS:
                    j += 1
        text = s[self.i:j]
        if len(text) > 64:
            raise HclUnsupported("numeric literal longer than 64 characters", self.line)
        value = float(text) if is_float else int(text)
        if is_float and (value != value or value in (float("inf"), float("-inf"))):
            raise HclUnsupported("non-finite numeric literal", self.line)
        self.add("NUMBER", value, self.line)
        self.i = j

    def _skip_template_expr(self, j: int, start_line: int) -> Tuple[int, int]:
        """j points just after '${' or '%{'. Returns index after the matching '}' and lines consumed."""
        s, depth, lines = self.s, 1, 0
        while j < len(s):
            c = s[j]
            if c == "\n":
                lines += 1
            elif c == '"':
                j, extra = self._skip_quoted(j + 1, start_line + lines)
                lines += extra
                continue
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return j + 1, lines
            j += 1
        raise HclSyntaxError("unterminated template interpolation", start_line)

    def _skip_quoted(self, j: int, start_line: int) -> Tuple[int, int]:
        s, lines = self.s, 0
        while j < len(s):
            c = s[j]
            if c == "\\":
                j += 2
                continue
            if c == '"':
                return j + 1, lines
            if c == "\n":
                raise HclSyntaxError("unterminated string", start_line)
            if s.startswith("${", j) or s.startswith("%{", j):
                j, extra = self._skip_template_expr(j + 2, start_line + lines)
                lines += extra
                continue
            j += 1
        raise HclSyntaxError("unterminated string", start_line)

    def string(self):
        s, j, start = self.s, self.i + 1, self.line
        out, templated, lines = [], False, 0
        while True:
            if j >= len(s):
                raise HclSyntaxError("unterminated string", start)
            c = s[j]
            if c == '"':
                j += 1
                break
            if c == "\n":
                raise HclSyntaxError("unterminated string", start)
            if c == "\\":
                if j + 1 >= len(s):
                    raise HclSyntaxError("unterminated string", start)
                e = s[j + 1]
                if e in _ESCAPES:
                    out.append(_ESCAPES[e])
                    j += 2
                elif e in "uU":
                    width = 4 if e == "u" else 8
                    hexpart = s[j + 2:j + 2 + width]
                    if len(hexpart) != width or any(h not in "0123456789abcdefABCDEF" for h in hexpart):
                        raise HclSyntaxError("invalid unicode escape", start)
                    cp = int(hexpart, 16)
                    if cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF:
                        raise HclSyntaxError("invalid unicode escape", start)
                    out.append(chr(cp))
                    j += 2 + width
                else:
                    raise HclSyntaxError("invalid escape sequence", start)
                continue
            if s.startswith("$${", j) or s.startswith("%%{", j):
                out.append(s[j + 1:j + 3])
                j += 3
                continue
            if s.startswith("${", j) or s.startswith("%{", j):
                templated = True
                j, extra = self._skip_template_expr(j + 2, start + lines)
                lines += extra
                continue
            out.append(c)
            j += 1
        self.add("STRING", None if templated else "".join(out), start, start + lines, templated)
        self.line += lines
        self.i = j

    def heredoc(self):
        s, start = self.s, self.line
        j = self.i + 2
        indent = False
        if s[j] == "-":
            indent = True
            j += 1
        k = j
        while k < len(s) and s[k] in _IDENT_CHARS:
            k += 1
        marker = s[j:k]
        if s.startswith("\r\n", k):
            k += 1
        if not s.startswith("\n", k):
            raise HclSyntaxError("heredoc marker must be followed by a newline", start)
        pos, lines_out, line_no = k + 1, [], start
        while True:
            if pos >= len(s):
                raise HclSyntaxError("unterminated heredoc", start)
            nl = s.find("\n", pos)
            line_text = s[pos:] if nl < 0 else s[pos:nl]
            line_no += 1
            if line_text.strip() == marker:
                end_pos = len(s) if nl < 0 else nl
                break
            lines_out.append(line_text)
            if nl < 0:
                raise HclSyntaxError("unterminated heredoc", start)
            pos = nl + 1
        if indent:
            widths = [len(l) - len(l.lstrip(" \t")) for l in lines_out if l.strip()]
            cut = min(widths) if widths else 0
            lines_out = [l[cut:] for l in lines_out]
        body = "\n".join(lines_out) + ("\n" if lines_out else "")
        scrub = body.replace("$${", "").replace("%%{", "")
        templated = "${" in scrub or "%{" in scrub
        if not templated:
            body = body.replace("$${", "${").replace("%%{", "%{")
        self.add("HEREDOC", None if templated else body, start, line_no, templated)
        self.line = line_no
        self.i = end_pos


def tokenize(text: str) -> List[Tok]:
    return _Lexer(text).run()


# ----------------------------------------------------------------------------- parser
class _Parser:
    def __init__(self, toks: List[Tok]):
        self.t, self.p, self.depth = toks, 0, 0

    def peek(self, k: int = 0) -> Tok:
        return self.t[min(self.p + k, len(self.t) - 1)]

    def next(self) -> Tok:
        tok = self.t[self.p]
        self.p += 1
        return tok

    def skip_newlines(self):
        while self.peek().type == "NEWLINE":
            self.p += 1

    def enter(self, line):
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise HclUnsupported(f"nesting deeper than {MAX_DEPTH}", line)

    def leave(self):
        self.depth -= 1

    # body := (attribute | block)*
    def body(self, closing: str) -> List[Union[Attribute, Block]]:
        items, names = [], set()
        while True:
            self.skip_newlines()
            tok = self.peek()
            if tok.type == closing:
                return items
            if tok.type == "EOF":
                raise HclSyntaxError("unexpected end of file (missing '}')", tok.line)
            if tok.type != "IDENT":
                raise HclSyntaxError("expected an attribute or block", tok.line)
            name = self.next()
            if self.peek().type == "EQ":
                self.next()
                expr = self.expr(("NEWLINE", "EOF", "RBRACE"), newline_ends=True)
                if name.value in names:
                    raise HclSyntaxError("attribute redefined", name.line)
                names.add(name.value)
                items.append(Attribute(name.value, expr, name.line, expr.line_end))
                end = self.peek()
                if end.type not in ("NEWLINE", "EOF", "RBRACE"):
                    raise HclSyntaxError("unexpected token after attribute value", end.line)
                continue
            labels = []
            while self.peek().type in ("STRING", "IDENT"):
                lab = self.next()
                if lab.type == "STRING" and lab.templated:
                    raise HclSyntaxError("block labels may not contain interpolation", lab.line)
                labels.append(lab.value)
            open_tok = self.next()
            if open_tok.type != "LBRACE":
                raise HclSyntaxError("expected '{' to open a block", open_tok.line)
            self.enter(open_tok.line)
            inner = self.body("RBRACE")
            close = self.next()
            self.leave()
            items.append(Block(name.value, labels, inner, name.line, close.line))
            if self.peek().type not in ("NEWLINE", "EOF", "RBRACE"):
                raise HclSyntaxError("expected a newline after block", self.peek().line)

    # expression with literal evaluation, otherwise opaque Dyn
    def expr(self, terms: Tuple[str, ...], newline_ends: bool) -> Node:
        start = self.p
        node = self._literal(terms, newline_ends)
        if node is not None and self._at_term(terms, newline_ends):
            return node
        self.p = start
        return self._dynamic(terms, newline_ends)

    def _at_term(self, terms, newline_ends) -> bool:
        tok = self.peek()
        if tok.type == "NEWLINE" and not newline_ends:
            k = 0
            while self.peek(k).type == "NEWLINE":
                k += 1
            return self.peek(k).type in terms
        return tok.type in terms

    def _literal(self, terms, newline_ends) -> Optional[Node]:
        tok = self.peek()
        if tok.type == "STRING" and not tok.templated:
            self.next()
            return Lit(tok.value, tok.line, tok.end_line)
        if tok.type == "HEREDOC" and not tok.templated:
            self.next()
            return Lit(tok.value, tok.line, tok.end_line, from_heredoc=True)
        if tok.type == "NUMBER":
            self.next()
            return Lit(tok.value, tok.line, tok.line)
        if tok.type == "OP" and tok.value == "-" and self.peek(1).type == "NUMBER":
            self.next()
            num = self.next()
            return Lit(-num.value, tok.line, num.line)
        if tok.type == "IDENT" and tok.value in ("true", "false", "null"):
            self.next()
            return Lit({"true": True, "false": False, "null": None}[tok.value], tok.line, tok.line)
        if tok.type == "LBRACK" and not self._starts_for(1):
            return self._tuple()
        if tok.type == "LBRACE" and not self._starts_for(1):
            return self._object()
        if tok.type == "IDENT" and tok.value == "jsonencode" and self.peek(1).type == "LPAREN":
            self.next()
            lp = self.next()
            self.enter(lp.line)
            inner = self.expr(("RPAREN",), newline_ends=False)
            self.skip_newlines()
            rp = self.next()
            self.leave()
            if rp.type != "RPAREN":
                raise HclSyntaxError("expected ')'", rp.line)
            # jsonencode is pure: keep the argument's structure (literal parts stay inspectable,
            # dynamic parts stay Dyn). A wholly dynamic argument remains opaque.
            if isinstance(inner, (Lit, Tuple_, Obj)):
                _mark_jsonencode(inner)
                if isinstance(inner, Lit):
                    inner.line_start, inner.line_end = tok.line, rp.line
                return inner
            return Dyn("jsonencode(...)", tok.line, rp.line)
        return None

    def _starts_for(self, k: int) -> bool:
        while self.peek(k).type == "NEWLINE":
            k += 1
        return self.peek(k).type == "IDENT" and self.peek(k).value == "for"

    def _tuple(self) -> Node:
        open_tok = self.next()
        self.enter(open_tok.line)
        items = []
        while True:
            self.skip_newlines()
            if self.peek().type == "RBRACK":
                close = self.next()
                break
            items.append(self.expr(("COMMA", "RBRACK"), newline_ends=False))
            self.skip_newlines()
            tok = self.peek()
            if tok.type == "COMMA":
                self.next()
            elif tok.type != "RBRACK":
                raise HclSyntaxError("expected ',' or ']' in tuple", tok.line)
        self.leave()
        return Tuple_(items, open_tok.line, close.line)

    def _object(self) -> Node:
        open_tok = self.next()
        self.enter(open_tok.line)
        items, keys = [], set()
        while True:
            self.skip_newlines()
            tok = self.peek()
            if tok.type == "RBRACE":
                close = self.next()
                break
            if tok.type == "IDENT":
                key = self.next().value
            elif tok.type == "STRING" and not tok.templated:
                key = self.next().value
            elif tok.type == "LPAREN" or (tok.type == "STRING" and tok.templated):
                key_node = self._dynamic(("EQ", "COLON"), newline_ends=True)
                key = key_node
            else:
                raise HclSyntaxError("expected an object key", tok.line)
            sep = self.next()
            if sep.type not in ("EQ", "COLON"):
                raise HclSyntaxError("expected '=' or ':' after object key", sep.line)
            value = self.expr(("COMMA", "NEWLINE", "RBRACE"), newline_ends=True)
            if isinstance(key, str):
                if key in keys:
                    raise HclSyntaxError("duplicate object key", tok.line)
                keys.add(key)
            items.append((key, value))
            if self.peek().type == "COMMA":
                self.next()
            elif self.peek().type not in ("NEWLINE", "RBRACE"):
                raise HclSyntaxError("expected ',' or newline between object items", self.peek().line)
        self.leave()
        return Obj(items, open_tok.line, close.line)

    def _dynamic(self, terms, newline_ends) -> Dyn:
        """Consume a balanced token run up to a terminator at depth 0; keep only its span."""
        start_tok = self.peek()
        depth, parts, last_line = 0, [], start_tok.line
        pairs = {"LBRACE": "RBRACE", "LBRACK": "RBRACK", "LPAREN": "RPAREN"}
        stack: List[str] = []
        for_open: List[bool] = []          # parallel to stack: bracket opens a for-expression
        prev_type = None
        while True:
            tok = self.peek()
            if tok.type == "EOF":
                if depth:
                    raise HclSyntaxError("unbalanced brackets in expression", start_tok.line)
                break
            if depth == 0:
                if tok.type == "NEWLINE" and not newline_ends:
                    self.next()
                    continue
                if tok.type in terms:
                    break
                if tok.type in ("RBRACE", "RBRACK", "RPAREN"):
                    raise HclSyntaxError("unbalanced closing bracket", tok.line)
            # Two operands with no operator between them are a syntax error in HCL, except inside
            # for-expressions ("for k, v in m : ...") where keywords and names are adjacent.
            if (prev_type in _OPERAND_END and tok.type in _OPERAND_START and not any(for_open)
                    and not (tok.type == "IDENT" and tok.value in ("for", "in", "if"))):
                raise HclSyntaxError("missing operator between expression parts", tok.line)
            if tok.type == "NEWLINE":
                if stack and stack[-1] == "RBRACE":
                    prev_type = None  # newlines separate items inside an object constructor
            else:
                if prev_type is None and not parts and tok.type == "OP" and tok.value not in ("-", "!"):
                    raise HclSyntaxError("expression starts with a binary operator", tok.line)
                prev_type = tok.type
            if tok.type in pairs:
                stack.append(pairs[tok.type])
                for_open.append(self._starts_for(1))
                depth += 1
                if depth > MAX_DEPTH:
                    raise HclUnsupported(f"nesting deeper than {MAX_DEPTH}", tok.line)
            elif tok.type in ("RBRACE", "RBRACK", "RPAREN"):
                if not stack or stack.pop() != tok.type:
                    raise HclSyntaxError("mismatched brackets in expression", tok.line)
                for_open.pop()
                depth -= 1
            self.next()
            last_line = tok.end_line
            if tok.type != "NEWLINE" and len(parts) < 64:
                parts.append(str(tok.value) if tok.type in ("IDENT", "NUMBER", "OP") else
                             {"STRING": "<str>", "HEREDOC": "<heredoc>"}.get(tok.type, str(tok.value)))
        if not parts:
            raise HclSyntaxError("expected an expression", start_tok.line)
        if prev_type == "OP":
            raise HclSyntaxError("expression ends with an operator", last_line)
        return Dyn("".join(parts), start_tok.line, last_line)


def _is_literal(node: Node) -> bool:
    if isinstance(node, Lit):
        return True
    if isinstance(node, Tuple_):
        return all(_is_literal(i) for i in node.items)
    if isinstance(node, Obj):
        return all(isinstance(k, str) and _is_literal(v) for k, v in node.items)
    return False


def _mark_jsonencode(node: Node) -> None:
    if isinstance(node, Lit):
        node.via_jsonencode = True
    elif isinstance(node, Tuple_):
        for i in node.items:
            _mark_jsonencode(i)
    elif isinstance(node, Obj):
        for _, v in node.items:
            _mark_jsonencode(v)


_UNICODE_BREAKS = ("\u2028", "\u2029")


def parse(text: str) -> List[Union[Attribute, Block]]:
    """Parse a whole file. Raises HclSyntaxError or HclUnsupported."""
    for ch in _UNICODE_BREAKS:
        if ch in text:
            raise HclUnsupported("Unicode line/paragraph separator characters",
                                 text.count("\n", 0, text.index(ch)) + 1)
    parser = _Parser(tokenize(text))
    items = parser.body("EOF")
    return items


def from_python(value, line_start: int, line_end: int) -> Node:
    """Wrap a decoded JSON value (e.g. a policy string) as literal nodes sharing one line span."""
    if isinstance(value, dict):
        return Obj([(k, from_python(v, line_start, line_end)) for k, v in value.items()], line_start, line_end)
    if isinstance(value, list):
        return Tuple_([from_python(v, line_start, line_end) for v in value], line_start, line_end)
    return Lit(value, line_start, line_end)

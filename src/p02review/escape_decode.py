"""Bounded, format-aware escape decoding for credential screening (security hardening L1).

Purpose: recover the text that HCL and YAML *define* through backslash escapes, so the credential screen can
see a credential whose characters are written as escapes. Nothing here evaluates anything:
  * no template execution, no ${...} / %{...} interpolation, no variable resolution, no YAML tag handling;
  * only the escape forms each format documents are decoded; any other backslash sequence is left literal and
    counted in ``unsupported`` (never silently reinterpreted);
  * single forward pass, iterative (explicit context stack, no recursion), O(1) work per input character, so
    cost is linear in the (already size-bounded) input; decoded output is never decoded again.

Supported forms
  HCL (terraform, terraform-vars): inside double-quoted template literals, including literals nested inside
      ${...} / %{...} sequences of quoted templates and of heredoc templates:
          \\n \\r \\t \\" \\\\ \\uNNNN \\UNNNNNNNN   and the literal markers $${ %%{
      Not decoded: comments, heredoc literal text (HCL heredocs take no backslash escapes), code outside strings.
  YAML (yaml, kubernetes, helm-rendered): inside double-quoted scalars only (YAML 1.2 section 5.7):
          \\0 \\a \\b \\t \\<TAB> \\n \\v \\f \\r \\e \\<SPACE> \\" \\/ \\\\ \\N \\_ \\L \\P \\xNN \\uNNNN \\UNNNNNNNN
      and an escaped line break (the break and the next line's leading white space are removed).
      Not decoded: plain scalars (including multi-line continuation lines), single-quoted scalars, block
      scalars (| >, ended by indentation relative to the owning key or sequence entry), comments.
      A double-quoted scalar is recognised where YAML lets a node start: at the start of a line's content,
      after '- ', '? ', ': ' (or ':' directly after a quoted key, JSON-style), '[', '{', ',', and after any
      number of tag/anchor properties.
Malformed input: an unterminated string is decoded up to where it ends (HCL quoted literal: the line break;
YAML: end of input); only valid escapes in it are decoded, so this can only add screen hits (fail-closed).

Results: ``values`` holds each decoded string value that contained a backslash (unit tests, diagnostics);
``text`` is the whole input with every decoded string replaced in place by its decoded form, so the screen
also sees each value next to its key (credential-assignment rule); ``changed`` says whether any escape was
decoded. Literal text either side of an HCL interpolation keeps the ``${...}`` text between, so no credential
shape can be manufactured across an interpolation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

_HEX = frozenset("0123456789abcdefABCDEF")
_HCL_SIMPLE = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
_YAML_SIMPLE = {"0": "\x00", "a": "\x07", "b": "\x08", "t": "\t", "\t": "\t", "n": "\n", "v": "\x0b", "f": "\x0c",
                "r": "\r", "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0",
                "L": "\u2028", "P": "\u2029"}
_HEX_WIDTH_HCL = {"u": 4, "U": 8}
_HEX_WIDTH_YAML = {"x": 2, "u": 4, "U": 8}


@dataclass
class DecodeResult:
    values: List[str] = field(default_factory=list)
    unsupported: int = 0          # backslash sequences left literal because the format does not define them
    truncated: bool = False       # kept for API stability; the iterative lexers never truncate
    text: str = ""                # the input with decoded strings substituted in place
    changed: bool = False         # at least one escape was decoded


def _hex_char(text: str, i: int, width: int) -> Optional[str]:
    """Code point from `width` hex digits at text[i:]; None if malformed or not a Unicode scalar value."""
    digits = text[i:i + width]
    if len(digits) != width or any(c not in _HEX for c in digits):
        return None
    cp = int(digits, 16)
    if cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF:
        return None
    return chr(cp)


def _escape(text: str, i: int, simple: dict, widths: dict) -> Tuple[Optional[str], int]:
    """Decode the escape whose backslash is at text[i]: (decoded, length), or (None, 1) if unsupported."""
    nxt = text[i + 1] if i + 1 < len(text) else ""
    if nxt in simple:
        return simple[nxt], 2
    if nxt in widths:
        ch = _hex_char(text, i + 2, widths[nxt])
        if ch is not None:
            return ch, 2 + widths[nxt]
    return None, 1


# --------------------------------------------------------------------------------------------- HCL

def _heredoc_header(text: str, i: int) -> Optional[Tuple[str, int]]:
    """If text[i:] starts '<<ID' or '<<-ID' then a line break, return (ID, index after the line break)."""
    j = i + 2
    if j < len(text) and text[j] == "-":
        j += 1
    start = j
    while j < len(text) and (text[j].isalnum() or text[j] in "_-"):   # HCL identifiers may contain '-'
        j += 1
    marker = text[start:j]
    if not marker or not (marker[0].isalpha() or marker[0] == "_"):
        return None
    while j < len(text) and text[j] in " \t\r":
        j += 1
    if j >= len(text) or text[j] != "\n":
        return None
    return marker, j + 1


def _close_hcl_string(frame: list, res: DecodeResult) -> None:
    _kind, parts, buf, had_escape = frame
    if had_escape:
        res.values.append("\n".join(parts + ["".join(buf)]))


def hcl_string_values(text: str) -> DecodeResult:
    res = DecodeResult()
    out: List[str] = []
    stack: list = []          # frames: ["str", parts, buf, had_escape] | ["expr", braces] | ["heredoc", marker]
    i, n = 0, len(text)
    at_line_start = False     # used by heredoc frames only
    while i < n:
        top = stack[-1] if stack else None
        kind = top[0] if top else "code"
        c = text[i]
        if kind == "str":
            if c == '"':
                _close_hcl_string(stack.pop(), res)
                out.append(c)
                i += 1
            elif c == "\n":                                    # quoted literals cannot span lines: ends here
                _close_hcl_string(stack.pop(), res)
            elif c == "\\":
                top[3] = True
                decoded, length = _escape(text, i, _HCL_SIMPLE, _HEX_WIDTH_HCL)
                if decoded is None:
                    res.unsupported += 1
                    decoded = c
                else:
                    res.changed = True
                top[2].append(decoded)
                out.append(decoded)
                i += length
            elif c in "$%" and text.startswith(c + c + "{", i):  # $${ / %%{ are the literals ${ / %{
                top[2].append(c + "{")
                out.append(text[i:i + 3])
                i += 3
            elif c in "$%" and text.startswith(c + "{", i):     # interpolation / directive: never evaluated
                top[1].append("".join(top[2]))
                top[2] = []
                stack.append(["expr", 1])
                out.append(text[i:i + 2])
                i += 2
            else:
                top[2].append(c)
                out.append(c)
                i += 1
            continue
        if kind == "expr":
            if c == '"':
                stack.append(["str", [], [], False])
            elif c == "{":
                top[1] += 1
            elif c == "}":
                top[1] -= 1
                if top[1] == 0:
                    stack.pop()
            out.append(c)
            i += 1
            at_line_start = c == "\n"
            continue
        if kind == "heredoc":
            if at_line_start:
                end = text.find("\n", i)
                line_end = n if end == -1 else end
                at_line_start = False
                if text[i:line_end].strip() == top[1]:          # closing marker line
                    stack.pop()
                    out.append(text[i:line_end])
                    i = line_end
                    continue
            if c in "$%" and text.startswith(c + c + "{", i):
                out.append(text[i:i + 3])
                i += 3
            elif c in "$%" and text.startswith(c + "{", i):
                stack.append(["expr", 1])
                out.append(text[i:i + 2])
                i += 2
            else:
                out.append(c)
                i += 1
                at_line_start = c == "\n"
            continue
        # code, outside any string
        if c == "#" or text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end == -1 else end
            out.append(text[i:end])
            i = end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            out.append(text[i:end])
            i = end
        elif c == "<" and text.startswith("<<", i) and _heredoc_header(text, i) is not None:
            marker, after = _heredoc_header(text, i)
            out.append(text[i:after])
            stack.append(["heredoc", marker])
            at_line_start = True
            i = after
        elif c == '"':
            stack.append(["str", [], [], False])
            out.append(c)
            i += 1
        else:
            out.append(c)
            i += 1
    while stack:                                                # unterminated at end of input
        frame = stack.pop()
        if frame[0] == "str":
            _close_hcl_string(frame, res)
    res.text = "".join(out)
    return res


# -------------------------------------------------------------------------------------------- YAML

_SEPARATOR = " \t\r\n"


def _sep_after(text: str, j: int) -> bool:
    return j >= len(text) or text[j] in _SEPARATOR


def _rest_is_blank(text: str, i: int) -> bool:
    n = len(text)
    while i < n and text[i] in " \t\r":
        i += 1
    return i >= n or text[i] == "\n"


def _yaml_double(text: str, i: int, out: List[str], res: DecodeResult) -> int:
    """Decode the double-quoted scalar whose opening quote is at text[i]; return the index after it."""
    n = len(text)
    out.append('"')
    i += 1
    buf: List[str] = []
    had_escape = False
    while i < n:
        c = text[i]
        if c == '"':
            out.append(c)
            i += 1
            break
        if c == "\\":
            had_escape = True
            nxt = text[i + 1] if i + 1 < n else ""
            if nxt in ("\n", "\r"):                     # escaped line break: join without a separator
                i += 3 if text.startswith("\r\n", i + 1) else 2
                while i < n and text[i] in " \t":
                    i += 1
                res.changed = True
                continue
            decoded, length = _escape(text, i, _YAML_SIMPLE, _HEX_WIDTH_YAML)
            if decoded is None:
                res.unsupported += 1
                decoded = c
            else:
                res.changed = True
            buf.append(decoded)
            out.append(decoded)
            i += length
            continue
        buf.append(c)
        out.append(c)
        i += 1
    if had_escape:
        res.values.append("".join(buf))
    return i


def _yaml_single_end(text: str, i: int) -> int:
    """Index after the single-quoted scalar starting at text[i] ('' is an escaped quote); end of input if open."""
    n = len(text)
    j = i + 1
    while j < n:
        if text[j] == "'":
            if j + 1 < n and text[j + 1] == "'":
                j += 2
                continue
            return j + 1
        j += 1
    return n


def _token_end(text: str, i: int, flow: int) -> int:
    n = len(text)
    while i < n and text[i] not in _SEPARATOR and not (flow and text[i] in ",[]{}"):
        i += 1
    return i


def yaml_double_quoted_values(text: str) -> DecodeResult:
    res = DecodeResult()
    out: List[str] = []
    n = len(text)
    i = 0
    flow = 0                                  # flow-collection nesting depth
    block_parent: Optional[int] = None        # skipping block-scalar lines indented deeper than this column
    plain_owner: Optional[int] = None         # the previous line ended inside a plain scalar owned at this column
    expect_carry = True                       # node-expectation carried across line breaks inside flow context
    while i < n:
        # ---------------------------------------------------------------- start of a line
        line_start = i
        while i < n and text[i] == " ":
            i += 1
        indent = i - line_start
        blank = _rest_is_blank(text, i)
        out.append(text[line_start:i])
        doc_marker = indent == 0 and text.startswith(("---", "..."), i) and _sep_after(text, i + 3)
        if block_parent is not None:
            if not doc_marker and (blank or indent > block_parent):
                end = text.find("\n", i)
                end = n if end == -1 else end + 1
                out.append(text[i:end])
                i = end
                continue
            block_parent = None
        continuation = False
        if flow:
            expect, in_plain = expect_carry, False
        elif plain_owner is not None and not blank and indent > plain_owner and text[i] != "#":
            expect, in_plain, continuation = False, True, True   # continuation line of a multi-line plain scalar
        else:
            expect, in_plain = True, False
        owner_col: Optional[int] = None      # column of the key or '-' that owns a block scalar on this line
        node_col: Optional[int] = None       # column where the most recent node on this line began
        plain_start_owner: Optional[int] = None   # owner column of a plain scalar started on this line
        if doc_marker:
            out.append(text[i:i + 3])
            i += 3
            expect, in_plain = True, False
        # ---------------------------------------------------------------- rest of the line
        while i < n and text[i] != "\n":
            c = text[i]
            col = i - line_start
            if c == "#" and (i == line_start or text[i - 1] in " \t"):
                end = text.find("\n", i)
                end = n if end == -1 else end
                out.append(text[i:end])
                i = end
                break
            if in_plain:
                if c == ":" and (_sep_after(text, i + 1) or (flow and text[i + 1:i + 2] in (",", "[", "]", "{", "}"))):
                    owner_col, in_plain, expect = node_col, False, True
                elif flow and c == ",":
                    in_plain, expect = False, True
                elif flow and c in "]}":
                    flow, in_plain, expect = max(flow - 1, 0), False, False
                out.append(c)
                i += 1
                continue
            if expect:
                if c in " \t\r":
                    out.append(c)
                    i += 1
                elif c in "-?:" and _sep_after(text, i + 1):
                    if c in "-?":
                        owner_col = col
                    else:      # ':' value indicator; for an explicit entry (no key on this line) its own column
                        owner_col = node_col if node_col is not None else col
                    out.append(c)
                    i += 1
                elif c in "[{":
                    flow += 1
                    out.append(c)
                    i += 1
                elif c in "]}":
                    flow, expect = max(flow - 1, 0), False
                    out.append(c)
                    i += 1
                elif c == "," and flow:
                    out.append(c)
                    i += 1
                elif c in "!&":                                  # tag / anchor property: node still expected
                    j = _token_end(text, i, flow)
                    out.append(text[i:j])
                    i = j
                elif c == "*":                                   # alias: a complete node
                    j = _token_end(text, i, flow)
                    out.append(text[i:j])
                    i, expect = j, False
                elif c == '"':
                    node_col = col
                    i = _yaml_double(text, i, out, res)
                    expect = False
                elif c == "'":
                    node_col = col
                    j = _yaml_single_end(text, i)
                    out.append(text[i:j])
                    i, expect = j, False
                elif c in "|>" and not flow:
                    j = i + 1
                    while j < n and text[j] in "+-0123456789":
                        j += 1
                    while j < n and text[j] in " \t":
                        j += 1
                    if j >= n or text[j] in "\r\n#":            # block scalar header
                        block_parent = owner_col if owner_col is not None else indent - 1
                        end = text.find("\n", i)
                        end = n if end == -1 else end
                        out.append(text[i:end])
                        i = end
                        break
                    node_col, in_plain, expect = col, True, False
                    plain_start_owner = owner_col if owner_col is not None else indent - 1
                    out.append(c)
                    i += 1
                else:                                            # plain scalar starts
                    node_col, in_plain, expect = col, True, False
                    plain_start_owner = owner_col if owner_col is not None else indent - 1
                    out.append(c)
                    i += 1
                continue
            # after a complete node (quoted scalar, alias, closing bracket)
            if c == ":":
                owner_col, expect = node_col, True               # also ':' right after a quoted key (JSON-style)
            elif flow and c == ",":
                expect = True
            elif flow and c in "]}":
                flow = max(flow - 1, 0)
            elif flow and c in "[{":
                flow, expect = flow + 1, True
            out.append(c)
            i += 1
        # ---------------------------------------------------------------- end of the line
        if in_plain and not flow:
            # continuation lines must be indented deeper than the key or '-' that owns the plain scalar
            plain_owner = plain_owner if continuation else plain_start_owner
        else:
            plain_owner = None
        expect_carry = expect or not in_plain
        if i < n and text[i] == "\n":
            out.append("\n")
            i += 1
    res.text = "".join(out)
    return res


# ------------------------------------------------------------------------------------------ dispatch

HCL_KINDS = ("terraform", "terraform-vars")
YAML_KINDS = ("yaml", "kubernetes", "helm-rendered")


def decoded_values(kind: str, text: str) -> Tuple[List[str], DecodeResult]:
    """(decoded values, full result) for a source of the given kind; ([], unchanged result) for other kinds."""
    if kind in HCL_KINDS:
        r = hcl_string_values(text)
    elif kind in YAML_KINDS:
        r = yaml_double_quoted_values(text)
    else:
        return [], DecodeResult(text=text)
    return r.values, r

"""Increment 2.2 - Terraform configuration checks over the HCL subset AST.

Rules (ADR-0001 section 4, amended by ADR-0002):
  TF-IAM-001/002  IAM wildcard permissions (inline policies, policy documents incl. source/override docs)
  TF-IAM-003      literal attachment of the AWS-managed AdministratorAccess policy
  TF-NET-001      public SSH/RDP ingress (prefix-0 CIDR, or literal CIDRs whose union is the whole space)
Only literal values can confirm a finding; dynamic or unparseable values yield ``insufficient_evidence``.
Comments are never analysed (the tokenizer drops them), and strings only count when they are the value
of the specific attribute that grants the permission. ``module`` calls are not analysed and make
coverage partial, because the module source is not part of the evidence.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .findings import CoverageNote, Evidence, FileCoverage, Finding, safe_token
from .hcl_subset import (Attribute, Block, Dyn, HclSyntaxError, HclUnsupported, Lit, Obj, Tuple_,
                         from_python, parse)
from .strict_json import StrictJsonError, load_strict

ANALYZER_ID = "terraform-static-analyzer"
ANALYZER_VERSION = "2"
RULES = ("TF-IAM-001", "TF-IAM-002", "TF-IAM-003", "TF-NET-001")

POLICY_RESOURCES = ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy")
ATTACHMENT_RESOURCES = ("aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment",
                        "aws_iam_group_policy_attachment", "aws_iam_policy_attachment")
SG_RESOURCES = ("aws_security_group", "aws_default_security_group")
ADMIN_POLICY_ARN = re.compile(r"\Aarn:aws[a-z-]*:iam::aws:policy/AdministratorAccess\Z")
DOC_MERGE_ATTRS = ("source_policy_documents", "override_policy_documents", "source_json", "override_json")
ADMIN_PORTS = (22, 3389)
_SERVICE_WILDCARD = re.compile(r"\A[a-z0-9-]+:\*\Z")
_DOC_REF = re.compile(r"\Adata\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.json\Z")
_NUMERIC = re.compile(r"\A[0-9]{1,5}\Z")
UNKNOWN = object()


class _Ctx:
    def __init__(self, path, sha, cov, policy_docs: Set[str]):
        self.path, self.sha, self.cov, self.findings, self.policy_docs = path, sha, cov, [], policy_docs

    def add(self, rule, category, severity, state, resource, ls, le, summary, rationale, check, observation,
            locator=""):
        if state == "insufficient_evidence":
            self.cov.status = "partial"
        ev = Evidence("source_lines", self.path, self.sha, ANALYZER_ID, ANALYZER_VERSION, rule,
                      observation, line_start=ls, line_end=le)
        finding = Finding(rule, category, severity, state, ANALYZER_ID, resource, self.path, self.sha,
                          summary, rationale, check, line_start=ls, line_end=le, evidence=[ev], locator=locator)
        self.findings.append(finding)
        return finding

    def insufficient(self, rule, category, resource, ls, le, what, locator=""):
        _f = self.add(rule, category, "unknown", "insufficient_evidence", resource, ls, le,
                 f"Could not evaluate {what}: value is dynamic, unparseable or unsupported.",
                 "The value depends on variables, references, functions or constructs outside the "
                 "supported subset, so the rule cannot be confirmed or excluded.",
                 "Review the resolved value (e.g. from a plan) manually.",
                 f"{what} is not an interpretable literal in the supported subset.", locator)
        _f.facts.update({"unresolved": what})  # Phase 3A typed facts (not serialized)
        return _f


# ----------------------------------------------------------------------------- value helpers
def _strings(node) -> Tuple[List[Tuple[str, int]], bool]:
    """Literal strings in a string-or-list node, plus whether any element is dynamic/non-string."""
    if node is None:
        return [], False
    if isinstance(node, Lit):
        return ([(node.value, node.line_start)], False) if isinstance(node.value, str) else ([], True)
    if isinstance(node, Tuple_):
        out, dyn = [], False
        for item in node.items:
            if isinstance(item, Lit) and isinstance(item.value, str):
                out.append((item.value, item.line_start))
            else:
                dyn = True
        return out, dyn
    return [], True


def _has_dynamic_key(node) -> bool:
    """A computed key ((expr) or "${...}") could name any attribute, so the object cannot be evaluated."""
    return isinstance(node, Obj) and any(not isinstance(k, str) for k, _ in node.items)


def _lit(node):
    if isinstance(node, Lit):
        return node.value
    return UNKNOWN


def _port(node):
    """Terraform converts numeric strings to numbers for number-typed attributes."""
    value = _lit(node)
    if isinstance(value, bool):
        return UNKNOWN
    if isinstance(value, int):
        return value
    if isinstance(value, str) and _NUMERIC.match(value):
        return int(value)
    return UNKNOWN


# ----------------------------------------------------------------------------- IAM
def _eval_statement(ctx: _Ctx, resource: str, st: Dict[str, object], span: Tuple[int, int],
                    has_condition: bool, has_not: bool, default_allow: bool, effect_node, locator: str) -> None:
    ls, le = span
    ctx.cov.count("TF-IAM-001")
    ctx.cov.count("TF-IAM-002")
    if effect_node is None:
        effect = "Allow" if default_allow else UNKNOWN
    else:
        effect = _lit(effect_node)
    if effect is UNKNOWN or not isinstance(effect, str) or effect not in ("Allow", "Deny"):
        # Non-canonical values (e.g. "allow") are not guessed either way (ADR-0002).
        ctx.insufficient("TF-IAM-001", "identity", resource, ls, le, "IAM statement effect", locator)
        return
    if effect != "Allow":
        return
    if has_not:
        ctx.insufficient("TF-IAM-001", "identity", resource, ls, le,
                         "IAM statement using NotAction/NotResource (not evaluated)", locator)
        return
    actions, act_dyn = _strings(st.get("actions"))
    resources, res_dyn = _strings(st.get("resources"))
    admin_action = [l for v, l in actions if v.lower() in ("*", "*:*")]
    svc_action = [l for v, l in actions if _SERVICE_WILDCARD.match(v.lower())]
    any_resource = any(v == "*" for v, _ in resources)
    state = "suspected" if has_condition else "confirmed_by_rule"
    cond_note = (" A Condition is present and may narrow the grant, so this is reported as suspected."
                 if has_condition else "")
    if admin_action and any_resource:
        _f = ctx.add("TF-IAM-001", "identity", "high", state, resource, ls, le,
                "IAM policy statement allows all actions on all resources.",
                "Effect is Allow with Action '*' and Resource '*', which is administrator-equivalent for the "
                "principal it is attached to." + cond_note,
                "Replace with least-privilege actions and resources; confirm which principals receive it.",
                f"Allow statement: wildcard action at line {admin_action[0]} and Resource '*'.", locator)
        _f.facts.update({"wildcard_action": next(v.lower() for v, _ in actions if v.lower() in ("*", "*:*")), "resource_all": True, "condition_present": has_condition})  # Phase 3A typed facts (not serialized)
        return
    if admin_action or svc_action:
        line = (admin_action or svc_action)[0]
        _f = ctx.add("TF-IAM-002", "identity", "medium", state, resource, ls, le,
                "IAM policy statement grants a wildcard action.",
                "Effect is Allow with an action of '*' or '<service>:*'; resources are scoped or not all "
                "literal, so it is rated medium rather than administrator-equivalent." + cond_note,
                "Narrow the action list to the operations actually required.",
                f"Allow statement: wildcard action at line {line}.", locator)
        _f.facts.update({"wildcard_action": next(v.lower() for v, _ in actions if v.lower() in ("*", "*:*") or _SERVICE_WILDCARD.match(v.lower())), "resource_all": any_resource, "condition_present": has_condition})  # Phase 3A typed facts (not serialized)
        if admin_action and res_dyn:
            ctx.insufficient("TF-IAM-001", "identity", resource, ls, le, "IAM statement resources", locator)
        return
    if act_dyn:
        ctx.insufficient("TF-IAM-001", "identity", resource, ls, le, "IAM statement actions", locator)


def _statement_line_spans(text: str) -> Optional[List[Tuple[int, int]]]:
    """0-based (first, last) line of each element of the top-level "Statement" in JSON ``text``.
    A small string-aware bracket scan; returns None if the shape is not as expected."""
    i, n, depth, expect_key, last_key = 0, len(text), 0, False, None
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                return None
            if depth == 1 and expect_key:
                try:
                    last_key = load_strict(text[i:j + 1])
                except StrictJsonError:
                    return None
            i = j + 1
            continue
        if c in "{[":
            depth += 1
            expect_key = c == "{"
        elif c in "}]":
            depth -= 1
        elif c == ",":
            expect_key = depth == 1
        elif c == ":" and depth == 1 and last_key == "Statement":
            k = i + 1
            while k < n and text[k] in " \t\r\n":
                k += 1
            if k >= n or text[k] not in "[{":
                return None
            return _element_spans(text, k)
        i += 1
    return None


def _element_spans(text: str, start: int) -> Optional[List[Tuple[int, int]]]:
    def close_of(pos: int) -> Optional[int]:
        d, k = 0, pos
        while k < len(text):
            ch = text[k]
            if ch == '"':
                k += 1
                while k < len(text) and text[k] != '"':
                    k += 2 if text[k] == "\\" else 1
            elif ch in "{[":
                d += 1
            elif ch in "}]":
                d -= 1
                if d == 0:
                    return k
            k += 1
        return None

    line = lambda pos: text.count("\n", 0, pos)  # noqa: E731
    if text[start] == "{":
        end = close_of(start)
        return None if end is None else [(line(start), line(end))]
    spans, k = [], start + 1
    while k < len(text):
        while k < len(text) and text[k] in " \t\r\n,":
            k += 1
        if k >= len(text) or text[k] == "]":
            return spans
        if text[k] != "{":
            return None
        end = close_of(k)
        if end is None:
            return None
        spans.append((line(k), line(end)))
        k = end + 1
    return None


def _json_policy_statements(ctx: _Ctx, resource: str, node, span, locator_prefix: str = "") -> None:
    """Statements of a JSON-form policy (jsonencode object or literal JSON string/heredoc)."""
    if isinstance(node, Lit) and isinstance(node.value, str) and not node.via_jsonencode:
        try:
            doc = load_strict(node.value)
        except StrictJsonError:
            ctx.insufficient("TF-IAM-001", "identity", resource, span[0], span[1], "policy JSON (not parseable)",
                             locator_prefix)
            return
        heredoc_base = node.line_start + 1 if node.from_heredoc else None
        raw_text = node.value
        node = from_python(doc, span[0], span[1])
        # Heredoc JSON maps line-for-line onto the file: give each statement its own interval.
        spans = _statement_line_spans(raw_text) if heredoc_base is not None else None
        statements = node.get("Statement") if isinstance(node, Obj) else None
        items = statements.items if isinstance(statements, Tuple_) else ([statements] if statements else [])
        if spans is not None and len(spans) == len(items):
            for st_node, (a, b) in zip(items, spans):
                _respan(st_node, heredoc_base + a, heredoc_base + b)
    if not isinstance(node, Obj) or _has_dynamic_key(node):
        ctx.insufficient("TF-IAM-001", "identity", resource, span[0], span[1], "policy document", locator_prefix)
        return
    statements = node.get("Statement")
    if statements is None:
        return
    items = statements.items if isinstance(statements, Tuple_) else [statements]
    for index, st in enumerate(items):
        loc = f"{locator_prefix}Statement[{index}]"
        if not isinstance(st, Obj) or _has_dynamic_key(st):
            ctx.insufficient("TF-IAM-001", "identity", resource, st.line_start, st.line_end, "IAM statement", loc)
            continue
        _eval_statement(ctx, resource,
                        {"actions": st.get("Action"), "resources": st.get("Resource")},
                        (st.line_start, st.line_end),
                        has_condition=st.get("Condition") is not None,
                        has_not=st.get("NotAction") is not None or st.get("NotResource") is not None,
                        default_allow=False, effect_node=st.get("Effect"), locator=loc)


def _policy_attr(ctx: _Ctx, resource: str, attr: Optional[Attribute], locator: str = "") -> None:
    if attr is None:
        return
    expr = attr.expr
    if isinstance(expr, Dyn):
        m = _DOC_REF.match(expr.text)
        if m and m.group(1) in ctx.policy_docs:
            return  # analysed where the policy document data source is declared
        ctx.insufficient("TF-IAM-001", "identity", resource, attr.line_start, attr.line_end, "policy attribute",
                         locator)
        return
    _json_policy_statements(ctx, resource, expr, (attr.line_start, attr.line_end), locator)


def _policy_document(ctx: _Ctx, resource: str, block: Block) -> None:
    for item in block.body:
        if isinstance(item, Block) and item.type == "dynamic":
            ctx.insufficient("TF-IAM-001", "identity", resource, item.line_start, item.line_end,
                             "dynamic statement block", f"dynamic@{item.line_start}")
    # Merged-in documents contribute statements too (ADR-0002).
    for name in DOC_MERGE_ATTRS:
        attr = block.attr(name)
        if attr is None:
            continue
        expr = attr.expr
        if isinstance(expr, Tuple_):
            for i, element in enumerate(expr.items):
                if isinstance(element, Dyn):
                    m = _DOC_REF.match(element.text)
                    if not (m and m.group(1) in ctx.policy_docs):
                        ctx.insufficient("TF-IAM-001", "identity", resource, element.line_start, element.line_end,
                                         f"{name} element", f"{name}[{i}]")
                    continue
                _json_policy_statements(ctx, resource, element, (element.line_start, element.line_end),
                                        f"{name}[{i}].")
        else:
            _policy_attr(ctx, resource, attr, f"{name}.")
    for index, st in enumerate(block.blocks("statement")):
        def val(name, _st=st):
            a = _st.attr(name)
            return a.expr if a else None
        _eval_statement(ctx, resource, {"actions": val("actions"), "resources": val("resources")},
                        (st.line_start, st.line_end),
                        has_condition=bool(st.blocks("condition")),
                        has_not=st.attr("not_actions") is not None or st.attr("not_resources") is not None,
                        default_allow=True, effect_node=val("effect"), locator=f"statement[{index}]")


def _attachment(ctx: _Ctx, resource: str, block: Block, attr_name: str = "policy_arn") -> None:
    attr = block.attr(attr_name)
    if attr is None:
        return
    ctx.cov.count("TF-IAM-003")
    values, dyn = _strings(attr.expr)
    if any(ADMIN_POLICY_ARN.match(v) for v, _ in values):
        _f = ctx.add("TF-IAM-003", "identity", "high", "confirmed_by_rule", resource, attr.line_start, attr.line_end,
                "The AWS-managed AdministratorAccess policy is attached.",
                "AdministratorAccess grants all actions on all resources to the attached principal.",
                "Attach a least-privilege policy instead; confirm which principal receives it.",
                "policy ARN literal is the AWS-managed AdministratorAccess policy.", attr_name)
        _f.facts.update({"policy_name": "AdministratorAccess"})  # Phase 3A typed facts (not serialized)
    elif dyn:
        ctx.insufficient("TF-IAM-003", "identity", resource, attr.line_start, attr.line_end, "attached policy ARN",
                         attr_name)


def _respan(node, ls: int, le: int) -> None:
    node.line_start, node.line_end = ls, le
    if isinstance(node, Obj):
        for _, v in node.items:
            _respan(v, ls, le)
    elif isinstance(node, Tuple_):
        for v in node.items:
            _respan(v, ls, le)


# ----------------------------------------------------------------------------- network
def _cidr_status(values: List[Tuple[str, int]]) -> Tuple[bool, bool, Optional[str]]:
    """(public, unparseable) for literal CIDR strings. Public = a prefix-0 network, or literal networks
    whose union covers the whole IPv4 or IPv6 space (e.g. 0.0.0.0/1 + 128.0.0.0/1)."""
    nets4, nets6, bad = [], [], False
    for v, _line in values:
        try:
            net = ipaddress.ip_network(v.strip(), strict=False)
        except ValueError:
            bad = True
            continue
        (nets4 if net.version == 4 else nets6).append(net)
    open_fams = []
    for nets, full, fam in ((nets4, ipaddress.ip_network("0.0.0.0/0"), "ipv4"),
                            (nets6, ipaddress.ip_network("::/0"), "ipv6")):
        if nets and list(ipaddress.collapse_addresses(nets)) == [full]:
            open_fams.append((fam, any(n.prefixlen == 0 for n in nets)))
    if not open_fams:
        return False, bad, None
    # Third value is a Phase 3A typed fact only (N3; never serialized): "dual_*" when both families are open.
    fam = open_fams[0][0] if len(open_fams) == 1 else "dual"
    return True, bad, fam + ("_all" if all(prefix0 for _f, prefix0 in open_fams) else "_union_all")


def _eval_ingress(ctx: _Ctx, resource: str, span, get, proto_key: str, cidr_keys: Sequence[str],
                  locator: str) -> None:
    ctx.cov.count("TF-NET-001")
    ls, le = span
    literal, unknown_cidr = [], False
    for key in cidr_keys:
        vals, dyn = _strings(get(key))
        literal.extend(vals)
        unknown_cidr = unknown_cidr or dyn
    public, unparseable, cidr_class = _cidr_status(literal)
    public_unknown = unknown_cidr or unparseable
    if not public and not public_unknown:
        return
    proto = _lit(get(proto_key))
    if proto is UNKNOWN or isinstance(proto, bool) or not isinstance(proto, (str, int)):
        admin = UNKNOWN
    else:
        p = str(proto).lower()
        if p in ("-1", "all"):
            admin = True
        elif p in ("tcp", "6", "udp", "17"):
            lo, hi = _port(get("from_port")), _port(get("to_port"))
            admin = UNKNOWN if (lo is UNKNOWN or hi is UNKNOWN) else any(lo <= port <= hi for port in ADMIN_PORTS)
        else:
            admin = False
    if admin is False:
        return
    if public and admin is True:
        _f = ctx.add("TF-NET-001", "network", "high", "confirmed_by_rule", resource, ls, le,
                "Ingress allows the whole internet to reach an administrative port (SSH 22 / RDP 3389).",
                "Literal source CIDRs cover the entire address space (0.0.0.0/0, ::/0, or an equivalent union) "
                "and the protocol/port range covers 22 or 3389. Exposure also depends on attachment and "
                "routing, which P02 does not evaluate.",
                "Restrict the source to known administrative ranges or use a bastion/SSM-style access path.",
                f"ingress rule spanning lines {ls}-{le}: whole-internet source with admin-port coverage.", locator)
        _f.facts.update({"ports": "all" if p in ("-1", "all") else [x for x in ADMIN_PORTS if lo <= x <= hi], "protocol": {"6": "tcp", "17": "udp", "-1": "all"}.get(p, p), "cidr_class": cidr_class})  # Phase 3A typed facts (not serialized)
    else:
        ctx.insufficient("TF-NET-001", "network", resource, ls, le, "ingress source CIDR/protocol/ports", locator)


def _sg_block_ingress(ctx: _Ctx, resource: str, block: Block) -> None:
    for item in block.body:
        if isinstance(item, Block) and item.type == "dynamic" and item.labels[:1] == ["ingress"]:
            ctx.insufficient("TF-NET-001", "network", resource, item.line_start, item.line_end,
                             "dynamic ingress block", f"dynamic@{item.line_start}")
    for index, ing in enumerate(block.blocks("ingress")):
        def get(name, _b=ing):
            a = _b.attr(name)
            return a.expr if a else None
        _eval_ingress(ctx, resource, (ing.line_start, ing.line_end), get, "protocol",
                      ("cidr_blocks", "ipv6_cidr_blocks"), f"ingress[{index}]")
    attr = block.attr("ingress")  # attributes-as-blocks form: ingress = [ { ... } ]
    if attr is not None:
        if isinstance(attr.expr, Tuple_):
            for index, obj in enumerate(attr.expr.items):
                if isinstance(obj, Obj) and not _has_dynamic_key(obj):
                    _eval_ingress(ctx, resource, (obj.line_start, obj.line_end), obj.get, "protocol",
                                  ("cidr_blocks", "ipv6_cidr_blocks"), f"ingress=[{index}]")
                else:
                    ctx.insufficient("TF-NET-001", "network", resource, obj.line_start, obj.line_end,
                                     "ingress list element", f"ingress=[{index}]")
        else:
            ctx.insufficient("TF-NET-001", "network", resource, attr.line_start, attr.line_end, "ingress attribute",
                             "ingress=")


def _sg_rule(ctx: _Ctx, resource: str, block: Block) -> None:
    def get(name):
        a = block.attr(name)
        return a.expr if a else None
    rtype = _lit(get("type"))
    if rtype == "egress":
        return
    if rtype != "ingress":
        ctx.insufficient("TF-NET-001", "network", resource, block.line_start, block.line_end,
                         "security group rule type")
        return
    _eval_ingress(ctx, resource, (block.line_start, block.line_end), get, "protocol",
                  ("cidr_blocks", "ipv6_cidr_blocks"), "")


def _vpc_ingress_rule(ctx: _Ctx, resource: str, block: Block) -> None:
    def get(name):
        a = block.attr(name)
        return a.expr if a else None
    _eval_ingress(ctx, resource, (block.line_start, block.line_end), get, "ip_protocol", ("cidr_ipv4", "cidr_ipv6"), "")


# ----------------------------------------------------------------------------- entry points
def declared_policy_documents(items) -> Set[str]:
    return {b.labels[1] for b in items if isinstance(b, Block) and b.type == "data"
            and len(b.labels) == 2 and b.labels[0] == "aws_iam_policy_document"}


def parse_file(text: str):
    """Returns (items, None) or (None, (status, note))."""
    try:
        return parse(text), None
    except HclUnsupported as exc:
        return None, ("unsupported", CoverageNote("HCL_UNSUPPORTED_CONSTRUCT",
                                                  f"Outside the supported HCL subset: {exc.message}.", exc.line))
    except HclSyntaxError as exc:
        return None, ("parse_error", CoverageNote("HCL_SYNTAX_ERROR", f"HCL syntax error: {exc.message}.", exc.line))


def analyze_terraform(path: str, sha256: str, items, kind: str, policy_docs: Set[str]) -> Tuple[FileCoverage, List[Finding]]:
    cov = FileCoverage(path, kind, ANALYZER_ID, ANALYZER_VERSION, "analyzed")
    ctx = _Ctx(path, sha256, cov, policy_docs)
    if kind == "terraform-vars":
        return cov, []  # variable values are parsed for well-formedness; no rule targets them directly
    for b in items:
        if isinstance(b, Block) and b.type == "module":
            cov.status = "partial"
            cov.notes.append(CoverageNote("MODULE_NOT_ANALYZED",
                                          f"Module call {safe_token(b.labels[0] if b.labels else '?', 60)} is not "
                                          "analysed: its source is not part of the evidence.", b.line_start))
            continue
        if not isinstance(b, Block) or b.type not in ("resource", "data") or len(b.labels) != 2:
            continue
        rtype, name = b.labels
        resource = safe_token(("data." if b.type == "data" else "") + f"{rtype}.{name}", 160)
        cov.objects_analyzed += 1
        if b.type == "resource" and rtype in POLICY_RESOURCES:
            _policy_attr(ctx, resource, b.attr("policy"))
        elif b.type == "resource" and rtype == "aws_iam_role":
            for i, ip in enumerate(b.blocks("inline_policy")):
                _policy_attr(ctx, resource, ip.attr("policy"), f"inline_policy[{i}].")
            _attachment(ctx, resource, b, "managed_policy_arns")
        elif b.type == "resource" and rtype in ATTACHMENT_RESOURCES:
            _attachment(ctx, resource, b)
        elif b.type == "data" and rtype == "aws_iam_policy_document":
            _policy_document(ctx, resource, b)
        elif b.type == "resource" and rtype in SG_RESOURCES:
            _sg_block_ingress(ctx, resource, b)
        elif b.type == "resource" and rtype == "aws_security_group_rule":
            _sg_rule(ctx, resource, b)
        elif b.type == "resource" and rtype == "aws_vpc_security_group_ingress_rule":
            _vpc_ingress_rule(ctx, resource, b)
    return cov, ctx.findings

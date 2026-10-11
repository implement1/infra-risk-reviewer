"""L2 workflow linter (05 sec. 4, invariants 1-11) with a small YAML-subset parser and a GitHub-expression
evaluator. Standard library only; no third-party linter.

Modes: "strict" (deployment: every action and runtime pin must be resolved) and "template" (the committed,
not-yet-deployed file: PIN_REQUIRED_* placeholders are accepted, everything else is enforced).
Linting a PR's own copy is advisory (02 sec. 5); it is binding only from a required workflow or under
code-owner review.
"""
import os
import re

GATE_EXPRESSION = ("${{ needs.review.outputs.ack == 'not-required' && 'p02-no-ack' || "
                   "'p02-risk-acknowledgement' }}")
ALLOWED_ACTIONS = ("actions/checkout", "actions/setup-python")
REQUIRED_TYPES = ["opened", "synchronize", "reopened", "edited"]
FORBIDDEN_TRIGGERS = ("pull_request_target", "workflow_run", "issue_comment")
REQUIRED_JOBS = ("review", "gate")
PIN_PLACEHOLDER = "PIN_REQUIRED_"


class WorkflowError(Exception):
    pass


# ============================================================================ YAML subset
_KEY_RE = re.compile(r"\A([A-Za-z0-9_.-]+|'[^']*'|\"[^\"]*\"):(?: (.*)|)\Z")


def _strip_comment(s):
    out, q = [], None
    for i, c in enumerate(s):
        if q:
            if c == q:
                q = None
        elif c in "'\"":
            q = c
        elif c == "#" and (i == 0 or s[i - 1] == " "):
            break
        out.append(c)
    return "".join(out).rstrip(" ")


def _scalar(v, lineno):
    v = v.strip(" ")
    if v == "":
        return None
    if v[0] in "&*!%@`" or v.startswith("? ") or v == "?":
        raise WorkflowError(f"line {lineno}: unsupported YAML feature")
    if v[0] == "'":
        if not v.endswith("'") or len(v) < 2:
            raise WorkflowError(f"line {lineno}: bad quoted scalar")
        return v[1:-1].replace("''", "'")
    if v[0] == '"':
        if not v.endswith('"') or len(v) < 2:
            raise WorkflowError(f"line {lineno}: bad quoted scalar")
        if "\\" in v:
            # R3 V3-02: YAML escape sequences (\x65, \u..., ...) are not decoded by this subset parser, so they
            # are refused rather than read differently from GitHub's parser.
            raise WorkflowError(f"line {lineno}: escape sequence in double-quoted scalar")
        return v[1:-1]
    if v[0] == "[":
        if not v.endswith("]"):
            raise WorkflowError(f"line {lineno}: bad flow sequence")
        inner = v[1:-1].strip()
        return [] if not inner else [_scalar(x, lineno) for x in inner.split(",")]
    if v[0] == "{":
        if not v.endswith("}"):
            raise WorkflowError(f"line {lineno}: bad flow mapping")
        inner = v[1:-1].strip()
        out = {}
        if inner:
            for part in inner.split(","):
                if ":" not in part:
                    raise WorkflowError(f"line {lineno}: bad flow mapping")
                k, val = part.split(":", 1)
                k = k.strip(" ")
                if not re.fullmatch(r"[A-Za-z0-9_.-]+", k):
                    # R4 V4-01: quoted or unusual flow-mapping keys are refused (a YAML parser would unquote them).
                    raise WorkflowError(f"line {lineno}: unsupported flow-mapping key")
                if k in out:
                    raise WorkflowError(f"line {lineno}: duplicate key")
                out[k] = _scalar(val, lineno)
        return out
    if v in ("true", "True"):
        return True
    if v in ("false", "False"):
        return False
    if v in ("null", "~"):
        return None
    if re.fullmatch(r"-?[0-9]+", v):
        return int(v)
    return v


class _Parser:
    def __init__(self, text):
        # R3 V3-02: only printable ASCII and LF. Unicode spaces and line breaks (NBSP, U+2028, U+0085, ...) and
        # CR are read differently by full YAML parsers, so they are refused.
        bad = [c for c in text if not (" " <= c <= "~" or c == "\n")]
        if bad:
            raise WorkflowError(f"character outside printable ASCII: U+{ord(bad[0]):04X}")
        if "\t" in "".join(l[: len(l) - len(l.lstrip(" \t"))] for l in text.split("\n")):
            raise WorkflowError("tab indentation")
        self.raw = text.split("\n")
        for n, l in enumerate(self.raw, 1):
            if l.startswith("---") or l.startswith("%") or l.startswith("..."):
                raise WorkflowError(f"line {n}: multi-document or directive")

    def _sig(self, i):
        while i < len(self.raw):
            s = self.raw[i].strip()
            if s and not s.startswith("#"):
                return i
            i += 1
        return i

    def _indent(self, i):
        l = self.raw[i]
        return len(l) - len(l.lstrip(" "))

    def parse(self):
        i = self._sig(0)
        if i >= len(self.raw):
            raise WorkflowError("empty")
        node, i = self._block(i, self._indent(i))
        i = self._sig(i)
        if i < len(self.raw):
            raise WorkflowError(f"line {i + 1}: unexpected indentation")
        return node

    def _block(self, i, indent, first=None):
        text = first if first is not None else self.raw[i].strip()
        if text == "-" or text.startswith("- "):
            return self._seq(i, indent)
        return self._map(i, indent, first)

    def _seq(self, i, indent):
        out = []
        while True:
            i = self._sig(i)
            if i >= len(self.raw) or self._indent(i) != indent:
                return out, i
            text = _strip_comment(self.raw[i].strip())
            if not (text == "-" or text.startswith("- ")):
                return out, i
            item = text[2:].strip() if text != "-" else ""
            if item == "":
                j = self._sig(i + 1)
                node, i = self._block(j, self._indent(j))
                out.append(node)
            elif _KEY_RE.match(item):
                node, i = self._map(i, indent + 2, first=item)
                out.append(node)
            else:
                out.append(_scalar(item, i + 1))
                i += 1

    def _map(self, i, indent, first=None):
        out = {}
        use_first = first is not None
        while True:
            if not use_first:
                i = self._sig(i)
                if i >= len(self.raw) or self._indent(i) != indent:
                    return out, i
                text = _strip_comment(self.raw[i].strip())
                if text == "-" or text.startswith("- "):
                    return out, i
            else:
                text = _strip_comment(first)
                use_first = False
            m = _KEY_RE.match(text)
            if not m:
                raise WorkflowError(f"line {i + 1}: expected 'key: value'")
            key = m.group(1)
            if key[:1] == '"' and "\\" in key:
                raise WorkflowError(f"line {i + 1}: escape sequence in quoted key")
            key = key.strip("'\"")
            if key in out:
                raise WorkflowError(f"line {i + 1}: duplicate key {key}")
            val = (m.group(2) or "").strip()
            if val in ("|", "|-", ">", ">-", "|+"):
                body, i = self._block_scalar(i + 1, indent, val)
                out[key] = body
            elif val == "":
                j = self._sig(i + 1)
                if j < len(self.raw) and (self._indent(j) > indent or (
                        self._indent(j) == indent and self.raw[j].strip().startswith("- "))):
                    node, i = self._block(j, self._indent(j))
                    out[key] = node
                else:
                    out[key] = None
                    i += 1
            else:
                out[key] = _scalar(val, i + 1)
                i += 1

    def _block_scalar(self, i, parent_indent, style):
        lines = []
        content_indent = None
        while i < len(self.raw):
            l = self.raw[i]
            if l.strip() == "":
                lines.append("")
                i += 1
                continue
            ind = len(l) - len(l.lstrip(" "))
            if ind <= parent_indent:
                break
            if content_indent is None:
                content_indent = ind
            if ind < content_indent:
                break
            lines.append(l[content_indent:])
            i += 1
        while lines and lines[-1] == "":
            lines.pop()
        sep = "\n" if style.startswith("|") else " "
        body = sep.join(lines)
        if not style.endswith("-"):
            body += "\n"
        return body, i


def load_text(text):
    return _Parser(text).parse()


def load_workflow(path):
    with open(path, encoding="utf-8", newline="") as fh:  # keep CR visible (refused)
        return load_text(fh.read())


# ============================================================================ expressions
def normalize_expr(s):
    return re.sub(r"\s+", " ", str(s).strip())


_TOKEN = re.compile(r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<num>-?[0-9]+(?:\.[0-9]+)?)|(?P<op>==|!=|&&|\|\||!|\(|\))|"
                    r"(?P<id>[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*))")


def _tokens(expr):
    pos, out = 0, []
    while pos < len(expr):
        if expr[pos:].strip() == "":
            break
        m = _TOKEN.match(expr, pos)
        if not m:
            raise WorkflowError("expression syntax")
        pos = m.end()
        if m.group("str") is not None:
            out.append(("lit", m.group("str")[1:-1].replace("''", "'")))
        elif m.group("num") is not None:
            out.append(("lit", float(m.group("num"))))
        elif m.group("op") is not None:
            out.append(("op", m.group("op")))
        else:
            ident = m.group("id")
            if ident == "null":
                out.append(("lit", None))
            elif ident in ("true", "false"):
                out.append(("lit", ident == "true"))
            else:
                out.append(("ref", ident))
    return out


def _num(v):
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        return float(v)
    s = v.strip()
    if s == "":
        return 0.0
    try:
        return float(int(s, 0)) if s.lower().startswith(("0x", "0o")) else float(s)
    except ValueError:
        return float("nan")


def _eq(a, b):
    if type(a) is type(b) and isinstance(a, str):
        return a.lower() == b.lower()
    if type(a) is type(b) and a is None:
        return True
    x, y = _num(a), _num(b)
    return x == y  # NaN never equal


def _truthy(v):
    if v is None or v is False:
        return False
    if isinstance(v, float):
        return not (v == 0 or v != v)
    if isinstance(v, str):
        return v != ""
    return True


def evaluate(expr, ctx):
    """Evaluate a `${{ ... }}` expression with GitHub semantics (case-insensitive string equality; loose
    coercion to numbers across types; && and || return operands)."""
    s = expr.strip()
    if s.startswith("${{") and s.endswith("}}"):
        s = s[3:-2]
    toks = _tokens(s)
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else (None, None)

    def take():
        t = peek()
        pos[0] += 1
        return t

    def primary():
        kind, val = take()
        if kind == "lit":
            return val
        if kind == "ref":
            cur = ctx
            for part in val.split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
            return cur
        if (kind, val) == ("op", "("):
            v = or_()
            if take() != ("op", ")"):
                raise WorkflowError("missing )")
            return v
        if (kind, val) == ("op", "!"):
            return not _truthy(primary())
        raise WorkflowError("unexpected token")

    def eq_():
        left = primary()
        while peek() in (("op", "=="), ("op", "!=")):
            op = take()[1]
            right = primary()
            left = _eq(left, right) if op == "==" else not _eq(left, right)
        return left

    def and_():
        left = eq_()
        while peek() == ("op", "&&"):
            take()
            right = eq_()
            left = right if _truthy(left) else left
        return left

    def or_():
        left = and_()
        while peek() == ("op", "||"):
            take()
            right = and_()
            left = left if _truthy(left) else right
        return left

    result = or_()
    if pos[0] != len(toks):
        raise WorkflowError("trailing tokens")
    return result


# ============================================================================ lint
_PY_RE = re.compile(r"(?<![\w$-])(python3?(?:\.[0-9]+)?|\"\$PY\"|\$PY)(?![\w.])")
_CD_PR_RE = re.compile(r"\b(cd|pushd)\b[^\n;&|]*?[\s\"'](\./)?(\$\{?GITHUB_WORKSPACE\}?/)?pr(?![\w.-])")
_PR_REF_RE = re.compile(r"(?<![\w./-])(\./)?pr/|\$\{?GITHUB_WORKSPACE\}?/pr(?![\w.-])")
_ENV_FILE_RE = re.compile(r"GITHUB_PATH|GITHUB_ENV|BASH_ENV")
# R1 V1-05: the adapter step's run body must be exactly this (pins and an optional absolute LD_LIBRARY_PATH,
# A-8, are the only variable parts), so no extra interpreter flag, variable or argument can slip in.
ADAPTER_RUN_RE = re.compile(
    r"\Aset -eu\n"
    r"if \[ ! -f \"\$GITHUB_WORKSPACE/trusted/ci/p02ci/__main__\.py\" \]; then\n"
    r"  printf '%s\\n' '## P02 Infrastructure Risk Review -- TECHNICAL FAILURE -- no assessment produced' \\\n"
    r"    'The base commit has no P02 adapter \(bootstrap pull request\); P02 verdict not available\. Code owners "
    r"review this pull request manually\.' \\\n"
    r"    >> \"\$GITHUB_STEP_SUMMARY\"\n"
    r"  exit 1\n"
    r"fi\n"
    r"PY=\"\$\(command -v python3\)\"\n"
    r"W=\"\$\(mktemp -d \"\$RUNNER_TEMP/p02cwd\.XXXXXX\"\)\"\n"
    r"cd \"\$W\"\n"
    r"exec env -i PATH=\"\$PATH\" PYTHONPATH=\"\$GITHUB_WORKSPACE/trusted/src:\$GITHUB_WORKSPACE/trusted/ci\" "
    r"PYTHONDONTWRITEBYTECODE=1 (?:LD_LIBRARY_PATH=\"/opt/hostedtoolcache/Python/3\.13\.[0-9]+/x64/lib\" )?"
    r"RUNNER_TEMP=\"\$RUNNER_TEMP\" "
    r"GITHUB_OUTPUT=\"\$GITHUB_OUTPUT\" GITHUB_STEP_SUMMARY=\"\$GITHUB_STEP_SUMMARY\" "
    r"P02_BASE_SHA=\"\$P02_BASE_SHA\" P02_HEAD_SHA=\"\$P02_HEAD_SHA\" \"\$PY\" -P -s -B -m p02ci "
    r"--pr-dir \"\$GITHUB_WORKSPACE/pr\"(?: --expect-core-digest [0-9a-f]{64})+(?: --expect-adapter-digest "
    r"(?:[0-9a-f]{64}))+\n\Z")
_METADATA_RE = re.compile(r"169\.254\.169\.254|metadata\.google\.internal|ACTIONS_ID_TOKEN_REQUEST|"
                          r"ACTIONS_RUNTIME_TOKEN|id-token", re.IGNORECASE)


def _steps(job):
    steps = job.get("steps") if isinstance(job, dict) else None
    return steps if isinstance(steps, list) else []


def _walk_keys(node, key):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                yield v
            yield from _walk_keys(v, key)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_keys(v, key)


def _python_problems(run):
    probs = []
    for line in run.split("\n"):
        if "command -v python" in line:
            continue
        for m in _PY_RE.finditer(line):
            rest = line[m.end():]
            if not rest.startswith(" -P -s -B"):
                probs.append("inv10: python invocation without -P -s -B")
    return probs


def _pythonpath_problems(run):
    probs = []
    found = False
    for m in re.finditer(r"PYTHONPATH=(\"[^\"]*\"|'[^']*'|\S+)", run):
        found = True
        val = m.group(1).strip("\"'")
        for seg in val.split(":"):
            if not seg:
                probs.append("inv10: empty PYTHONPATH segment")
            elif not seg.startswith("$GITHUB_WORKSPACE/trusted/"):
                if "/pr/" in seg or seg.startswith("$GITHUB_WORKSPACE/pr"):
                    probs.append("inv8: PYTHONPATH reaches the PR checkout")
                probs.append("inv10: PYTHONPATH entry not absolute under the trusted checkout")
    return probs, found


BASE_SHA_EXPR = "${{ github.event.pull_request.base.sha }}"
HEAD_SHA_EXPR = "${{ github.event.pull_request.head.sha }}"
GATE_STEPS = [{"run": 'echo "P02 acknowledgement recorded or not requested"'}]
TOP_KEYS = {"name", "on", "permissions", "concurrency", "jobs"}
REVIEW_KEYS = {"runs-on", "timeout-minutes", "permissions", "outputs", "steps"}
GATE_KEYS = {"needs", "runs-on", "timeout-minutes", "permissions", "environment", "steps"}


def _structure_problems(wf):
    """R2 V2-03: the workflow's shape is fixed. The review job has exactly the four specified steps with exact
    `with:` maps, the adapter step only the two event-SHA env entries, and the gate job one fixed step."""
    p = []
    if set(wf) != TOP_KEYS:
        p.append("inv8: workflow top-level keys must be exactly name, on, permissions, concurrency, jobs")
    jobs = wf.get("jobs") if isinstance(wf.get("jobs"), dict) else {}
    review, gate = jobs.get("review") or {}, jobs.get("gate") or {}
    if isinstance(review, dict) and set(review) != REVIEW_KEYS:
        p.append("inv8: review job keys must be exactly runs-on, timeout-minutes, permissions, outputs, steps")
    if isinstance(gate, dict) and set(gate) != GATE_KEYS:
        p.append("inv9: gate job keys must be exactly needs, runs-on, timeout-minutes, permissions, environment, steps")
    steps = review.get("steps") if isinstance(review, dict) else None
    if not isinstance(steps, list) or len(steps) != 4 or not all(isinstance(s, dict) for s in steps):
        p.append("inv8: review job must have exactly the four specified steps")
        return p
    pr, trusted, setup, adapter = steps
    def uses(s, action):
        return isinstance(s.get("uses"), str) and s["uses"].startswith(action + "@") and set(s) <= {"name", "uses", "with"}
    if not uses(pr, "actions/checkout") or pr.get("with") != {"path": "pr", "persist-credentials": False,
                                                                "fetch-depth": 0}:
        p.append("inv8: step 1 must check out the PR merge commit into pr/ exactly as specified")
    if not uses(trusted, "actions/checkout") or trusted.get("with") != {
            "ref": BASE_SHA_EXPR, "path": "trusted", "persist-credentials": False, "sparse-checkout": "ci\nsrc\nschema\n"}:
        p.append("inv8: step 2 must check out the trusted bundle at the base commit exactly as specified")
    if not uses(setup, "actions/setup-python") or set(setup.get("with") or {}) != {"python-version"}:
        p.append("inv8: step 3 must be setup-python with python-version only")
    if set(adapter) != {"id", "name", "env", "run"} or adapter.get("id") != "adapter":
        p.append("inv8: step 4 must be the adapter step (id, name, env, run only)")
    if adapter.get("env") != {"P02_BASE_SHA": BASE_SHA_EXPR, "P02_HEAD_SHA": HEAD_SHA_EXPR}:
        p.append("inv5: adapter env must pass exactly the event base and head SHAs")
    if isinstance(gate, dict) and gate.get("steps") != GATE_STEPS:
        p.append("inv9: gate job must have exactly the one fixed step")
    return p


def lint_text(text, mode="strict"):
    try:
        wf = load_text(text)
    except WorkflowError as exc:
        return [f"parse: {exc}"]
    p = []
    if not isinstance(wf, dict):
        return ["parse: top level must be a mapping"]
    # inv1 -----------------------------------------------------------------
    on = wf.get("on")
    if not isinstance(on, dict) or set(on) != {"pull_request"}:
        p.append("inv1: trigger set must be exactly pull_request")
    else:
        pr = on["pull_request"]
        if not isinstance(pr, dict) or set(pr) != {"types"} or pr.get("types") != REQUIRED_TYPES:
            p.append("inv1: pull_request must list types [opened, synchronize, reopened, edited] and no filters")
    for t in FORBIDDEN_TRIGGERS:
        if isinstance(on, dict) and t in on:
            p.append(f"inv1: forbidden trigger {t}")
    # top-level keys --------------------------------------------------------
    for k in ("defaults",):
        if k in wf:
            p.append("inv11: workflow-level defaults are not allowed")
    if "env" in wf:
        p.append("inv6: workflow-level env is not allowed")
    # inv2 -----------------------------------------------------------------
    if wf.get("permissions") != {}:
        p.append("inv2: workflow-level permissions must be {}")
    jobs = wf.get("jobs") if isinstance(wf.get("jobs"), dict) else {}
    if set(jobs) != set(REQUIRED_JOBS):
        p.append("inv9: jobs must be exactly review and gate")
    review, gate = jobs.get("review") or {}, jobs.get("gate") or {}
    if review.get("permissions") != {"contents": "read"}:
        p.append("inv2: review permissions must be exactly contents: read")
    if gate.get("permissions") != {}:
        p.append("inv2: gate permissions must be {}")
    # per job --------------------------------------------------------------
    for name, job in jobs.items():
        if not isinstance(job, dict):
            p.append(f"inv9: job {name} malformed")
            continue
        if "if" in job:
            p.append(f"inv9: required job {name} has an if: condition")
        if "name" in job:
            p.append(f"inv9: job {name} overrides its check name")
        if "continue-on-error" in job:
            p.append(f"inv9: job {name} has continue-on-error")
        if job.get("runs-on") != "ubuntu-24.04":
            p.append(f"inv6: job {name} must run on ubuntu-24.04 (GitHub-hosted)")
        t = job.get("timeout-minutes")
        if not isinstance(t, int) or isinstance(t, bool) or not 1 <= t <= 30:
            p.append(f"inv7: job {name} needs timeout-minutes")
        for k in ("env", "container", "services", "defaults", "strategy"):
            if k in job:
                p.append(("inv11" if k == "defaults" else "inv6") + f": job {name} may not set {k}")
        for st in _steps(job):
            if not isinstance(st, dict):
                p.append(f"inv9: step in {name} malformed")
                continue
            if "if" in st:
                p.append(f"inv9: step in required job {name} has an if: condition")
            if "continue-on-error" in st:
                p.append(f"inv9: step in required job {name} has continue-on-error")
            if "working-directory" in st:
                p.append(f"inv11: step in {name} sets working-directory")
            if "shell" in st:
                p.append(f"inv10: step in {name} sets shell: (interpreter outside the -P -s -B rule)")
            uses = st.get("uses")
            if uses is not None:
                m = re.fullmatch(r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@(\S+)", str(uses))
                if not m:
                    p.append(f"inv3: malformed uses {uses}")
                else:
                    action, ref = m.groups()
                    if action == "actions/cache":
                        p.append("inv6: actions/cache is not allowed")
                    if action not in ALLOWED_ACTIONS:
                        p.append(f"inv3: action {action} not in the Mode A allow-list")
                    if ref.startswith(PIN_PLACEHOLDER):
                        if mode == "strict":
                            p.append(f"inv3: pin pending {ref}")
                    elif not re.fullmatch(r"[0-9a-f]{40}", ref):
                        p.append(f"inv3: {action} not pinned to a full commit SHA")
                    with_ = st.get("with") or {}
                    if action == "actions/checkout" and with_.get("persist-credentials") is not False:
                        p.append("inv4: checkout without persist-credentials: false")
                    if action == "actions/setup-python":
                        pv = str(with_.get("python-version", ""))
                        if pv.startswith("3.13." + PIN_PLACEHOLDER):
                            if mode == "strict":
                                p.append(f"inv3: python runtime pin pending ({PIN_PLACEHOLDER}patch)")
                        elif not re.fullmatch(r"3\.13\.[0-9]+", pv):
                            p.append("inv3: python-version must be an exact 3.13 patch release")
            run = st.get("run")
            if run is not None:
                run = str(run)
                if "${{" in run:
                    p.append("inv5: expression inside run:")
                if _CD_PR_RE.search(run):
                    p.append("inv11: run changes directory into the PR checkout")
                if _METADATA_RE.search(run):
                    p.append("inv6: credential or metadata endpoint access in run:")
                if _ENV_FILE_RE.search(run):
                    p.append("inv10: run: writes GITHUB_PATH / GITHUB_ENV / BASH_ENV (could substitute tools)")
                if st.get("id") != "adapter" and _PR_REF_RE.search(run):
                    p.append("inv11: run: references the PR checkout (PR content must never be executed)")
                p.extend(_python_problems(run))
    # inv6 text-level -----------------------------------------------------
    if re.search(r"\bsecrets\b", text, re.IGNORECASE):
        p.append("inv6: secrets context reference (any form: secrets.X, secrets['X'], toJSON(secrets), inherit)")
    for nm in _walk_keys(wf, "name"):
        if "${{" in str(nm):
            p.append("inv5: expression in a name: (R4 V4-02)")
    if re.search(r"id-token", text, re.IGNORECASE):
        p.append("inv6: id-token permission or reference")
    if "self-hosted" in text:
        p.append("inv6: self-hosted runner label")
    # inv8 / inv10 / adapter step -----------------------------------------
    steps = _steps(review)
    checkouts = [s for s in steps if isinstance(s, dict) and str(s.get("uses", "")).startswith("actions/checkout@")]
    trusted = [s for s in checkouts if (s.get("with") or {}).get("path") == "trusted"]
    if len(trusted) != 1 or (trusted[0].get("with") or {}).get("ref") != "${{ github.event.pull_request.base.sha }}":
        p.append("inv8: trusted bundle must be checked out at the PR base commit into trusted/")
    if not any((s.get("with") or {}).get("path") == "pr" for s in checkouts):
        p.append("inv8: PR content must be checked out into pr/ as data")
    if sorted((s.get("with") or {}).get("path") for s in checkouts) != ["pr", "trusted"]:
        p.append("inv8: exactly two checkouts, into pr/ and trusted/, are allowed")
    adapter = [s for s in steps if isinstance(s, dict) and s.get("id") == "adapter"]
    if len(adapter) != 1 or not isinstance(adapter[0].get("run"), str):
        p.append("inv9: the adapter step (id: adapter) is missing")
    else:
        run = adapter[0]["run"]
        pp, found = _pythonpath_problems(run)
        p.extend(pp)
        if not found:
            p.append("inv10: adapter PYTHONPATH not set")
        if "exec env -i " not in run:
            p.append("inv10: adapter must be launched with env -i and the explicit allow-list")
        if "-m p02ci" not in run or "--pr-dir \"$GITHUB_WORKSPACE/pr\"" not in run:
            p.append("inv8: adapter invocation must analyse pr/ with the trusted bundle")
        if not ADAPTER_RUN_RE.match(run):
            p.append("inv10: adapter run body differs from the specified command (no extra flags or variables)")
        if "trusted/ci/p02ci/__main__.py" not in run:
            p.append("inv8: bootstrap guard for a base commit without the adapter is missing")
        envs = adapter[0].get("env") or {}
        if set(envs) - {"P02_BASE_SHA", "P02_HEAD_SHA"}:
            p.append("inv5: adapter step env may only pass the base and head SHAs")
    # inv9 gate -------------------------------------------------------------
    if review.get("outputs") != {"ack": "${{ steps.adapter.outputs.ack }}"}:
        p.append("inv9: review must output ack from the adapter step only")
    if gate.get("needs") != "review":
        p.append("inv9: gate must need review")
    env = gate.get("environment")
    if not isinstance(env, str) or normalize_expr(env) != normalize_expr(GATE_EXPRESSION):
        p.append("inv9: gate environment must be the fail-closed expression")
    for st in _steps(gate):
        if not isinstance(st, dict) or "uses" in st or set(st) - {"run", "name"}:
            p.append("inv9: gate steps must be fixed run steps only")
        elif "${{" in str(st.get("run", "")):
            p.append("inv5: expression inside gate run:")
    p.extend(_structure_problems(wf))
    for job in jobs.values():
        for st in _steps(job):
            if isinstance(st, dict) and st.get("id") != "adapter":
                if "env" in st:
                    p.append("inv10: step-level env outside the adapter step (BASH_ENV, PATH, ... substitution)")
                run = str(st.get("run", ""))
                if re.search(r"(?<![\w.-])trusted/|(?<![\w.-])pr(?![\w.-])|GITHUB_STEP_SUMMARY|GITHUB_OUTPUT", run):
                    p.append("inv11: run: outside the adapter touches pr/, trusted/ or the job outputs")
    # inv11 ------------------------------------------------------------------
    for _ in _walk_keys(wf, "working-directory"):
        p.append("inv11: working-directory is not allowed")
        break
    if wf.get("concurrency") != {"group": "p02-review-${{ github.event.pull_request.number }}",
                                 "cancel-in-progress": True}:
        p.append("inv9: per-PR concurrency group with cancel-in-progress: true is required (E2E-32)")
    return sorted(set(p))


def _check_names(wf):
    """Job IDs and names, lower-cased (GitHub's case handling of check names is not relied on); an
    expression-valued name is reported as '${{...}}' because it can evaluate to a required check name."""
    names = set()
    jobs = wf.get("jobs") if isinstance(wf, dict) and isinstance(wf.get("jobs"), dict) else {}
    for jid, job in jobs.items():
        names.add(str(jid).lower())
        if isinstance(job, dict) and job.get("name") is not None:
            n = str(job["name"])
            names.add("${{...}}" if "${{" in n else n.strip().lower())
    return names


def lint_directory(directory, mode="strict"):
    """Lint p02-review.yml and check every other workflow for privileged triggers and for job IDs or names that
    duplicate the required check names `review` / `gate` (A-5, T-CI-17)."""
    problems = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(directory, name)
        with open(path, encoding="utf-8", newline="") as fh:  # keep CR visible (refused)
            text = fh.read()
        if name == "p02-review.yml":
            problems += [f"{name}: {x}" if not x.startswith(("inv", "parse")) else x for x in lint_text(text, mode)]
            continue
        try:
            wf = load_text(text)
        except WorkflowError as exc:
            problems.append(f"parse: {name}: {exc}")
            continue
        if not isinstance(wf, dict) or not isinstance(wf.get("jobs"), dict):
            problems.append(f"parse: {name}: workflow must be a mapping with a jobs mapping (R4 V4-06)")
            continue
        on = wf.get("on")
        if isinstance(on, dict):
            triggers = set(on)
        elif isinstance(on, str):
            triggers = {on}
        elif isinstance(on, list):
            triggers = {str(x) for x in on}
        else:
            triggers = set()
        for t in FORBIDDEN_TRIGGERS:
            if t in triggers:
                problems.append(f"inv1: {name}: forbidden trigger {t}")
        names = _check_names(wf)  # (wf is a mapping with a jobs mapping here)
        for d in sorted((names & set(REQUIRED_JOBS)) | ({"${{...}}"} & names)):
            problems.append(f"dup: {name}: job or check name '{d}' duplicates (or may evaluate to) a required "
                            "P02 check")
        # R5 V5-01: GitHub context names are not case-sensitive, so neither is this check.
        if re.search(r"\bsecrets\b|id-token", text, re.IGNORECASE):
            problems.append(f"inv6: {name}: secrets or id-token reference")
        # R3 V3-06: a workflow that can write commit statuses or check runs could forge a required check; the
        # default token permissions apply when `permissions:` is absent.
        perms = wf.get("permissions", "absent")
        job_perms = [j.get("permissions") for j in wf["jobs"].values() if isinstance(j, dict) and "permissions" in j]
        for pv in [perms] + job_perms:
            if pv == "absent" or isinstance(pv, str) or (isinstance(pv, dict) and any(
                    v not in ("read", "none") for v in pv.values())):
                problems.append(f"inv2: {name}: permissions must be explicit and read-only (status/check forgery)")
                break
    return problems


def main(argv=None):
    """python3 -B ci/tests/wflint.py [--template] [WORKFLOW_DIR]  (default .github/workflows, strict mode)."""
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    mode = "template" if "--template" in args else "strict"
    args = [a for a in args if a != "--template"]
    directory = args[0] if args else os.path.join(".github", "workflows")
    problems = lint_directory(directory, mode=mode)
    for p in problems:
        print(p)
    print(f"wflint: mode={mode} problems={len(problems)}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())

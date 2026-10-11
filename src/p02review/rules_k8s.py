"""Increment 2.3 - Kubernetes manifest checks (also used for submitted rendered Helm output).

Helm is never executed: only rendered YAML present in the fixture is analysed. Template and
values combinations that are not in evidence have not been tested.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from .findings import CoverageNote, Evidence, FileCoverage, Finding, safe_token
from .yaml_subset import (YamlSyntaxError, YamlUnsupported, YDocument, YMap, YScalar, YSeq,
                          parse_documents)

ANALYZER_ID = "kubernetes-manifest-analyzer"
ANALYZER_VERSION = "2"
RULES = ("K8S-PRIV-001", "K8S-HOSTNET-001", "K8S-RBAC-001", "K8S-RBAC-002", "K8S-IMG-001", "K8S-RES-001")

POD_SPEC_PATHS = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "ReplicationController": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}
RBAC_KINDS = ("Role", "ClusterRole")
NO_CHECK_KINDS = frozenset((
    "Service", "ConfigMap", "Namespace", "ServiceAccount", "Ingress", "NetworkPolicy",
    "PersistentVolumeClaim", "PersistentVolume", "HorizontalPodAutoscaler", "PodDisruptionBudget",
    "RoleBinding", "ClusterRoleBinding", "LimitRange", "ResourceQuota", "StorageClass", "PriorityClass",
))
CONTAINER_LISTS = ("containers", "initContainers", "ephemeralContainers")
# Top-level fields of the kinds that rules evaluate; anything else means the object is not understood.
KNOWN_TOP_LEVEL = {"workload": frozenset(("apiVersion", "kind", "metadata", "spec", "status")),
                   "rbac": frozenset(("apiVersion", "kind", "metadata", "rules", "aggregationRule"))}
_TRUE = ("true", "True", "TRUE")
_FALSE = ("false", "False", "FALSE")
_YAML11_BOOLS = frozenset(("y", "Y", "yes", "Yes", "YES", "n", "N", "no", "No", "NO",
                           "on", "On", "ON", "off", "Off", "OFF"))


def _bool(node) -> object:
    """True / False / None (absent or null) / 'ambiguous'."""
    if node is None:
        return None
    if isinstance(node, YScalar) and node.style == "plain":
        if node.is_null:
            return None
        if node.text in _TRUE:
            return True
        if node.text in _FALSE:
            return False
        if node.text in _YAML11_BOOLS:
            return "ambiguous"
    return "ambiguous"


def _key_line(mapping: YMap, key: str) -> int:
    for k, line, _v in mapping.items:
        if k == key:
            return line
    return mapping.line_start


def _get_path(node, path) -> Optional[object]:
    for key in path:
        if not isinstance(node, YMap):
            return None
        node = node.get(key)
    return node


def _scalar_text(node) -> Optional[str]:
    return node.text if isinstance(node, YScalar) and not node.is_null else None


def _str_list(node) -> Tuple[List[Tuple[str, int]], bool]:
    """Strings of a sequence node, plus whether shape was unexpected."""
    if node is None:
        return [], False
    if isinstance(node, YSeq):
        out, odd = [], False
        for item in node.items:
            if isinstance(item, YScalar) and not item.is_null:
                out.append((item.text, item.line_start))
            else:
                odd = True
        return out, odd
    return [], True


class _Ctx:
    def __init__(self, path, sha, cov):
        self.path, self.sha, self.cov, self.findings = path, sha, cov, []
        self.kind = None  # Phase 3A: set per document; used only for typed facts

    def add(self, rule, category, severity, state, resource, ls, le, summary, rationale, check, observation,
            locator=""):
        if state == "insufficient_evidence":
            self.cov.status = "partial"
        ev = Evidence("source_lines", self.path, self.sha, ANALYZER_ID, ANALYZER_VERSION, rule, observation,
                      line_start=ls, line_end=le)
        finding = Finding(rule, category, severity, state, ANALYZER_ID, resource, self.path, self.sha,
                          summary, rationale, check, line_start=ls, line_end=le, evidence=[ev], locator=locator)
        self.findings.append(finding)
        return finding

    def insufficient(self, rule, resource, ls, le, what, locator=""):
        _f = self.add(rule, "kubernetes", "unknown", "insufficient_evidence", resource, ls, le,
                 f"Could not evaluate {what}.",
                 "The value is ambiguous (e.g. a YAML 1.1 boolean such as 'yes'), quoted, or has an "
                 "unexpected shape, so the rule cannot be confirmed or excluded.",
                 "Check the value manually and prefer canonical true/false booleans.",
                 f"{what}: value not interpretable by the rule.", locator)
        _f.facts.update({"unresolved": what})  # Phase 3A typed facts (not serialized)
        return _f


def _image_tag(image: str) -> Tuple[Optional[str], bool]:
    """(tag, has_digest). Registry ports ('host:5000/img') are not tags."""
    if "@" in image:
        return None, True
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        return last.rsplit(":", 1)[1], False
    return None, False


def _containers(ctx: _Ctx, obj_id: str, pod: YMap) -> None:
    host = pod.get("hostNetwork")
    ctx.cov.count("K8S-HOSTNET-001")
    hv = _bool(host)
    if hv is True:
        _f = ctx.add("K8S-HOSTNET-001", "kubernetes", "medium", "confirmed_by_rule", obj_id, host.line_start,
                host.line_end, "Pod uses the node's network namespace (hostNetwork: true).",
                "hostNetwork exposes node network interfaces and bypasses pod network isolation; whether that "
                "is acceptable depends on the workload (e.g. CNI or node agents) - context-dependent.",
                "Confirm the workload genuinely needs host networking and that NetworkPolicy assumptions still hold.",
                "hostNetwork is the literal boolean true.", "hostNetwork")
        _f.facts.update({"workload_kind": ctx.kind})  # Phase 3A typed facts (not serialized)
    elif hv == "ambiguous":
        ctx.insufficient("K8S-HOSTNET-001", obj_id, host.line_start, host.line_end, "hostNetwork")
    for list_name in CONTAINER_LISTS:
        lst = pod.get(list_name)
        if lst is None:
            continue
        if not isinstance(lst, YSeq):
            ctx.insufficient("K8S-PRIV-001", obj_id, lst.line_start, lst.line_end, f"{list_name} list")
            continue
        for index, c in enumerate(lst.items):
            if not isinstance(c, YMap):
                ctx.insufficient("K8S-PRIV-001", obj_id, c.line_start, c.line_end, f"{list_name} entry")
                continue
            ctx.cov.objects_analyzed += 1
            cname = _scalar_text(c.get("name")) or f"#{index}"
            cid = safe_token(f"{obj_id} {list_name}[{cname}]", 200)
            loc = f"{list_name}[{index}]"
            # privileged
            ctx.cov.count("K8S-PRIV-001")
            sc = c.get("securityContext")
            if sc is not None and not isinstance(sc, YMap) and not (isinstance(sc, YScalar) and sc.is_null):
                ctx.insufficient("K8S-PRIV-001", cid, sc.line_start, sc.line_end,
                                 "securityContext (not a mapping)", loc)
            priv = _get_path(c, ("securityContext", "privileged"))
            pv = _bool(priv)
            if pv is True:
                _f = ctx.add("K8S-PRIV-001", "kubernetes", "high", "confirmed_by_rule", cid, priv.line_start,
                        priv.line_end, "Container runs privileged (securityContext.privileged: true).",
                        "A privileged container has broad access to the host's devices and kernel capabilities; "
                        "a compromise of the container is close to a compromise of the node.",
                        "Remove privileged mode or grant only the specific capabilities required.",
                        "securityContext.privileged is the literal boolean true.", loc)
                _f.facts.update({"container_list": list_name, "workload_kind": ctx.kind})  # Phase 3A typed facts (not serialized)
            elif pv == "ambiguous":
                ctx.insufficient("K8S-PRIV-001", cid, priv.line_start, priv.line_end, "securityContext.privileged", loc)
            # image tag
            ctx.cov.count("K8S-IMG-001")
            img_node = c.get("image")
            img = _scalar_text(img_node)
            if img_node is not None and not isinstance(img_node, YScalar):
                ctx.insufficient("K8S-IMG-001", cid, img_node.line_start, img_node.line_end, "image (not a scalar)", loc)
            if img is not None:
                tag, digest = _image_tag(img)
                if not digest and (tag is None or tag == "latest"):
                    which = "the 'latest' tag" if tag == "latest" else "no tag (implicitly 'latest')"
                    _f = ctx.add("K8S-IMG-001", "kubernetes", "medium", "confirmed_by_rule", cid, img_node.line_start,
                            img_node.line_end, f"Container image uses {which}.",
                            "A mutable tag can resolve to different image content over time, which weakens "
                            "reproducibility and review; impact is context-dependent.",
                            "Pin the image to an immutable version tag or digest.",
                            f"image reference has {which} and no digest.", loc)
                    _f.facts.update({"tag_state": "latest" if tag == "latest" else "untagged", "container_list": list_name})  # Phase 3A typed facts (not serialized)
            # resources
            if list_name != "ephemeralContainers":
                ctx.cov.count("K8S-RES-001")
                res = c.get("resources")
                req = _get_path(c, ("resources", "requests"))
                lim = _get_path(c, ("resources", "limits"))
                missing = [n for n, v in (("requests", req), ("limits", lim)) if not isinstance(v, YMap) or not v.items]
                if missing:
                    # Interval starts at the "resources:" key line (or the container entry when absent).
                    if res is not None:
                        ls, le = _key_line(c, "resources"), res.line_end
                    else:
                        ls = le = c.line_start
                    _f = ctx.add("K8S-RES-001", "availability", "medium", "confirmed_by_rule", cid, ls, max(ls, le),
                            "Container does not declare resource " + " and ".join(missing) + ".",
                            "Without requests/limits the scheduler and node cannot bound this container's usage; "
                            "whether that matters depends on namespace defaults (e.g. LimitRange) - context-dependent.",
                            "Declare CPU/memory requests and limits, or confirm a LimitRange applies.",
                            "resources." + "/".join(missing) + " mapping absent or empty.", loc)
                    _f.facts.update({"missing": sorted(missing), "container_list": list_name})  # Phase 3A typed facts (not serialized)


def _rbac(ctx: _Ctx, obj_id: str, doc_root: YMap) -> None:
    if doc_root.get("aggregationRule") is not None:
        ctx.cov.status = "partial"
        ctx.cov.notes.append(CoverageNote("RBAC_AGGREGATION_NOT_EVALUATED",
                                          f"{obj_id} uses aggregationRule; its effective rules come from other "
                                          "ClusterRoles selected by label and are not evaluated.",
                                          doc_root.line_start))
    rules = doc_root.get("rules")
    if rules is None:
        return
    if not isinstance(rules, YSeq):
        ctx.insufficient("K8S-RBAC-001", obj_id, rules.line_start, rules.line_end, "rules list")
        return
    for index, rule in enumerate(rules.items):
        ctx.cov.count("K8S-RBAC-001")
        ctx.cov.count("K8S-RBAC-002")
        ctx.cov.objects_analyzed += 1
        rid = safe_token(f"{obj_id} rules[{index}]", 200)
        if not isinstance(rule, YMap):
            ctx.insufficient("K8S-RBAC-001", rid, rule.line_start, rule.line_end, "RBAC rule")
            continue
        verbs, v_odd = _str_list(rule.get("verbs"))
        resources, r_odd = _str_list(rule.get("resources"))
        urls, u_odd = _str_list(rule.get("nonResourceURLs"))
        if v_odd or r_odd or u_odd:
            ctx.insufficient("K8S-RBAC-001", rid, rule.line_start, rule.line_end, "RBAC rule fields")
            continue
        wv = any(v == "*" for v, _ in verbs)
        wr = any(r == "*" for r, _ in resources)
        wu = any(u == "*" for u, _ in urls)
        if wv and wr:
            _f = ctx.add("K8S-RBAC-001", "identity", "high", "confirmed_by_rule", rid, rule.line_start, rule.line_end,
                    "RBAC rule grants all verbs on all resources.",
                    "verbs contains '*' and resources contains '*'; within the listed apiGroups this is "
                    "equivalent to full control, and for a ClusterRole it applies cluster-wide when bound.",
                    "Replace wildcards with the specific verbs and resources required; review the bindings.",
                    "rule has verbs '*' and resources '*'.")
            _f.facts.update({"role_kind": ctx.kind, "wildcard_fields": sorted(n for n, flag in (("verbs", wv), ("resources", wr), ("nonResourceURLs", wu)) if flag)})  # Phase 3A typed facts (not serialized)
        elif wv or wr or wu:
            what = ", ".join(n for n, f in (("verbs", wv), ("resources", wr), ("nonResourceURLs", wu)) if f)
            _f = ctx.add("K8S-RBAC-002", "identity", "medium", "confirmed_by_rule", rid, rule.line_start, rule.line_end,
                    f"RBAC rule uses a wildcard in {what}.",
                    "A wildcard grants every current and future value of that field.",
                    "Enumerate the specific values required.",
                    f"rule has '*' in {what}.")
            _f.facts.update({"role_kind": ctx.kind, "wildcard_fields": sorted(n for n, flag in (("verbs", wv), ("resources", wr), ("nonResourceURLs", wu)) if flag)})  # Phase 3A typed facts (not serialized)


def parse_file(text: str):
    try:
        return parse_documents(text), None
    except YamlUnsupported as exc:
        return None, ("unsupported", CoverageNote("YAML_UNSUPPORTED_CONSTRUCT",
                                                  f"Outside the supported YAML subset: {exc.message}.", exc.line))
    except YamlSyntaxError as exc:
        return None, ("parse_error", CoverageNote("YAML_SYNTAX_ERROR", f"YAML syntax error: {exc.message}.", exc.line))


def analyze_k8s(path: str, sha256: str, docs: List[YDocument], kind: str) -> Tuple[FileCoverage, List[Finding]]:
    cov = FileCoverage(path, kind, ANALYZER_ID, ANALYZER_VERSION, "analyzed")
    ctx = _Ctx(path, sha256, cov)
    for doc_index, doc in enumerate(docs):
        root = doc.root
        if root is None:
            continue
        api, k = (_scalar_text(root.get("apiVersion")), _scalar_text(root.get("kind"))) if isinstance(root, YMap) else (None, None)
        if not api or not k:
            cov.status = "partial"
            cov.notes.append(CoverageNote("NOT_KUBERNETES",
                                          f"Document {doc_index} has no apiVersion/kind; not analysed as Kubernetes.",
                                          doc.line_start))
            continue
        name = _scalar_text(_get_path(root, ("metadata", "name"))) or "<unnamed>"
        ns = _scalar_text(_get_path(root, ("metadata", "namespace")))
        obj_id = safe_token(f"{k}/{ns + '/' if ns else ''}{name}", 160)
        family = "workload" if k in POD_SPEC_PATHS else "rbac" if k in RBAC_KINDS else None
        if family:
            unknown_keys = sorted(key for key, _l, _v in root.items if key not in KNOWN_TOP_LEVEL[family])
            if unknown_keys:
                cov.status = "partial"
                cov.notes.append(CoverageNote("UNKNOWN_TOP_LEVEL_FIELD",
                                              f"{obj_id} has unrecognised top-level field(s) "
                                              f"{safe_token(', '.join(unknown_keys), 80)}; object not fully understood.",
                                              doc.line_start))
        ctx.kind = k  # Phase 3A: kind for typed facts (k is a POD_SPEC_PATHS or RBAC_KINDS key when used)
        if k in POD_SPEC_PATHS:
            pod = _get_path(root, POD_SPEC_PATHS[k])
            if not isinstance(pod, YMap):
                cov.status = "partial"
                cov.notes.append(CoverageNote("POD_SPEC_MISSING",
                                              f"{safe_token(k, 40)} document {doc_index} has no pod spec at the expected path.",
                                              doc.line_start))
                continue
            _containers(ctx, obj_id, pod)
        elif k in RBAC_KINDS:
            _rbac(ctx, obj_id, root)
        elif k in NO_CHECK_KINDS:
            continue
        else:
            cov.status = "partial"
            cov.notes.append(CoverageNote("UNRECOGNIZED_KIND",
                                          f"Kind {safe_token(k, 60)} (document {doc_index}) is not covered by the "
                                          "Phase 2 rule set.", doc.line_start))
    return cov, ctx.findings

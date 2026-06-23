import logging

from PySide6.QtCore import Signal, QThread

from ._models import GraphData, GraphNode, GraphEdge
from ._constants import _CDN_TECH_MAP, _cdn_node_kind

logger = logging.getLogger(__name__)


class GraphDataLoader(QThread):
    loaded = Signal(object)   # GraphData
    error  = Signal(str)

    def __init__(self, project_dir: str, target: str, scope=None, parent=None):
        super().__init__(parent)
        self._project_dir = project_dir
        self._target      = target
        self._scope       = scope   # ScopeConfig | None  (passed at start() time)

    def run(self):
        try:
            from database.repository import AweRepository
            repo = AweRepository(self._project_dir)
            self.loaded.emit(self._build(repo))
        except Exception as exc:
            logger.exception("GraphDataLoader failed")
            self.error.emit(str(exc))

    def _build(self, repo) -> GraphData:
        from urllib.parse import urlsplit

        nodes: dict[str, GraphNode] = {}
        edges: dict[tuple, GraphEdge] = {}
        target = self._target
        scope  = self._scope  # ScopeConfig | None — None means "show everything"

        def _node(nid, kind, label, data=None):
            if nid not in nodes:
                nodes[nid] = GraphNode(nid, kind, label, data or {})
            elif kind in ("cdn", "reverse_proxy") and data:
                # Multiple sessions may report the same CDN/RP — merge.
                ex = nodes[nid]
                # Accumulate origin IPs
                ex_ips = ex.data.setdefault("origin_ips", [])
                for ip in (data.get("origin_ips") or []):
                    if ip and ip not in ex_ips:
                        ex_ips.append(ip)
                # Prefer the most informative proxy_type
                new_pt = data.get("proxy_type", "")
                if "reverse proxy" in new_pt.lower():
                    ex.data["proxy_type"] = new_pt
                    ex.kind = "reverse_proxy"  # upgrade kind in-place

        _CDN_EDGE_KINDS = {"proxied_by", "routes_through"}

        def _edge(src, tgt, kind):
            k = (src, tgt, kind)
            if k not in edges:
                # CDN relationship edge: replace any existing opposite-kind CDN edge
                # so a node that upgrades from cdn→reverse_proxy doesn't end up with
                # both a "proxied_by" and a "routes_through" edge to the same target.
                if kind in _CDN_EDGE_KINDS:
                    for other in _CDN_EDGE_KINDS - {kind}:
                        edges.pop((src, tgt, other), None)
                edges[k] = GraphEdge(src, tgt, kind)

        root_id = f"target:{target}"
        _node(root_id, "target", target, {"domain": target})

        # Process oldest sessions first so base nodes (subdomains from early
        # pipeline runs) exist in `nodes` before newer manual/proxy additions
        # reference them.  limit=0 means no cap — include every session.
        all_sessions = sorted(
            repo.list_sessions(limit=0),
            key=lambda s: s.get("started_at") or "",
        )
        for session in all_sessions:
            sid = session["id"]

            # ── subdomains ────────────────────────────────────────────────────
            for r in repo.get_results(sid, "subdomain"):
                d = r.get("data", {})
                dom = d.get("domain", "")
                if not dom:
                    continue
                if scope is not None and not scope.matches(dom):
                    continue
                nid = f"subdomain:{dom}"
                _node(nid, "subdomain", dom, {
                    "domain": dom,
                    "ips": d.get("ip_addresses", []),
                    "sources": r.get("sources", []),
                })
                _edge(root_id, nid, "has_subdomain")
                for ip in d.get("ip_addresses", []):
                    if not ip:
                        continue
                    ip_id = f"ip:{ip}"
                    _node(ip_id, "ip", ip, {"ip": ip})
                    _edge(nid, ip_id, "resolves_to")

            # ── port scan ─────────────────────────────────────────────────────
            for r in repo.get_results(sid, "portscan"):
                d = r.get("data", {})
                host, port = d.get("host", ""), d.get("port", 0)
                if not host or not port:
                    continue
                ip_id = f"ip:{host}"
                _node(ip_id, "ip", host, {"ip": host})
                svc = d.get("service", "")
                proto = d.get("protocol", "tcp")
                label = f"{port}/{proto}" + (f" {svc}" if svc else "")
                port_id = f"port:{host}:{port}"
                _node(port_id, "port", label, {
                    "host": host, "port": port,
                    "protocol": proto, "service": svc,
                    "version": d.get("version", ""),
                })
                _edge(ip_id, port_id, "has_port")

            # ── live HTTP hosts / technologies ────────────────────────────────
            for r in repo.get_results(sid, "http"):
                d   = r.get("data", {})
                url = d.get("url", "")
                if not url:
                    continue
                try:
                    host = urlsplit(url).hostname or ""
                except Exception:
                    host = ""
                if not host:
                    continue
                if scope is not None and not scope.matches(host):
                    continue
                sub_id = f"subdomain:{host}"
                _node(sub_id, "subdomain", host, {
                    "domain": host,
                    "status": d.get("status_code", ""),
                    "title":  d.get("title", ""),
                })
                _edge(root_id, sub_id, "has_subdomain")

                port_num = 443 if url.startswith("https") else 80
                port_id  = f"port:{host}:{port_num}"
                _node(port_id, "port", f"{port_num}/tcp", {
                    "host": host, "port": port_num, "url": url,
                    "status": d.get("status_code", ""),
                    "title":  d.get("title", ""),
                })
                ip_id = f"ip:{host}"
                parent_id = ip_id if ip_id in nodes else sub_id
                _edge(parent_id, port_id, "has_port")

                for tech in d.get("technologies", []):
                    tech_lower = tech.lower()
                    cdn_match  = next(
                        ((prov, ptype) for key, (prov, ptype) in _CDN_TECH_MAP.items()
                         if key in tech_lower),
                        None,
                    )
                    if cdn_match:
                        provider, proxy_type = cdn_match
                        kind   = _cdn_node_kind(proxy_type)
                        cdn_id = f"cdn:{provider.lower()}:{host}"
                        _node(cdn_id, kind, provider, {
                            "provider":      provider,
                            "proxy_type":    proxy_type,
                            "proxied_host":  host,
                            "origin_masked": True,
                            "origin_ips":    [],
                            "bypass_hints":  [],
                        })
                        edge_kind = "routes_through" if kind == "reverse_proxy" else "proxied_by"
                        _edge(sub_id, cdn_id, edge_kind)
                    else:
                        tech_id = f"tech:{tech}"
                        _node(tech_id, "tech", tech, {"tech": tech})
                        _edge(port_id, tech_id, "uses_tech")

            # ── CDN / reverse proxy (explicit results) ────────────────────────
            for r in repo.get_results(sid, "cdn"):
                d         = r.get("data", {})
                provider  = d.get("provider", "")
                subdomain = d.get("subdomain", "")
                if not provider:
                    continue
                proxy_type = d.get("proxy_type", "CDN")
                kind       = _cdn_node_kind(proxy_type)
                cdn_id     = f"cdn:{provider.lower()}:{subdomain.lower()}"
                _node(cdn_id, kind, provider, {
                    "provider":      provider,
                    "proxy_type":    proxy_type,
                    "proxied_host":  subdomain,
                    "origin_masked": d.get("origin_masked", True),
                    "origin_ips":    d.get("origin_ips", []),
                    "bypass_hints":  d.get("bypass_hints", []),
                    "sources":       r.get("sources", []),
                })
                parent_id = (f"subdomain:{subdomain}"
                             if f"subdomain:{subdomain}" in nodes else root_id)
                edge_kind = "routes_through" if kind == "reverse_proxy" else "proxied_by"
                _edge(parent_id, cdn_id, edge_kind)
                for origin_ip in d.get("origin_ips", []):
                    if not origin_ip:
                        continue
                    oid = f"ip:{origin_ip}"
                    _node(oid, "ip", origin_ip, {
                        "ip": origin_ip, "note": "origin server"
                    })
                    _edge(cdn_id, oid, "origin_of")

            # ── vulnerabilities ───────────────────────────────────────────────
            for r in repo.get_results(sid, "vuln"):
                d    = r.get("data", {})
                name = d.get("name", "")
                sev  = d.get("severity", "info")
                url  = d.get("url", "")
                if not name:
                    continue
                try:
                    host = urlsplit(url).hostname or ""
                except Exception:
                    host = ""
                vid   = f"vuln:{d.get('template_id','?')}:{host}"
                label = f"[{sev[:4].upper()}] {name[:18]}"
                _node(vid, "vuln", label, {
                    "name": name, "severity": sev,
                    "url": url, "description": d.get("description", ""),
                })
                parent = f"subdomain:{host}" if f"subdomain:{host}" in nodes else root_id
                _edge(parent, vid, "has_vuln")

            # ── OSINT ─────────────────────────────────────────────────────────
            for r in repo.get_results(sid, "osint"):
                d     = r.get("data", {})
                rtype = d.get("result_type", "")
                value = d.get("value", "")
                if not value:
                    continue
                oid = f"osint:{rtype}:{value}"
                _node(oid, "osint", value[:24], {
                    "type": rtype, "value": value,
                    "extra": d.get("extra", ""),
                    "provider": d.get("provider", ""),
                })
                _edge(root_id, oid, "is_osint")

            # ── Info notes ────────────────────────────────────────────────────
            for r in repo.get_results(sid, "info"):
                d         = r.get("data", {})
                parent_id = d.get("parent_node_id", "")
                content   = d.get("content", "")
                if not parent_id or not content or parent_id not in nodes:
                    continue
                first_line = content.split("\n")[0].strip()
                label = (first_line[:20] + "…") if len(first_line) > 20 else first_line
                info_id = f"info:{parent_id}"
                _node(info_id, "info", label, {
                    "content":        content,
                    "parent_node_id": parent_id,
                })
                _edge(parent_id, info_id, "annotates")

            # ── Custom user nodes ──────────────────────────────────────────────
            for r in repo.get_results(sid, "custom"):
                d         = r.get("data", {})
                parent_id = d.get("parent_node_id", "")
                label     = d.get("label", "")
                if not label or parent_id not in nodes:
                    continue
                custom_id = f"custom:{r.get('result_key', label)}"
                _node(custom_id, "custom", label, {
                    "label":          label,
                    "description":    d.get("description", ""),
                    "parent_node_id": parent_id,
                })
                _edge(parent_id, custom_id, "linked_to")

            # ── Endpoints (hidden by default) ─────────────────────────────────
            for r in repo.get_results(sid, "crawl"):
                d      = r.get("data", {})
                url    = d.get("url", "")
                method = d.get("method", "GET")
                if not url:
                    continue
                try:
                    parsed  = urlsplit(url)
                    host    = parsed.netloc
                    path    = parsed.path or "/"
                except Exception:
                    continue
                sub_id = f"subdomain:{host}"
                if sub_id not in nodes:
                    continue  # skip if subdomain not in main graph
                path_lbl = path if len(path) <= 28 else path[:25] + "…"
                ep_id    = f"endpoint:{method}:{url}"
                _node(ep_id, "endpoint", f"{method} {path_lbl}", {
                    "url":          url,
                    "method":       method,
                    "status_code":  d.get("status_code", 0),
                    "content_type": d.get("content_type", ""),
                })
                _edge(sub_id, ep_id, "has_endpoint")

            # ── Parameters (hidden by default, children of endpoints) ──────────
            for r in repo.get_results(sid, "params"):
                d        = r.get("data", {})
                name     = d.get("name", "")
                endpoint = d.get("endpoint", "")
                method   = d.get("method", "GET")
                if not name or not endpoint:
                    continue
                ep_id = f"endpoint:{method}:{endpoint}"
                if ep_id not in nodes:
                    continue  # endpoint not in graph
                ptype    = d.get("param_type", "query")
                param_id = f"param:{ep_id}:{name}"
                _node(param_id, "param", f"{'?' if ptype == 'query' else '⬤'} {name}", {
                    "name":       name,
                    "param_type": ptype,
                    "example":    d.get("example_value", ""),
                    "endpoint":   endpoint,
                    "method":     method,
                })
                _edge(ep_id, param_id, "has_param")

        return GraphData(nodes=list(nodes.values()), edges=list(edges.values()))


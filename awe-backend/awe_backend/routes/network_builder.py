"""Network builder API handlers and helpers."""

from ..repositories import LegacyRepositoryFactory
from ..schemas import NetworkEdge
from ..schemas import NetworkGraph
from ..schemas import NetworkNode
from pathlib import Path
from urllib.parse import urlsplit


def _network_graph(project_dir: Path, target: str, repositories: LegacyRepositoryFactory) -> NetworkGraph:
    """Build the typed attack-surface graph used by the web client."""
    repo = repositories(project_dir); nodes: dict[str, NetworkNode] = {}; edges: dict[tuple[str,str,str], NetworkEdge] = {}
    sessions = sorted(repo.list_sessions(limit=0), key=lambda x: x.get("started_at", ""))
    live_hosts: set[str] = set()

    def hostname(value: str) -> str:
        parsed = urlsplit(value if "://" in value else f"https://{value}")
        return (parsed.hostname or "").rstrip(".").lower()

    for session in sessions:
        for result in repo.get_results(session["id"], "http"):
            url = str(result.get("data", {}).get("url") or "")
            if url and hostname(url):
                live_hosts.add(hostname(url))

    def is_live(value: str) -> bool:
        return hostname(value) in live_hosts

    def architecture_kind(result_type: str) -> str:
        return {
            "vulnerability": "vuln", "technology": "tech", "parameter": "param",
            "cloud_account": "cloud_asset", "cloud_resource": "cloud_asset",
            "cloud_bucket": "cloud_asset", "cloud_asset": "cloud_asset",
        }.get(result_type, result_type)

    def architecture_edge(result_type: str) -> str:
        return {
            "platform": "runs", "component": "has_component", "vulnerability": "has_finding",
            "vuln": "has_finding", "misconfiguration": "has_finding", "cloud_account": "contains",
            "cloud_resource": "has_resource", "cloud_asset": "has_cloud_asset", "cloudflare_zone": "contains",
            "dns_record": "has_dns", "cluster": "contains", "workload": "contains",
            "container_image": "uses_image", "identity_provider": "uses_identity_provider",
            "oidc_endpoint": "exposes", "endpoint": "exposes", "secret": "contains_secret",
            "repository": "has_repository", "email": "has_email", "person": "mentions",
        }.get(result_type, "is_architecture")

    def node(nid: str, kind: str, label: str, data: dict | None = None):
        if nid not in nodes: nodes[nid] = NetworkNode(id=nid, kind=kind, label=label, data=data or {})
        elif data:
            nodes[nid].data.update({k:v for k,v in data.items() if v not in (None, "", [], {})})
    def edge(src: str, dst: str, kind: str, label: str = ""):
        if src in nodes and dst in nodes: edges[(src,dst,kind)] = NetworkEdge(source_id=src,target_id=dst,kind=kind,label=label)
    root=f"target:{target}"; node(root,"target",target,{"domain":target})
    default = f"subdomain:{target}"
    if is_live(target):
        node(default, "subdomain", target, {"domain": target, "live": True})
        edge(root, default, "has_subdomain")
    for session in sessions:
        sid=session["id"]
        for category in ("subdomain","portscan","http","cdn","vuln","osint","architecture","crawl","params","info","custom"):
            for result in repo.get_results(sid, category):
                d=result.get("data",{}); sources=result.get("sources",[])
                if category=="subdomain" and d.get("domain"):
                    dom=str(d["domain"])
                    if not is_live(dom):
                        continue
                    sid2=f"subdomain:{hostname(dom)}"; node(sid2,"subdomain",dom,{"domain":dom,"live":True,"ips":d.get("ip_addresses",[]),"sources":sources}); edge(root,sid2,"has_subdomain")
                    for ip in d.get("ip_addresses",[]): node(f"ip:{ip}","ip",ip,{"ip":ip}); edge(sid2,f"ip:{ip}","resolves_to")
                elif category=="portscan" and d.get("host") and d.get("port"):
                    host=str(d["host"]); ip=f"ip:{host}"; node(ip,"ip",host,{"ip":host}); pid=f"port:{host}:{d['port']}"; node(pid,"port",f"{d['port']}/{d.get('protocol','tcp')} {d.get('service','')}",d); edge(ip,pid,"has_port")
                elif category=="http" and d.get("url"):
                    parsed=urlsplit(d["url"]); host=hostname(d["url"])
                    if not host:
                        continue
                    sub=f"subdomain:{host}"; node(sub,"subdomain",host,{"domain":host,"live":True,"status":d.get("status_code"),"title":d.get("title","")}); edge(root,sub,"has_subdomain")
                    for tech in d.get("technologies",[]): tid=f"tech:{tech}"; node(tid,"tech",tech,{"tech":tech}); edge(sub,tid,"uses_tech")
                    port=int(d.get("port") or (443 if parsed.scheme=="https" else 80)); pid=f"port:{host}:{port}"; node(pid,"port",f"{port}/tcp",{"host":host,"port":port,"url":d["url"],"status":d.get("status_code")}); edge(sub,pid,"has_port")
                elif category=="cdn" and d.get("provider"):
                    subdomain=str(d.get("subdomain", target))
                    if not is_live(subdomain):
                        continue
                    sub=f"subdomain:{hostname(subdomain)}"; node(sub,"subdomain",subdomain,{"domain":subdomain,"live":True}); cid=f"cdn:{d['provider']}:{hostname(subdomain)}"; node(cid,"cdn",d["provider"],d); edge(sub,cid,"proxied_by")
                elif category=="vuln" and d.get("name"):
                    host=hostname(d.get("url", "")) or hostname(target)
                    if not is_live(host):
                        continue
                    sub=f"subdomain:{host}"; node(sub,"subdomain",host,{"domain":host,"live":True}); vid=f"vuln:{d.get('template_id',d['name'])}:{host}"; node(vid,"vuln",d["name"],d); edge(sub,vid,"has_vuln")
                elif category=="osint" and d.get("value"):
                    oid=f"osint:{d.get('result_type','hit')}:{d['value']}"; node(oid,"osint",str(d['value'])[:80],d); edge(root,oid,"is_osint")
                elif category=="architecture" and d.get("value"):
                    result_type = str(d.get("result_type") or d.get("kind") or "architecture")
                    value = str(d.get("value"))
                    kind = architecture_kind(result_type)
                    related = hostname(str(d.get("related_host") or d.get("metadata", {}).get("input") or ""))
                    parent = root
                    if related and is_live(related):
                        parent = f"subdomain:{related}"
                        node(parent, "subdomain", related, {"domain": related, "live": True})
                        edge(root, parent, "has_subdomain")
                    node_id = f"{kind}:{value}"
                    node(node_id, kind, value[:80], {**d, "architecture_type": result_type})
                    edge(parent, node_id, architecture_edge(result_type))
                elif category=="crawl" and d.get("url"):
                    parsed=urlsplit(d["url"]); host=hostname(d["url"])
                    if not is_live(host):
                        continue
                    sub=f"subdomain:{host}"; node(sub,"subdomain",host,{"domain":host,"live":True}); eid=f"endpoint:{d.get('method','GET')}:{d['url']}"; node(eid,"endpoint",f"{d.get('method','GET')} {parsed.path or '/'}",d); edge(sub,eid,"has_endpoint")
                elif category=="params" and d.get("name"):
                    eid=f"endpoint:{d.get('method','GET')}:{d.get('endpoint','')}"; pid=f"param:{eid}:{d['name']}"; node(pid,"param",str(d['name']),d); edge(eid,pid,"has_param")
                elif category=="info" and d.get("content"):
                    parent=d.get("parent_node_id",""); iid=f"info:{parent}"; node(iid,"info",str(d["content"]).splitlines()[0][:80],d); edge(parent,iid,"annotates")
                elif category=="custom" and d.get("label"):
                    parent=d.get("parent_node_id",""); cid=f"custom:{result.get('result_key',d['label'])}"; node(cid,"custom",d["label"],d); edge(parent,cid,"linked_to")
    for item in repo._db.results.find({"session_id":{"$exists":False},"project_id":project_dir.name,"category":"network_manual"}):
        d=item.get("data",{}); node(item.get("result_key",d.get("label","manual")),d.get("kind","custom"),d.get("label","manual"),d); edge(d.get("parent_id",""),item.get("result_key",""),"linked_to")
    return NetworkGraph(nodes=list(nodes.values()), edges=list(edges.values()))

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

import httpx
from cryptography.fernet import Fernet
import base64
import hashlib


def _now() -> str: return datetime.now(timezone.utc).isoformat()


class AIService:
    def __init__(self, project_dir: Path, secret_key: str = "development-only-change-me"):
        self.root = project_dir / ".awe_ai_chats"; self.root.mkdir(parents=True, exist_ok=True)
        self.settings_file = project_dir / ".awe-ai-settings.json"
        self._fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret_key.encode()).digest()))
        self.approvals_file = project_dir / ".awe-ai-approvals.json"

    def settings(self) -> dict:
        try:
            data=json.loads(self.settings_file.read_text())
            if data.get("api_key_enc"): data["api_key"]=self._fernet.decrypt(data.pop("api_key_enc")).decode()
            return data
        except Exception: return {"provider":"openai","model":"gpt-4o-mini","base_url":"","api_key_configured":False}

    def save_settings(self, values: dict) -> dict:
        allowed = {"provider","model","base_url"}; current = self.settings(); current.update({k:v for k,v in values.items() if k in allowed})
        api_key=values.get("api_key") or current.get("api_key",""); current.pop("api_key",None); current.pop("api_key_configured",None); current["api_key_enc"]=self._fernet.encrypt(api_key.encode()).decode(); self.settings_file.write_text(json.dumps(current, indent=2)); return {**current, "api_key":"", "api_key_configured": bool(api_key)}

    def list_conversations(self) -> list[dict]:
        rows=[]
        for path in self.root.glob("*.json"):
            try:
                data=json.loads(path.read_text()); rows.append({"id":data["id"],"title":data.get("title","New chat"),"updated_at":data.get("updated_at","")})
            except Exception: pass
        return sorted(rows,key=lambda x:x["updated_at"],reverse=True)

    def get(self, conversation_id: str) -> dict:
        path=self.root/f"{conversation_id}.json"
        if not path.exists(): raise KeyError(conversation_id)
        return json.loads(path.read_text())

    def create(self, title="New chat") -> dict:
        cid=secrets.token_urlsafe(16); data={"id":cid,"title":title,"created_at":_now(),"updated_at":_now(),"messages":[]}; (self.root/f"{cid}.json").write_text(json.dumps(data,indent=2)); return data

    def append(self, conversation_id: str, role: str, content: str) -> dict:
        data=self.get(conversation_id); data["messages"].append({"role":role,"content":content,"created_at":_now()}); data["updated_at"]=_now(); self.get_path(conversation_id).write_text(json.dumps(data,indent=2)); return data

    def get_path(self, cid): return self.root/f"{cid}.json"

    def approvals(self) -> list[dict]:
        try: return json.loads(self.approvals_file.read_text())
        except Exception: return []

    def request_approval(self, conversation_id: str, tool_name: str, arguments: dict, risk: str = "medium") -> dict:
        item={"id":secrets.token_urlsafe(16),"conversation_id":conversation_id,"tool_name":tool_name,"arguments":arguments,"risk":risk,"status":"pending","created_at":_now(),"resolved_at":None}; rows=self.approvals(); rows.append(item); self.approvals_file.write_text(json.dumps(rows,indent=2)); return item

    def resolve_approval(self, approval_id: str, decision: str) -> dict | None:
        rows=self.approvals(); item=next((row for row in rows if row["id"]==approval_id),None)
        if item is None: return None
        if item["status"] != "pending": return item
        item["status"]="approved" if decision=="approve" else "rejected"; item["resolved_at"]=_now(); self.approvals_file.write_text(json.dumps(rows,indent=2)); return item

    async def reply(self, conversation_id: str, prompt: str) -> str:
        data=self.append(conversation_id,"user",prompt); cfg=self.settings(); provider=cfg.get("provider","openai"); key=cfg.get("api_key","")
        if provider != "ollama" and not key: raise RuntimeError("Configure an AI API key in AI Settings first")
        messages=[{"role":m["role"],"content":m["content"]} for m in data["messages"]]
        if provider == "anthropic":
            headers={"x-api-key":key,"anthropic-version":"2023-06-01","content-type":"application/json"}; body={"model":cfg.get("model","claude-3-5-sonnet-latest"),"max_tokens":2048,"messages":[m for m in messages if m["role"]!="system"]}; url=cfg.get("base_url") or "https://api.anthropic.com/v1/messages"; response=await self._post(url,headers,body); answer=response.json().get("content",[{}])[0].get("text","")
        else:
            base=cfg.get("base_url") or ("http://127.0.0.1:11434/v1" if provider=="ollama" else "https://api.openai.com/v1"); headers={"content-type":"application/json"};
            if key: headers["authorization"]=f"Bearer {key}"
            tools=self.tool_specs()
            body={"model":cfg.get("model","gpt-4o-mini"),"messages":messages,"temperature":0.2,"tools":tools,"tool_choice":"auto"}
            response=await self._post(base.rstrip("/")+"/chat/completions",headers,body); message=response.json()["choices"][0]["message"]
            if message.get("tool_calls"):
                messages.append(message)
                for call in message["tool_calls"]:
                    name=call["function"]["name"]
                    try: arguments=json.loads(call["function"].get("arguments") or "{}")
                    except ValueError: arguments={}
                    result=self.execute_tool(name, arguments, conversation_id)
                    messages.append({"role":"tool","tool_call_id":call["id"],"content":json.dumps(result)})
                response=await self._post(base.rstrip("/")+"/chat/completions",headers,{**body,"messages":messages}); message=response.json()["choices"][0]["message"]
            answer=message.get("content","")
        self.append(conversation_id,"assistant",answer); return answer

    async def stream_reply(self, conversation_id: str, prompt: str):
        """Yield protocol events shared by browser clients and future multi-agent runtimes."""
        data=self.append(conversation_id,"user",prompt); cfg=self.settings(); provider=cfg.get("provider","openai"); key=cfg.get("api_key","")
        if provider == "anthropic":
            answer=await self.reply(conversation_id, prompt)
            yield {"type":"token","text":answer}; yield {"type":"message_complete","content":answer}; return
        if provider != "ollama" and not key: raise RuntimeError("Configure an AI API key in AI Settings first")
        messages=[{"role":m["role"],"content":m["content"]} for m in data["messages"]]
        base=cfg.get("base_url") or ("http://127.0.0.1:11434/v1" if provider=="ollama" else "https://api.openai.com/v1")
        headers={"content-type":"application/json"};
        if key: headers["authorization"]=f"Bearer {key}"
        body={"model":cfg.get("model","gpt-4o-mini"),"messages":messages,"temperature":0.2,"stream":True}
        answer_parts=[]
        async with httpx.AsyncClient(timeout=120) as client:
            async with client.stream("POST",base.rstrip("/")+"/chat/completions",headers=headers,json=body) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line.startswith("data:") or line.strip()=="data: [DONE]": continue
                    try: text=json.loads(line[5:].strip())["choices"][0].get("delta",{}).get("content","")
                    except (ValueError, KeyError, IndexError): continue
                    if text: answer_parts.append(text); yield {"type":"token","text":text}
        answer="".join(answer_parts); self.append(conversation_id,"assistant",answer); yield {"type":"message_complete","content":answer}

    async def _post(self,url,headers,body):
        async with httpx.AsyncClient(timeout=120) as client:
            response=await client.post(url,headers=headers,json=body); response.raise_for_status(); return response

    def project_context(self) -> dict:
        context={"project_dir":str(self.root.parent)}
        for name in (".awe-project.json", ".awe-scope.json"):
            try: context[name]=json.loads((self.root.parent/name).read_text())
            except Exception: context[name]={}
        return context

    def recent_traffic(self, limit: int = 20) -> list[dict]:
        try:
            from pymongo import MongoClient
            docs=MongoClient().awe_proxy_traffic.traffic.find({}, {"_id":0,"host":1,"path":1,"method":1,"status_code":1,"timestamp":1}).sort("timestamp",-1).limit(max(1,min(limit,50)))
            return list(docs)
        except Exception as exc:
            return [{"error":f"Traffic unavailable: {exc}"}]

    def tool_specs(self) -> list[dict]:
        def fn(name, description, properties=None): return {"type":"function","function":{"name":name,"description":description,"parameters":{"type":"object","properties":properties or {}}}}
        return [fn("project_context","Read the current AWE project target and scope"),fn("recent_traffic","Read recent proxy traffic",{"limit":{"type":"integer","minimum":1,"maximum":50}}),fn("scan_sessions","List recent scan sessions",{"limit":{"type":"integer","minimum":1,"maximum":50}}),fn("session_results","Read stored results for a scan session",{"session_id":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":100}}),fn("start_pipeline","Start a project pipeline; this always requires user approval",{"pipeline_key":{"type":"string"}})]

    def execute_tool(self, name: str, arguments: dict, conversation_id: str = "") -> object:
        if name == "project_context": return self.project_context()
        if name == "start_pipeline": return {"approval_required":True, **self.request_approval(conversation_id,"start_pipeline",arguments,"high")}
        if name == "recent_traffic": return self.recent_traffic(int(arguments.get("limit",20)))
        try:
            from database.mongo import get_db
            db=get_db(str(self.root.parent))
            if name == "scan_sessions": return list(db.scan_sessions.find({}, {"_id":0}).sort("started_at",-1).limit(max(1,min(int(arguments.get("limit",20)),50))))
            if name == "session_results": return list(db.results.find({"session_id":arguments.get("session_id")},{"_id":0}).limit(max(1,min(int(arguments.get("limit",50)),100))))
        except Exception as exc: return {"error":str(exc)}
        return {"error":f"Unknown tool: {name}"}

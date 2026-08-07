from __future__ import annotations

import json
import secrets
from pathlib import Path


class TerminalProfileStore:
    def __init__(self, project_dir: Path): self.path=project_dir/".awe-terminal-profiles.json"
    def list(self):
        try: return json.loads(self.path.read_text())
        except Exception: return []
    def create(self, name: str, host: str, port: int, username: str):
        rows=self.list(); item={"id":secrets.token_urlsafe(12),"name":name or host,"host":host,"port":port,"username":username}; rows.append(item); self.path.write_text(json.dumps(rows,indent=2)); return item
    def update(self, profile_id: str, name: str, host: str, port: int, username: str):
        rows=self.list()
        for index, row in enumerate(rows):
            if row.get("id") == profile_id:
                item={"id":profile_id,"name":name or host,"host":host,"port":port,"username":username}
                rows[index]=item
                self.path.write_text(json.dumps(rows,indent=2))
                return item
        return None
    def delete(self, profile_id: str) -> bool:
        rows=self.list(); kept=[row for row in rows if row.get("id")!=profile_id]
        if len(rows)==len(kept): return False
        self.path.write_text(json.dumps(kept,indent=2)); return True

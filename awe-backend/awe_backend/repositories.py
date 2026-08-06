import sys
from pathlib import Path


class LegacyRepositoryFactory:
    """Creates existing Mongo repositories without exposing them to API modules."""

    def __init__(self, legacy_src_dir: Path, mongo_uri: str):
        self.legacy_src_dir = legacy_src_dir.resolve()
        self.mongo_uri = mongo_uri

    def __call__(self, project_dir: Path):
        source = str(self.legacy_src_dir)
        if source not in sys.path:
            sys.path.insert(0, source)
        from database.repository import AweRepository

        return AweRepository(str(project_dir), self.mongo_uri)

    def traffic(self):
        source = str(self.legacy_src_dir)
        if source not in sys.path:
            sys.path.insert(0, source)
        from database.mongo import get_proxy_traffic_db
        return get_proxy_traffic_db(self.mongo_uri).traffic

    def websocket_db(self):
        source = str(self.legacy_src_dir)
        if source not in sys.path:
            sys.path.insert(0, source)
        from database.mongo import get_proxy_traffic_db
        return get_proxy_traffic_db(self.mongo_uri)

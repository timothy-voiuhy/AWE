import os

from containers.parsers._common import _read_jsonl
from containers.results.models import ScreenshotResult


def parse_gowitness(output_dir: str) -> list[ScreenshotResult]:
    results = []
    for obj in _read_jsonl(os.path.join(output_dir, "gowitness.jsonl")):
        url = obj.get("url", "")
        if not url:
            continue
        techs = []
        for t in obj.get("technologies", []) or []:
            name = t.get("name", "") if isinstance(t, dict) else str(t)
            if name:
                techs.append(name)
        r = ScreenshotResult(
            url=url,
            final_url=obj.get("final_url", url),
            status_code=obj.get("response_code", obj.get("status_code", 0)),
            title=obj.get("title", ""),
            screenshot_path=obj.get("screenshot_path", ""),
            technologies=techs,
        )
        r.add_source("gowitness")
        results.append(r)
    return results

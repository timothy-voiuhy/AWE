import os

from containers.parsers._common import _read_lines
from containers.results.models import WordlistEntry


def parse_cewl(output_dir: str) -> list[WordlistEntry]:
    results = []
    for word in _read_lines(os.path.join(output_dir, "cewl_wordlist.txt")):
        if word and not word.startswith("#") and len(word) >= 3:
            r = WordlistEntry(word=word)
            r.add_source("cewl")
            results.append(r)
    return results

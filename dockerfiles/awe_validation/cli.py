"""Container entrypoint; secrets arrive only through the execution environment."""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from awe_validation.engine import PROFILES, execute


def main():
    parser = argparse.ArgumentParser(description="AWE bounded HTTP validation")
    parser.add_argument('--profile', choices=[profile['id'] for profile in PROFILES], required=True)
    parser.add_argument('--output', default='/output')
    args = parser.parse_args()
    try:
        config = json.loads(os.environ.get('AWE_VALIDATION_CONFIG', '{}'))
        data = execute(args.profile, config, args.output)
    except Exception:
        # Malformed contexts can contain credentials; never log exception text.
        destination = Path(args.output); destination.mkdir(parents=True, exist_ok=True)
        data = {'schema_version': 1, 'profile': args.profile, 'outcome': 'inconclusive', 'findings': [], 'requests': [], 'errors': [{'type': 'InvalidConfiguration', 'message': 'Check the required URL and JSON request-context parameters.'}]}
        (destination / 'validation-report.json').write_text(json.dumps(data, indent=2))
    print(f"{args.profile}: {data['outcome']}; {len(data['findings'])} finding(s); {len(data['requests'])} request(s).")
    for error in data.get('errors', []):
        print(f"{error['type']}: {error['message']}")
    print('Redacted report: /output/validation-report.json')
    return 2 if data['outcome'] == 'inconclusive' else 0


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Explicit HA-over-OpenSSH aggregate collector; preflight by default."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from router_agent.home_ssh import collect_home_ssh, preflight
from router_agent.home_observations import write_observation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--collect', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.collect and args.output is None:
        parser.error('--collect requires --output')
    try:
        result = collect_home_ssh(args.config) if args.collect else preflight(args.config)
        if args.output:
            write_observation(args.output, result)
        print(json.dumps({'ready': result['status'] == 'ready', 'passed': result['status'] == 'passed',
                          'blocked_access': result['status'] == 'blocked_access',
                          'request_count': result.get('request_count', 0), 'evidence_written': bool(args.output)}))
        return 0 if result['status'] in ('passed', 'ready') else 2
    except Exception:
        print(json.dumps({'passed': False, 'evidence_written': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

"""Collect a private, descriptive DNS baseline on the existing system resolver.

Pass either an owner-only --config JSON or --system-resolver to opt in directly.
Only /etc/resolv.conf is read for resolver selection, at execution. No settings
are changed. Names, resolver addresses and raw DNS output are never retained.
"""
import argparse
import json
import os
from pathlib import Path
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from router_agent.dns_baseline import make_system_config, validate_config, observe_baseline, observe_dns_diagnostic
from router_agent.network_measurements import (MeasurementError, read_private_json,
    create_output_directory, write_private_result)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--config', type=Path, help='Owner-only fixed baseline JSON configuration')
    choice.add_argument('--system-resolver', action='store_true',
        help='Explicit opt-in to fixed workload; read /etc/resolv.conf only for resolver selection')
    parser.add_argument('--output', required=True, type=Path, help='New private evidence directory')
    parser.add_argument('--diagnostic', action='store_true', help='Separate four-query control observation; not a baseline')
    args = parser.parse_args(argv)
    directory = None
    try:
        config = validate_config(read_private_json(args.config)) if args.config else make_system_config()
        directory = create_output_directory(args.output)
        result = observe_dns_diagnostic(config) if args.diagnostic else observe_baseline(config)
        write_private_result(directory, result)
        print(json.dumps({'kind': result['kind'], 'saved': True,
            'sampling_quality_passed': result.get('sampling_quality_passed'),
            'overall_gain_established': False}, separators=(',', ':')))
        return 0
    except (MeasurementError, OSError) as error:
        print(json.dumps({'error': {'code': str(error) if isinstance(error, MeasurementError)
            else 'local_measurement_failure'}}, separators=(',', ':')))
        return 1
    finally:
        if directory is not None:
            os.close(directory)


if __name__ == '__main__':
    raise SystemExit(main())

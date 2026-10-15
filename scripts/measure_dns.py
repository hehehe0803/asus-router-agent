"""Explicit bounded client-DNS sampling or offline A1/B/A2 comparison.

Private manifest/artifacts only; never changes router, resolver, HA or AdGuard settings.
"""
import argparse
import json
import os
from pathlib import Path
import sys

# Standalone checkout entry point; installed package imports work unchanged.
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from router_agent.network_measurements import (MeasurementError, read_private_json,
    validate_manifest, sample_dns, compare_dns, create_output_directory, write_private_result, manifest_template)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('sample', 'compare'):
        sub = commands.add_parser(name)
        sub.add_argument('--manifest', type=Path, required=True, help='Owner-only JSON manifest fixed before sampling')
        sub.add_argument('--output', type=Path, required=True, help='New owner-0700 evidence directory; never overwritten')
        if name == 'sample':
            sub.add_argument('--stage', choices=('A1', 'B', 'A2'), required=True)
        else:
            for stage in ('a1', 'b', 'a2'):
                sub.add_argument('--' + stage, type=Path, required=True, help='Owner-only stage summary.json')
    template = commands.add_parser('template', help='Create a private upstream-mode manifest proposal; no queries or changes')
    template.add_argument('--output', type=Path, required=True)
    template.add_argument('--resolver', required=True, help='Explicit numeric resolver, written privately')
    template.add_argument('--client-role', required=True, help='Opaque role token, not a personal/device name')
    template.add_argument('--path-id', required=True, help='Opaque fixed client/network path token')
    template.add_argument('--baseline-config', required=True, help='Reviewed baseline SHA256 configuration fingerprint')
    template.add_argument('--candidate-config', required=True, help='Reviewed candidate SHA256 configuration fingerprint')
    template.add_argument('--transport', choices=('udp', 'tcp'), default='udp')
    args = parser.parse_args(argv)
    directory = None
    try:
        if args.command == 'template':
            manifest = manifest_template(resolver=args.resolver, client_role=args.client_role, path_id=args.path_id,
                baseline_config=args.baseline_config, candidate_config=args.candidate_config, transport=args.transport)
            directory = create_output_directory(args.output)
            write_private_result(directory, manifest, filename='manifest.json')
            print(json.dumps({'kind': 'dns_manifest_proposal', 'saved': True, 'network_queries': 0}))
            return 0
        manifest = validate_manifest(read_private_json(args.manifest))
        if args.command == 'compare':
            result = compare_dns(manifest, *(read_private_json(getattr(args, stage)) for stage in ('a1', 'b', 'a2')))
            directory = create_output_directory(args.output)
        else:
            directory = create_output_directory(args.output)
            result = sample_dns(manifest, args.stage)
        write_private_result(directory, result)
        print(json.dumps({'kind': result['kind'], 'saved': True,
            'sampling_quality_passed': result.get('sampling_quality_passed'),
            'latency_criteria_met': result.get('latency_criteria_met'),
            'overall_gain_established': False}, separators=(',', ':')))
        return 0
    except (MeasurementError, OSError):
        # Codes are generated internally; raw paths, names, addresses and errors stay private.
        error = sys.exc_info()[1]
        code = str(error) if isinstance(error, MeasurementError) else 'local_measurement_failure'
        print(json.dumps({'error': {'code': code}}, separators=(',', ':')))
        return 1
    finally:
        if directory is not None:
            os.close(directory)


if __name__ == '__main__':
    raise SystemExit(main())

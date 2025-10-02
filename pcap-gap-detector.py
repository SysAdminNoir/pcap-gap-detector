#!/usr/bin/env python3
"""
PCAP Gap Detector - Single-threaded Version
============================================
Simplified version without multiprocessing overhead.
Should be faster for most use cases since PCAP reading is the bottleneck.
"""

import argparse
import os
import sys
import time
from collections import defaultdict

from scapy.utils import RawPcapReader


# ANSI color codes for better output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def printable_timestamp(ts, resol):
    ts_sec = ts // resol
    ts_subsec = ts % resol
    ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ts_sec))
    return f'{ts_sec_str}.{ts_subsec:06d}'


def format_duration(seconds):
    """Format duration in human-readable form"""
    if seconds < 60:
        return f'{seconds:.1f}s'
    elif seconds < 3600:
        return f'{seconds / 60:.1f}m'
    elif seconds < 86400:
        return f'{seconds / 3600:.1f}h'
    else:
        return f'{seconds / 86400:.1f}d'


class ProfileTimer:
    """Context manager for timing code sections"""

    def __init__(self, name, enabled=True):
        self.name = name
        self.enabled = enabled
        self.elapsed = 0

    def __enter__(self):
        if self.enabled:
            self.start = time.time()
        return self

    def __exit__(self, *args):
        if self.enabled:
            self.elapsed = time.time() - self.start
            print(f'{Colors.OKCYAN}  [{self.name}]{Colors.ENDC} {self.elapsed:.2f}s')


def process_pcap(file_name, diffsecs, csv_output=None, profile=False):
    start_time = time.time()
    timing_data = {}

    print(f'{Colors.HEADER}{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.ENDC}')
    print(f'{Colors.HEADER}{Colors.BOLD}  PCAP Gap Detector (Single-threaded){Colors.ENDC}')
    print(f'{Colors.HEADER}{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.ENDC}\n')

    print(f'{Colors.OKCYAN}File:{Colors.ENDC} {file_name}')
    file_size = os.path.getsize(file_name)
    print(f'{Colors.OKCYAN}Size:{Colors.ENDC} {file_size / (1024 ** 3):.2f} GB')
    print(f'{Colors.OKCYAN}Gap threshold:{Colors.ENDC} {diffsecs} seconds')
    if csv_output:
        print(f'{Colors.OKCYAN}CSV Export:{Colors.ENDC} {csv_output}')
    if profile:
        print(f'{Colors.OKCYAN}Profiling:{Colors.ENDC} Enabled')
    print()

    all_gaps = []
    total_packets = 0
    prev_timestamp = None
    prev_tsres = None

    print(f'{Colors.OKBLUE}Processing PCAP file...{Colors.ENDC}')

    with ProfileTimer("PCAP reading and gap detection", profile) as t1:
        for (_, pkt_metadata) in RawPcapReader(file_name):
            total_packets += 1  # Increment first so we start at 1
            tsres = pkt_metadata.tsresol
            timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow

            if prev_timestamp is not None:
                difference = (timestamp / tsres) - (prev_timestamp / prev_tsres)
                if difference > diffsecs:
                    all_gaps.append({
                        'start': (prev_timestamp, prev_tsres),
                        'end': (timestamp, tsres),
                        'gap': difference,
                        'start_pkt': total_packets - 1,
                        'end_pkt': total_packets
                    })

            prev_timestamp = timestamp
            prev_tsres = tsres

            # Progress indicator every 100k packets
            if not profile and total_packets % 100000 == 0:
                print(f'\r  Packets processed: {total_packets:,}', end='', flush=True)

        if not profile:
            print(f'\r  Packets processed: {total_packets:,}')
        timing_data['processing'] = t1.elapsed if profile else 0

    # Export to CSV if requested
    if csv_output and all_gaps:
        print(f'{Colors.OKBLUE}Exporting to CSV...{Colors.ENDC}')
        with ProfileTimer("CSV export", profile) as t2:
            import csv
            try:
                with open(csv_output, 'w', newline='') as csvfile:
                    fieldnames = ['gap_number', 'packet_start', 'packet_end', 'timestamp_start_utc',
                                  'timestamp_end_utc', 'gap_seconds', 'gap_duration']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()

                    for idx, gap in enumerate(all_gaps, 1):
                        start_ts, start_res = gap['start']
                        end_ts, end_res = gap['end']

                        writer.writerow({
                            'gap_number': idx,
                            'packet_start': gap['start_pkt'],
                            'packet_end': gap['end_pkt'],
                            'timestamp_start_utc': printable_timestamp(start_ts, start_res),
                            'timestamp_end_utc': printable_timestamp(end_ts, end_res),
                            'gap_seconds': f'{gap["gap"]:.6f}',
                            'gap_duration': format_duration(gap['gap'])
                        })
                print(f'{Colors.OKGREEN}CSV exported successfully to {csv_output}{Colors.ENDC}')
            except Exception as e:
                print(f'{Colors.FAIL}Failed to export CSV: {e}{Colors.ENDC}')
            timing_data['csv_export'] = t2.elapsed if profile else 0

    # Sort gaps by size for display
    all_gaps_by_size = sorted(all_gaps, key=lambda x: x['gap'], reverse=True)

    # Display results
    print()
    print(f'{Colors.HEADER}{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.ENDC}')
    print(f'{Colors.HEADER}{Colors.BOLD}  RESULTS{Colors.ENDC}')
    print(f'{Colors.HEADER}{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.ENDC}\n')

    if all_gaps:
        print(f'{Colors.WARNING}Found {len(all_gaps)} gap(s) exceeding {diffsecs}s threshold:{Colors.ENDC}\n')

        # Categorize gaps
        gap_categories = defaultdict(list)
        for gap in all_gaps_by_size:
            duration = gap['gap']
            if duration < 60:
                gap_categories['< 1 minute'].append(gap)
            elif duration < 3600:
                gap_categories['1 min - 1 hour'].append(gap)
            elif duration < 86400:
                gap_categories['1 hour - 1 day'].append(gap)
            else:
                gap_categories['> 1 day'].append(gap)

        # Show summary
        print(f'{Colors.BOLD}Gap Summary:{Colors.ENDC}')
        for category in ['< 1 minute', '1 min - 1 hour', '1 hour - 1 day', '> 1 day']:
            if category in gap_categories:
                print(f'  {category}: {len(gap_categories[category])} gap(s)')
        print()

        # Show detailed gaps
        print(f'{Colors.BOLD}Detailed Gap List (sorted by duration):{Colors.ENDC}\n')
        for idx, gap in enumerate(all_gaps_by_size, 1):
            start_ts, start_res = gap['start']
            end_ts, end_res = gap['end']

            start_str = printable_timestamp(start_ts, start_res)
            end_str = printable_timestamp(end_ts, end_res)
            gap_str = format_duration(gap['gap'])

            color = Colors.FAIL if gap['gap'] > 3600 else Colors.WARNING

            print(f'{color}Gap #{idx}:{Colors.ENDC}')
            print(f'  Packets: {gap["start_pkt"]} -> {gap["end_pkt"]}')
            print(f'  From: {start_str} UTC')
            print(f'  To:   {end_str} UTC')
            print(f'  Duration: {gap_str} ({gap["gap"]:.2f} seconds)')
            print()
    else:
        print(f'{Colors.OKGREEN}No gaps found exceeding {diffsecs}s threshold{Colors.ENDC}\n')

    # Summary statistics
    elapsed = time.time() - start_time
    print(f'{Colors.HEADER}{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.ENDC}')
    print(f'{Colors.HEADER}{Colors.BOLD}  STATISTICS{Colors.ENDC}')
    print(f'{Colors.HEADER}{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.ENDC}\n')
    print(f'{Colors.OKGREEN}Total packets processed:{Colors.ENDC} {total_packets:,}')
    print(f'{Colors.OKGREEN}Processing time:{Colors.ENDC} {elapsed:.2f} seconds')
    print(f'{Colors.OKGREEN}Processing rate:{Colors.ENDC} {total_packets / elapsed:,.0f} packets/second')

    # Show profiling breakdown if enabled
    if profile and timing_data:
        print()
        print(f'{Colors.BOLD}Performance Breakdown:{Colors.ENDC}')
        total_accounted = sum(timing_data.values())
        for name, duration in timing_data.items():
            percentage = (duration / elapsed * 100) if elapsed > 0 else 0
            print(f'  {name:.<30} {duration:>6.2f}s ({percentage:>5.1f}%)')

        if total_accounted < elapsed:
            overhead = elapsed - total_accounted
            overhead_pct = (overhead / elapsed * 100) if elapsed > 0 else 0
            print(f'  {"other/overhead":.<30} {overhead:>6.2f}s ({overhead_pct:>5.1f}%)')

    print()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='PCAP Timestamp Gap Detector (Single-threaded)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python script.py --pcap capture.pcap --seconds 5
  python script.py --pcap large.pcap --seconds 10 --csv gaps.csv --profile
        '''
    )
    parser.add_argument('--pcap', metavar='<pcap file name>', required=True,
                        help='Path to PCAP file')
    parser.add_argument('--seconds', metavar='<seconds>', required=True, type=float,
                        help='Gap threshold in seconds')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    parser.add_argument('--csv', metavar='<output.csv>', dest='csv_output',
                        help='Export gaps to CSV file')
    parser.add_argument('--profile', action='store_true',
                        help='Enable performance profiling to show time breakdown')

    args = parser.parse_args()

    # Disable colors if requested
    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith('_'):
                setattr(Colors, attr, '')

    if not os.path.isfile(args.pcap):
        print(f'{Colors.FAIL}Error: "{args.pcap}" does not exist{Colors.ENDC}', file=sys.stderr)
        sys.exit(1)

    try:
        process_pcap(args.pcap, args.seconds, args.csv_output, args.profile)
    except KeyboardInterrupt:
        print(f'\n{Colors.WARNING}Interrupted by user{Colors.ENDC}')
        sys.exit(130)
    except Exception as e:
        print(f'{Colors.FAIL}Error: {e}{Colors.ENDC}', file=sys.stderr)
        sys.exit(1)

    sys.exit(0)
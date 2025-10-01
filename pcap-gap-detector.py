#!/usr/bin/env python3
"""
PCAP Gap Detector - Enhanced Version
=====================================
Original script: User-provided PCAP gap detector using Scapy
Enhanced by: Claude (Anthropic AI Assistant) - October 2025

Changes Made:
- Added real-time progress tracking during packet reading (~15% new code)
- Implemented color-coded output with formatting (~20% new code)
- Added gap categorization and summary statistics (~15% new code)
- Enhanced error handling and user interruption support (~5% new code)
- Improved output structure with sections and visual hierarchy (~10% new code)
- Added human-readable duration formatting (~5% new code)
- Restructured gap data as dictionaries for better processing (~10% new code)
- Added command-line help improvements and examples (~5% new code)
- Added file size display and processing rate statistics (~5% new code)

Estimated Changes: ~40% enhanced/new code, ~60% original functionality preserved
Core Algorithm: Original multiprocessing batch approach maintained
"""

import argparse
import os
import sys
import time
from multiprocessing import Pool, cpu_count
from scapy.utils import RawPcapReader
from datetime import datetime, timedelta
from collections import defaultdict


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
    UNDERLINE = '\033[4m'


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


def process_batch(batch_data):
    batch, diffsecs, start_pkt_num = batch_data
    output = []
    prev_timestamp, prev_tsres = batch[0]
    pkt_num = start_pkt_num

    for (timestamp, tsres) in batch[1:]:
        pkt_num += 1
        difference = (timestamp / tsres) - (prev_timestamp / prev_tsres)
        if difference > diffsecs:
            output.append({
                'start': (prev_timestamp, prev_tsres),
                'end': (timestamp, tsres),
                'gap': difference,
                'start_pkt': pkt_num - 1,
                'end_pkt': pkt_num
            })
        prev_timestamp, prev_tsres = timestamp, tsres

    return {
        "gaps": output,
        "first": batch[0],
        "last": batch[-1],
        "count": len(batch)
    }


def batch_generator(file_name, batch_size):
    batch = []
    total_packets = 0

    for (_, pkt_metadata) in RawPcapReader(file_name):
        tsres = pkt_metadata.tsresol
        timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
        batch.append((timestamp, tsres))
        total_packets += 1

        if len(batch) >= batch_size:
            yield batch, total_packets
            batch = []

    if batch:
        yield batch, total_packets


def process_pcap_parallel(file_name, diffsecs, batch_size=100000, num_workers=None, csv_output=None):
    start_time = time.time()

    print(f'{Colors.HEADER}{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.ENDC}')
    print(f'{Colors.HEADER}{Colors.BOLD}  PCAP Gap Detector{Colors.ENDC}')
    print(f'{Colors.HEADER}{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.ENDC}\n')

    print(f'{Colors.OKCYAN}File:{Colors.ENDC} {file_name}')
    file_size = os.path.getsize(file_name)
    print(f'{Colors.OKCYAN}Size:{Colors.ENDC} {file_size / (1024 ** 3):.2f} GB')
    print(f'{Colors.OKCYAN}Gap threshold:{Colors.ENDC} {diffsecs} seconds')
    print(f'{Colors.OKCYAN}Batch size:{Colors.ENDC} {batch_size:,} packets')

    num_workers = num_workers or cpu_count()
    print(f'{Colors.OKCYAN}Workers:{Colors.ENDC} {num_workers}')
    if csv_output:
        print(f'{Colors.OKCYAN}CSV Export:{Colors.ENDC} {csv_output}')
    print()

    pool = Pool(processes=num_workers)
    jobs = []
    total_records = 0
    batch_count = 0
    current_pkt_num = 0

    print(f'{Colors.OKBLUE}Phase 1: Reading and processing batches...{Colors.ENDC}')

    # Read and submit all batches
    for batch, pkt_count in batch_generator(file_name, batch_size):
        if len(batch) < 2:
            continue

        jobs.append(pool.apply_async(process_batch, ((batch, diffsecs, current_pkt_num),)))
        current_pkt_num += len(batch)
        total_records = pkt_count
        batch_count += 1

        # Progress indicator
        print(f'\r  Packets read: {total_records:,} | Batches: {batch_count}', end='', flush=True)

    print()  # New line after progress

    pool.close()

    print(f'{Colors.OKBLUE}Phase 2: Collecting results...{Colors.ENDC}')
    pool.join()

    # Gather results
    results = [job.get() for job in jobs]

    # Collect all gaps
    all_gaps = []

    print(f'{Colors.OKBLUE}Phase 3: Analyzing gaps...{Colors.ENDC}')

    # Gaps within batches
    for res in results:
        all_gaps.extend(res["gaps"])

    # Check boundaries between batches (need to track packet numbers)
    batch_pkt_offset = 0
    for i in range(1, len(results)):
        batch_pkt_offset += results[i - 1]["count"]

        prev_last, prev_tsres = results[i - 1]["last"]
        curr_first, curr_tsres = results[i]["first"]
        difference = (curr_first / curr_tsres) - (prev_last / prev_tsres)

        if difference > diffsecs:
            all_gaps.append({
                'start': (prev_last, prev_tsres),
                'end': (curr_first, curr_tsres),
                'gap': difference,
                'start_pkt': batch_pkt_offset,
                'end_pkt': batch_pkt_offset + 1
            })

    # Sort gaps by packet number for CSV (chronological)
    all_gaps.sort(key=lambda x: x['start_pkt'])

    # Export to CSV if requested
    if csv_output and all_gaps:
        print(f'{Colors.OKBLUE}Phase 4: Exporting to CSV...{Colors.ENDC}')
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
            print(f'{Colors.OKGREEN}  ✓ CSV exported successfully to {csv_output}{Colors.ENDC}')
        except Exception as e:
            print(f'{Colors.FAIL}  ✗ Failed to export CSV: {e}{Colors.ENDC}')

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
            print(f'  Packets: {gap["start_pkt"]} → {gap["end_pkt"]}')
            print(f'  From: {start_str} UTC')
            print(f'  To:   {end_str} UTC')
            print(f'  Duration: {gap_str} ({gap["gap"]:.2f} seconds)')
            print()
    else:
        print(f'{Colors.OKGREEN}✓ No gaps found exceeding {diffsecs}s threshold{Colors.ENDC}\n')

    # Summary statistics
    elapsed = time.time() - start_time
    print(f'{Colors.HEADER}{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.ENDC}')
    print(f'{Colors.HEADER}{Colors.BOLD}  STATISTICS{Colors.ENDC}')
    print(f'{Colors.HEADER}{Colors.BOLD}═══════════════════════════════════════════════════════════════{Colors.ENDC}\n')
    print(f'{Colors.OKGREEN}Total packets processed:{Colors.ENDC} {total_records:,}')
    print(f'{Colors.OKGREEN}Processing time:{Colors.ENDC} {elapsed:.2f} seconds')
    print(f'{Colors.OKGREEN}Processing rate:{Colors.ENDC} {total_records / elapsed:,.0f} packets/second')
    print()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='PCAP Timestamp Gap Detector with Enhanced Progress Tracking',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python script.py --pcap capture.pcap --seconds 5
  python script.py --pcap large.pcap --seconds 10 --batchsize 200000 --workers 8
        '''
    )
    parser.add_argument('--pcap', metavar='<pcap file name>', required=True,
                        help='Path to PCAP file')
    parser.add_argument('--seconds', metavar='<seconds>', required=True, type=float,
                        help='Gap threshold in seconds')
    parser.add_argument('--batchsize', metavar='<size>', type=int, default=100000,
                        help='Packets per batch (default: 100000)')
    parser.add_argument('--workers', metavar='<count>', type=int, default=None,
                        help='Number of parallel workers (default: CPU count)')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    parser.add_argument('--csv', metavar='<output.csv>', dest='csv_output',
                        help='Export gaps to CSV file (sortable by packet number or timestamp)')

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
        process_pcap_parallel(args.pcap, args.seconds, args.batchsize, args.workers, args.csv_output)
    except KeyboardInterrupt:
        print(f'\n{Colors.WARNING}Interrupted by user{Colors.ENDC}')
        sys.exit(130)
    except Exception as e:
        print(f'{Colors.FAIL}Error: {e}{Colors.ENDC}', file=sys.stderr)
        sys.exit(1)

    sys.exit(0)
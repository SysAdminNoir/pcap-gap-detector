# PCAP Gap Detector

Detects timestamp gaps in PCAP files using parallel processing.

## Requirements

- Python 3.6+
- Scapy

```bash
pip install scapy
```

## Usage

```bash
python pcap_gap_detector.py --pcap <file> --seconds <threshold>
```

## Options

```
--pcap <file>           PCAP file to analyze (required)
--seconds <threshold>   Gap threshold in seconds (required)
--batchsize <size>      Packets per batch (default: 100000)
--workers <count>       Number of parallel workers (default: CPU count)
--csv <output.csv>      Export gaps to CSV file
--no-color              Disable colored output
```

## Examples

Basic usage:
```bash
python pcap_gap_detector.py --pcap capture.pcap --seconds 5
```

Export to CSV:
```bash
python pcap_gap_detector.py --pcap capture.pcap --seconds 5 --csv gaps.csv
```

Large file with custom settings:
```bash
python pcap_gap_detector.py --pcap large.pcap --seconds 10 --batchsize 200000 --workers 8
```

## How It Works

1. Reads PCAP file in batches
2. Processes batches in parallel across multiple CPU cores
3. Detects gaps between packet timestamps that exceed the threshold
4. Reports gaps with packet numbers and timestamps

## CSV Output

When using `--csv`, exports the following columns:

- gap_number
- packet_start
- packet_end
- timestamp_start_utc
- timestamp_end_utc
- gap_seconds
- gap_duration

## Attribution

Original script enhanced with progress tracking, CSV export, and improved output formatting by Claude (Anthropic AI) in October 2025. Core multiprocessing algorithm preserved from original.

## License
BSD 3-Clause License

Copyright (c) 2025, Justin Hendren

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#!/usr/bin/env python3
"""
BIRD BGP & Babel Prometheus Exporter

Communicates with BIRD via Unix socket (instead of birdc subprocess) and
exposes Prometheus metrics for:
  - BGP session state (Established/Connect/Active/...)
  - BGP neighbor/local AS numbers
  - BGP Channel (ipv4/ipv6) state and route counts (imported, exported, preferred)
  - Babel neighbor RTT (ms)

Usage:
    python3 bird_exporter.py [port]

Default port: 8000
Metrics endpoint: http://localhost:8000/metrics
"""

import socket
import time
import re
import sys
from prometheus_client import start_http_server, Gauge

# Default BIRD control socket path
BIRD_SOCKET = '/var/run/bird/bird.ctl'

# ============================================================
# Prometheus Metrics Definitions
# ============================================================

# --- BGP metrics ---
BGP_UP = Gauge(
    'bird_bgp_up',
    'BGP session state (1=Established, 0=other)',
    ['name']
)
BGP_NEIGHBOR_AS = Gauge(
    'bird_bgp_neighbor_as',
    'BGP neighbor AS number',
    ['name']
)
BGP_LOCAL_AS = Gauge(
    'bird_bgp_local_as',
    'BGP local AS number',
    ['name']
)
CHANNEL_UP = Gauge(
    'bird_channel_up',
    'BGP channel state (1=UP, 0=DOWN)',
    ['name', 'channel']
)
CHANNEL_ROUTES_IMPORTED = Gauge(
    'bird_channel_routes_imported',
    'Routes imported in channel',
    ['name', 'channel']
)
CHANNEL_ROUTES_EXPORTED = Gauge(
    'bird_channel_routes_exported',
    'Routes exported in channel',
    ['name', 'channel']
)
CHANNEL_ROUTES_PREFERRED = Gauge(
    'bird_channel_routes_preferred',
    'Routes preferred in channel',
    ['name', 'channel']
)

# --- Babel metrics ---
BABEL_NEIGHBOR_RTT = Gauge(
    'bird_babel_neighbor_rtt_ms',
    'Babel neighbor RTT in milliseconds',
    ['neighbor_ip', 'interface']
)

# --- System health ---
BIRD_UP = Gauge(
    'bird_up',
    '1 if birdc command succeeded, 0 otherwise'
)


# ============================================================
# BIRD Socket Interface
# ============================================================

def run_birdc(args):
    """
    Run a BIRD command via the Unix control socket.

    The BIRD control protocol works as follows:
      1. Client connects to the socket; server sends a banner line like
         "0001 BIRD v2.19.1 ready".
      2. Client sends a command terminated by newline, e.g.
         "show protocols all\n".
      3. Server replies with one or more data lines, each prefixed by a
         4-digit status code. Continuation lines use "1xxx", the final line
         uses "0000" (or "2xxx"/"5xxx"/"9xxx" for some replies).
      4. This function strips the status-code prefixes and returns the
         joined data as plain text (matching birdc stdout).

    Args:
        args: list of command tokens, e.g. ['show', 'protocols', 'all']

    Returns:
        The command output as a string, or '' on error.
    """
    command = ' '.join(args) + '\n'
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect(BIRD_SOCKET)

            # Read the server banner line
            _read_bird_line(s)

            # Send the command
            s.sendall(command.encode())

            # Collect response lines until a terminating zero-code line
            output_lines = []
            while True:
                line = _read_bird_line(s)
                if line is None:
                    break  # connection closed
                code = line[:4]
                # Strip the leading "NNNN " status code from each line
                if len(line) > 4 and line[4] == ' ':
                    data = line[5:]
                else:
                    data = line[4:]

                output_lines.append(data)

                # "0000" marks the end of the response
                if code == '0000':
                    break

            return '\n'.join(output_lines)
    except Exception as e:
        print(f"[bird_exporter] bird socket error: {e}", file=sys.stderr)
        return ""


def _read_bird_line(sock):
    """
    Read a single newline-terminated line from the BIRD socket.

    Returns the line without trailing newline, or None if the connection
    is closed before any data is received.
    """
    buf = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            if not buf:
                return None
            break
        if chunk == b'\n':
            break
        buf.extend(chunk)
    return buf.decode(errors='replace')


# ============================================================
# BGP Parsing
# ============================================================

def parse_bgp_protocols(output):
    """
    Parse the output of 'birdc show protocols all' for BGP protocols.

    Uses line-by-line parsing to detect new protocol blocks by looking for
    lines matching the pattern: <name> BGP --- ...

    Returns a list of dicts with keys:
        name         - protocol name (e.g. ibgp_hham, as0298)
        bgp_state    - Established / Connect / Active / ...
        neighbor_as  - neighbor AS number
        local_as     - local AS number
        channels     - dict of { 'ipv4': {...}, 'ipv6': {...} }
                          each channel has: state, imported, exported, preferred
    """
    protocols = []
    current = None
    current_channel = None

    # Regex to match a BGP protocol summary line:
    #   <name> BGP --- <state> <since> <bgp_state> [extra...]
    bgp_header_re = re.compile(
        r'^(\S+)\s+BGP\s+---\s+\S+\s+\S+\s+(\S+)'
    )

    for line in output.split('\n'):
        stripped = line.strip()

        # Skip empty lines and the "BIRD X.Y.Z ready." line
        if not stripped or stripped.startswith('BIRD '):
            continue

        # Check if this is a new BGP protocol header
        m = bgp_header_re.match(stripped)
        if m:
            # Save previous protocol
            if current:
                protocols.append(current)

            current = {
                'name': m.group(1),
                'bgp_state': m.group(2),
                'neighbor_as': 0,
                'local_as': 0,
                'channels': {},
            }
            current_channel = None
            continue

        # If we're not inside a BGP block, skip
        if current is None:
            continue

        # Inside a BGP protocol block, parse detail lines
        if stripped.startswith('Neighbor AS:'):
            try:
                current['neighbor_as'] = int(
                    stripped.split(':')[1].strip()
                )
            except ValueError:
                pass

        elif stripped.startswith('Local AS:'):
            try:
                current['local_as'] = int(
                    stripped.split(':')[1].strip()
                )
            except ValueError:
                pass

        elif stripped.startswith('Channel ipv4'):
            current_channel = 'ipv4'
            current['channels'][current_channel] = {
                'state': 'DOWN',
                'imported': 0,
                'exported': 0,
                'preferred': 0,
            }

        elif stripped.startswith('Channel ipv6'):
            current_channel = 'ipv6'
            current['channels'][current_channel] = {
                'state': 'DOWN',
                'imported': 0,
                'exported': 0,
                'preferred': 0,
            }

        elif current_channel and stripped.startswith('State:'):
            state_val = stripped.split(':')[1].strip()
            current['channels'][current_channel]['state'] = state_val

        elif current_channel and stripped.startswith('Routes:'):
            # Routes: NNN imported, MMM exported, PPP preferred
            match = re.match(
                r'Routes:\s+(\d+)\s+imported,\s+(\d+)\s+exported,\s+(\d+)\s+preferred',
                stripped,
            )
            if match:
                current['channels'][current_channel]['imported'] = int(
                    match.group(1)
                )
                current['channels'][current_channel]['exported'] = int(
                    match.group(2)
                )
                current['channels'][current_channel]['preferred'] = int(
                    match.group(3)
                )

    # Don't forget the last protocol
    if current:
        protocols.append(current)

    return protocols


# ============================================================
# Babel Parsing
# ============================================================

def parse_babel_neighbors(output):
    """
    Parse the output of 'birdc show protocols all babel1' for Babel neighbors.

    Expected format (table):
        IP address                Interface  Metric Routes Hellos Expires Auth  RTT (ms)
        fe80::5                   wg2sthk       123     10     16   4.172 No      41.689

    Returns a list of dicts with keys: ip, interface, rtt_ms
    """
    neighbors = []
    lines = output.split('\n')

    # Locate the header line that contains "IP address" and "RTT"
    header_idx = None
    for i, line in enumerate(lines):
        if 'IP address' in line and 'RTT' in line:
            header_idx = i
            break

    if header_idx is None:
        return neighbors

    # Parse data lines that follow the header
    for j in range(header_idx + 1, len(lines)):
        stripped = lines[j].strip()
        if not stripped:
            break

        parts = stripped.split()
        # Expected columns: IP, Interface, Metric, Routes, Hellos, Expires, Auth, RTT(ms)
        # RTT is at index 7 because Auth column (e.g. "No") exists at index 6
        if len(parts) >= 8:
            try:
                rtt = float(parts[7])
                neighbors.append({
                    'ip': parts[0],
                    'interface': parts[1],
                    'rtt_ms': rtt,
                })
            except ValueError:
                continue

    return neighbors


# ============================================================
# Metrics Collection
# ============================================================

def collect_metrics():
    """Run birdc commands, parse output, and update Prometheus metrics."""

    # ---- BGP ----
    bgp_output = run_birdc(['show', 'protocols', 'all'])
    if not bgp_output:
        BIRD_UP.set(0)
        return

    BIRD_UP.set(1)
    protocols = parse_bgp_protocols(bgp_output)

    for proto in protocols:
        name = proto['name']

        # BGP session state: 1 if Established, 0 otherwise
        BGP_UP.labels(name=name).set(1 if proto['bgp_state'] == 'Established' else 0)

        # AS numbers
        BGP_NEIGHBOR_AS.labels(name=name).set(proto['neighbor_as'])
        BGP_LOCAL_AS.labels(name=name).set(proto['local_as'])

        # Per-channel metrics
        for ch_name, ch_data in proto['channels'].items():
            CHANNEL_UP.labels(name=name, channel=ch_name).set(
                1 if ch_data['state'] == 'UP' else 0
            )
            CHANNEL_ROUTES_IMPORTED.labels(name=name, channel=ch_name).set(
                ch_data['imported']
            )
            CHANNEL_ROUTES_EXPORTED.labels(name=name, channel=ch_name).set(
                ch_data['exported']
            )
            CHANNEL_ROUTES_PREFERRED.labels(name=name, channel=ch_name).set(
                ch_data['preferred']
            )

    # ---- Babel ----
    babel_output = run_birdc(['show', 'protocols', 'all', 'babel1'])
    if babel_output:
        neighbors = parse_babel_neighbors(babel_output)
        for n in neighbors:
            BABEL_NEIGHBOR_RTT.labels(
                neighbor_ip=n['ip'],
                interface=n['interface'],
            ).set(n['rtt_ms'])


# ============================================================
# Main
# ============================================================

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    start_http_server(port)
    print(f"[bird_exporter] Listening on :{port}/metrics", flush=True)

    while True:
        collect_metrics()
        time.sleep(15)


if __name__ == '__main__':
    main()
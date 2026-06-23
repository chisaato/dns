#!/usr/bin/env python3
"""
Rule builder for dnsdist Phase 2.

Downloads DNS blocklist/allowlist sources, parses hosts/adblock/plain domain
formats, applies allowlist overrides, and outputs files consumable by dnsdist.

Usage:
  python3 rule-builder/rule_builder.py [--config rule-builder/config.yaml] [--output-dir dnsdist/generated]
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone

try:
    from google.protobuf import descriptor_pool, descriptor_pb2, message_factory
    HAS_PROTOBUF = True
except ImportError:
    HAS_PROTOBUF = False


# ---------------------------------------------------------------------------
# Minimal YAML parser — handles only the config format we need
# ---------------------------------------------------------------------------

def _parse_yaml_value(val: str):
    """Convert a YAML string value to Python type."""
    val = val.strip()
    if val.lower() == 'true':
        return True
    if val.lower() == 'false':
        return False
    # quoted string
    if (val.startswith('"') and val.endswith('"')) or \
       (val.startswith("'") and val.endswith("'")):
        return val[1:-1]
    # unquoted string
    return val


def parse_config(path: str) -> dict:
    """Minimal YAML parser for rule-builder config structure.

    Expects:
      rule_sources:
        - name: ...
          url: ...
          enabled: true|false
          action: nxdomain|zero_ip
      allowlist_sources:
        - name: ...
          url: ...
          enabled: true|false
      mac_remote_url: https://...
      geosite_url: https://...
    """
    sources = []
    allowlist_sources = []
    mac_remote_url = ''
    geosite_url = ''
    current_section = None
    current_item = None
    current_key = None

    with open(path, 'r') as f:
        for raw_line in f:
            line = raw_line.rstrip()
            # skip comments and blank lines
            stripped = line.lstrip()
            if not stripped or stripped.startswith('#'):
                continue

            indent = len(line) - len(stripped)

            # top-level key
            if indent == 0 and not stripped.startswith('-'):
                # Save in-progress item before switching section
                if current_item is not None and current_section:
                    (sources if current_section == 'rule_sources' else allowlist_sources).append(current_item)
                    current_item = None
                key = stripped.split(':', 1)[0].strip()
                if key == 'rule_sources':
                    current_section = 'rule_sources'
                elif key == 'allowlist_sources':
                    current_section = 'allowlist_sources'
                elif key == 'mac_remote_url':
                    mac_remote_url = stripped.split(':', 1)[1].strip().strip('"').strip("'")
                    current_section = None
                elif key == 'geosite_url':
                    geosite_url = stripped.split(':', 1)[1].strip().strip('"').strip("'")
                    current_section = None
                else:
                    # unknown top-level key, skip
                    current_section = None
                current_item = None
                continue

            # list item marker
            if indent == 2 and stripped.startswith('- '):
                # save previous item
                if current_item is not None:
                    (sources if current_section == 'rule_sources' else allowlist_sources).append(current_item)
                current_item = {}
                rest = stripped[2:].strip()
                if ':' in rest and not rest.startswith('"'):
                    k, v = rest.split(':', 1)
                    current_item[k.strip()] = _parse_yaml_value(v)
                continue

            # item key-value pairs (indent 4)
            if indent == 4 and current_item is not None:
                if ':' in stripped:
                    k, v = stripped.split(':', 1)
                    current_item[k.strip()] = _parse_yaml_value(v)
                continue

        # save last item
        if current_item is not None:
            (sources if current_section == 'rule_sources' else allowlist_sources).append(current_item)

    return {
        'rule_sources': sources,
        'allowlist_sources': allowlist_sources,
        'mac_remote_url': mac_remote_url,
        'geosite_url': geosite_url,
    }


# ---------------------------------------------------------------------------
# HTTP download
# ---------------------------------------------------------------------------

def normalize_mac(mac: str) -> str | None:
    """Normalize MAC address to lowercase hex without separators.

    Accepts formats like:
      - 04:7C:16:BF:92:3C
      - 04-7C-16-BF-92-3C
      - 047C16BF923C
    Returns 12-char lowercase hex string, or None if invalid.
    """
    mac = mac.strip().lower()
    # Remove common separators
    mac = mac.replace(':', '').replace('-', '').replace('.', '')
    # Must be exactly 12 hex chars
    if len(mac) != 12:
        return None
    try:
        int(mac, 16)
    except ValueError:
        return None
    return mac


def _read_with_progress(resp, label: str) -> bytes:
    """Read response body with progress logging."""
    total = resp.headers.get('Content-Length')
    total = int(total) if total else None
    chunks = []
    downloaded = 0
    last_log = 0

    while True:
        chunk = resp.read(65536)
        if not chunk:
            break
        chunks.append(chunk)
        downloaded += len(chunk)

        if total:
            pct = downloaded * 100 // total
            # Log every 10% or at completion
            if pct - last_log >= 10 or downloaded == total:
                mb = downloaded / (1024 * 1024)
                total_mb = total / (1024 * 1024)
                print(f"    {label}: {pct}% ({mb:.1f}/{total_mb:.1f} MB)")
                last_log = pct
        else:
            # No Content-Length, log every 1MB
            mb = downloaded / (1024 * 1024)
            if mb - last_log >= 1:
                print(f"    {label}: {mb:.1f} MB downloaded")
                last_log = int(mb)

    print(f"    {label}: done ({downloaded / (1024 * 1024):.1f} MB)")
    return b''.join(chunks)


def download(url: str, timeout: int = 30, label: str = "download") -> str | None:
    """Download URL content as text. Returns None on failure."""
    req = urllib.request.Request(url, headers={
        'User-Agent': 'dnsdist-rule-builder/0.1',
    })
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = _read_with_progress(resp, label)
                # Try UTF-8 first, then Latin-1 as fallback
                try:
                    return data.decode('utf-8')
                except UnicodeDecodeError:
                    return data.decode('latin-1')
        except Exception as e:
            if attempt < 2:
                print(f"    {label}: retry {attempt + 1}/3 after error: {e}", file=sys.stderr)
                time.sleep(5)
            else:
                print(f"  [download failed after 3 retries: {e}]", file=sys.stderr)
                return None
    return None


def download_binary(url: str, timeout: int = 60, label: str = "download") -> bytes | None:
    """Download URL content as binary. Returns None on failure."""
    req = urllib.request.Request(url, headers={
        'User-Agent': 'dnsdist-rule-builder/0.1',
    })
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return _read_with_progress(resp, label)
        except Exception as e:
            if attempt < 2:
                print(f"    {label}: retry {attempt + 1}/3 after error: {e}", file=sys.stderr)
                time.sleep(5)
            else:
                print(f"  [download failed after 3 retries: {e}]", file=sys.stderr)
                return None
    return None


# ---------------------------------------------------------------------------
# Geosite protobuf parsing
# ---------------------------------------------------------------------------

def build_geosite_descriptor():
    """Build geosite protobuf descriptor dynamically."""
    proto_desc = descriptor_pb2.FileDescriptorProto()
    proto_desc.name = "geosite.proto"
    proto_desc.syntax = "proto3"

    msg_domain = proto_desc.message_type.add()
    msg_domain.name = "Domain"
    enum_type = msg_domain.enum_type.add()
    enum_type.name = "Type"
    for i, name in enumerate(["Plain", "Domain", "Full"]):
        val = enum_type.value.add()
        val.name = name
        val.number = i

    f = msg_domain.field.add()
    f.name = "type"
    f.number = 1
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_ENUM
    f.type_name = ".Domain.Type"
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL

    f = msg_domain.field.add()
    f.name = "value"
    f.number = 2
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL

    f = msg_domain.field.add()
    f.name = "attribute"
    f.number = 3
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED

    msg_site = proto_desc.message_type.add()
    msg_site.name = "GeoSite"

    f = msg_site.field.add()
    f.name = "country_code"
    f.number = 1
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL

    f = msg_site.field.add()
    f.name = "domain"
    f.number = 2
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    f.type_name = ".Domain"
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED

    msg_list = proto_desc.message_type.add()
    msg_list.name = "GeoSiteList"

    f = msg_list.field.add()
    f.name = "site"
    f.number = 1
    f.type = descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
    f.type_name = ".GeoSite"
    f.label = descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED

    pool = descriptor_pool.Default()
    pool.Add(proto_desc)
    file_desc = pool.FindFileByName("geosite.proto")

    return message_factory.GetMessageClass(file_desc.message_types_by_name['GeoSiteList'])


def extract_cn_domains(data: bytes) -> list[str]:
    """Extract CN domains from geosite.dat protobuf data."""
    GeoSiteList = build_geosite_descriptor()
    geo_list = GeoSiteList()
    geo_list.ParseFromString(data)

    cn_site = None
    for site in geo_list.site:
        if site.country_code == 'CN':
            cn_site = site
            break

    if cn_site is None:
        print("  [ERROR] CN entry not found", file=sys.stderr)
        return []

    print(f"  CN entries: {len(cn_site.domain)} domains")

    domains = set()
    skipped = 0

    for d in cn_site.domain:
        value = d.value.strip().lower()
        if not value:
            continue
        if '.' not in value:
            skipped += 1
            continue
        if '*' in value:
            continue
        domains.add(value)

    print(f"  Valid domains: {len(domains)}")
    print(f"  Skipped (no dot): {skipped}")

    return sorted(domains)


# ---------------------------------------------------------------------------
# Rule parsers
# ---------------------------------------------------------------------------

# Adblock: ||domain^ or |http://domain^ or ||domain (without ^ suffix)
RE_ADBLOCK = re.compile(r'^\|+\|?(https?://)?(?P<domain>[a-zA-Z0-9][a-zA-Z0-9_.-]*[a-zA-Z0-9])\^?(?:\$.*)?$')

# Adblock allow: @@||domain^ or @@||domain
RE_ADBLOCK_ALLOW = re.compile(r'^@@\|\|?(https?://)?(?P<domain>[a-zA-Z0-9][a-zA-Z0-9_.-]*[a-zA-Z0-9])\^?(?:\$.*)?$')

# Hosts: IP + domain (second non-whitespace field)
RE_HOSTS = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::)\s+(?P<domain>\S+)(?:\s|#|$)', re.IGNORECASE)

# Adblock comment / section header
RE_ADBLOCK_META = re.compile(r'^!')

# Adblock cosmetic / element hiding
RE_COSMETIC = re.compile(r'(?:##|#@#|#\?#)')

# Adblock regex rule
RE_ADBLOCK_REGEX = re.compile(r'^/[^/]+/')


def parse_hosts_line(line: str) -> str | None:
    """Extract domain from a hosts-format line. Returns None if not a hosts rule."""
    m = RE_HOSTS.match(line)
    if not m:
        return None
    domain = m.group('domain').lower().rstrip('.')
    if not domain or domain in ('localhost', 'localhost.localdomain',
                                'ip6-localhost', 'ip6-loopback'):
        return None
    return domain


def parse_adblock_line(line: str) -> tuple[str, bool] | None:
    """Parse an Adblock/adblock-style DNS line. Returns (domain, is_allow) or None.

    Returns None for unsupported rules (cosmetic, regex, $modifier lines).
    """
    line = line.strip()

    # Skip comments, sections
    if not line or line.startswith('#') or RE_ADBLOCK_META.match(line):
        return None

    # Skip cosmetic, element-hiding rules
    if RE_COSMETIC.search(line):
        return None

    # Skip regex rules
    if RE_ADBLOCK_REGEX.match(line):
        return None

    # Allow rules: @@||domain^
    m = RE_ADBLOCK_ALLOW.match(line)
    if m:
        return (m.group('domain').lower(), True)

    # Block rules (supports ||domain^, ||domain, ||domain^$modifier, etc.)
    m = RE_ADBLOCK.match(line)
    if not m:
        return None

    domain = m.group('domain').lower()
    return (domain, False)


def parse_plain_domain(line: str) -> str | None:
    """Parse a bare domain name line (no prefix)."""
    line = line.strip()
    if not line or line.startswith('#') or line.startswith('!'):
        return None
    # Must look like a domain: contains a dot, no spaces, no special prefix
    if ' ' in line or '/' in line or '|' in line:
        return None
    if '.' not in line:
        return None
    domain = line.lower().rstrip('.')
    return domain


def is_unsupported_line(line: str) -> bool:
    """Check if a non-comment, non-empty line is unsupported (not parseable as any format)."""
    line = line.strip()
    if not line or line.startswith('#') or RE_ADBLOCK_META.match(line):
        return False  # not unsupported, just a comment
    if RE_HOSTS.match(line):
        return False
    if RE_ADBLOCK_ALLOW.match(line) or RE_ADBLOCK.match(line):
        return False
    if parse_plain_domain(line):
        return False
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def process_source(source: dict, allow_domains: set) -> dict:
    """
    Download and parse a single rule source. Returns stats dict.

    Also populates global `nxdomain_domains`, `zero_ip_domains`, and
    logs ignored lines to `ignored_log`.
    """
    global nxdomain_domains, zero_ip_domains, ignored_log

    name = source.get('name', 'unnamed')
    url = source.get('url', '')
    action = source.get('action', 'nxdomain')

    stats = {
        'name': name,
        'loaded': 0,
        'ignored': 0,
        'invalid': 0,
        'allow_overrides': 0,
        'in_block_nxdomain': 0,
        'in_block_zero_ip': 0,
    }

    action_set = nxdomain_domains if action == 'nxdomain' else zero_ip_domains

    print(f"  Downloading: {name} → {url}")
    content = download(url, label=name)
    if content is None:
        print(f"  [FAILED] {name} — skipping", file=sys.stderr)
        ignored_log.append(f"# SOURCE FAILED: {name} — download failed\n")
        return stats

    lines = content.splitlines()
    parse_count = 0

    for line_no, line in enumerate(lines, 1):
        # Try hosts format first
        domain = parse_hosts_line(line)
        if domain is not None:
            parse_count += 1
            if domain in allow_domains:
                stats['allow_overrides'] += 1
            else:
                action_set.add(domain)
                stats['loaded'] += 1
            continue

        # Try adblock format
        result = parse_adblock_line(line)
        if result is not None:
            domain, is_allow = result
            parse_count += 1
            if is_allow:
                allow_domains.add(domain)
                # also remove from any existing block sets
                removed = False
                for s in (nxdomain_domains, zero_ip_domains):
                    if domain in s:
                        s.discard(domain)
                        removed = True
                if removed:
                    stats['allow_overrides'] += 1
            elif domain in allow_domains:
                stats['allow_overrides'] += 1
            else:
                action_set.add(domain)
                stats['loaded'] += 1
            continue

        # Try plain domain format
        domain = parse_plain_domain(line)
        if domain is not None:
            parse_count += 1
            if domain in allow_domains:
                stats['allow_overrides'] += 1
            else:
                action_set.add(domain)
                stats['loaded'] += 1
            continue

        # Check if it's an unsupported rule (not just a comment)
        if is_unsupported_line(line):
            stats['ignored'] += 1
            truncated = line[:120] + ('...' if len(line) > 120 else '')
            ignored_log.append(f"[{name}] L{line_no}: {truncated}\n")

    print(f"    parsed={parse_count} loaded={stats['loaded']} ignored={stats['ignored']} allow_overrides={stats['allow_overrides']}")
    return stats


def format_mac(mac: str) -> str:
    """Convert 12-char hex MAC to colon-separated format (aa:bb:cc:dd:ee:ff)."""
    return ':'.join(mac[i:i+2] for i in range(0, 12, 2))


def write_file(path: str, domains: set):
    """Write sorted domain list to file atomically (tmp → rename)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = path + '.tmp'
    with open(tmp_path, 'w') as f:
        for domain in sorted(domains):
            f.write(domain + '\n')
    os.replace(tmp_path, path)


def main():
    parser = argparse.ArgumentParser(description='DNS rule builder for dnsdist')
    parser.add_argument('--config', default='rule-builder/config.yaml',
                        help='Path to config.yaml')
    parser.add_argument('--output-dir', default='dnsdist/lists',
                        help='Output directory for generated files')
    parser.add_argument('--require-network', action='store_true', default=True,
                        help='Exit without writing files if network is unavailable')
    args = parser.parse_args()

    config_path = args.config
    output_dir = args.output_dir

    # Quick network check before heavy downloads
    if args.require_network:
        try:
            urllib.request.urlopen('https://1.1.1.1', timeout=5)
        except Exception:
            print("Network unavailable — exiting without modifying files", file=sys.stderr)
            sys.exit(0)

    print(f"Rule Builder — loading config: {config_path}")
    config = parse_config(config_path)

    sources = config.get('rule_sources', [])
    allowlist_sources = config.get('allowlist_sources', [])

    enabled_sources = [s for s in sources if s.get('enabled', True)]
    enabled_allowlist = [s for s in allowlist_sources if s.get('enabled', True)]

    print(f"Sources: {len(enabled_sources)} block, {len(enabled_allowlist)} allowlist\n")

    # Global state — all sources contribute to these
    global nxdomain_domains, zero_ip_domains, ignored_log
    nxdomain_domains = set()
    zero_ip_domains = set()
    ignored_log = []

    # Phase 1: Download allowlist sources first
    allow_domains = set()
    if enabled_allowlist:
        print("[Allowlist sources]")
        for src in enabled_allowlist:
            name = src.get('name', 'unnamed')
            url = src.get('url', '')
            print(f"  Downloading: {name} → {url}")
            content = download(url, label=name)
            if content is None:
                print(f"  [FAILED] {name} — skipping", file=sys.stderr)
                ignored_log.append(f"# SOURCE FAILED: {name} (allowlist) — download failed\n")
                continue
            count = 0
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('!'):
                    continue
                # Try multiple format parsers for allowlists
                domain = None
                domain = parse_hosts_line(line) or None
                if domain is None:
                    domain = parse_plain_domain(line)
                if domain is None:
                    result = parse_adblock_line(line)
                    if result:
                        domain = result[0]
                if domain:
                    allow_domains.add(domain)
                    count += 1
            print(f"    allowlist domains: {count}")

    # Phase 2: Download and parse block sources
    all_source_stats = []
    nxdomain_contrib = {}
    zero_ip_contrib = {}

    for src in enabled_sources:
        nx_before = len(nxdomain_domains)
        zi_before = len(zero_ip_domains)
        stats = process_source(src, allow_domains)
        all_source_stats.append(stats)

        action = src.get('action', 'nxdomain')
        if action == 'nxdomain':
            stats['in_block_nxdomain'] = len(nxdomain_domains) - nx_before
        else:
            stats['in_block_zero_ip'] = len(zero_ip_domains) - zi_before

    # Post-processing: deduplicate — if same domain is in both, nxdomain wins
    overlap = nxdomain_domains & zero_ip_domains
    if overlap:
        zero_ip_domains -= overlap
        for dom in sorted(overlap):
            ignored_log.append(f"[DEDUP] {dom} in both nxdomain and zero_ip → nxdomain wins\n")

    # Write output files
    print(f"\nWriting output to {output_dir}/")
    os.makedirs(output_dir, exist_ok=True)

    write_file(os.path.join(output_dir, 'block-nxdomain.txt'), nxdomain_domains)
    print(f"  block-nxdomain.txt: {len(nxdomain_domains)} domains")

    write_file(os.path.join(output_dir, 'block-zero-ip.txt'), zero_ip_domains)
    print(f"  block-zero-ip.txt : {len(zero_ip_domains)} domains")

    write_file(os.path.join(output_dir, 'allowlist.txt'), allow_domains)
    print(f"  allowlist.txt     : {len(allow_domains)} domains")

    with open(os.path.join(output_dir, 'ignored-rules.log'), 'w') as f:
        for entry in ignored_log:
            f.write(entry)
    print(f"  ignored-rules.log : {len(ignored_log)} entries")

    # Write stats.json
    stats_data = {
        'sources': all_source_stats,
        'totals': {
            'block_nxdomain_unique': len(nxdomain_domains),
            'block_zero_ip_unique': len(zero_ip_domains),
            'allowlist_unique': len(allow_domains),
            'total_ignored': sum(s['ignored'] for s in all_source_stats),
            'overlap_resolved': len(overlap) if overlap else 0,
        },
        'generated_at': datetime.now(timezone.utc).isoformat(),
    }
    with open(os.path.join(output_dir, 'stats.json'), 'w') as f:
        json.dump(stats_data, f, indent=2, ensure_ascii=False)

    total_loaded = sum(s['loaded'] for s in all_source_stats)
    total_ignored = sum(s['ignored'] for s in all_source_stats)
    print(f"\nDone. {total_loaded} loaded, {total_ignored} ignored, "
          f"{len(allow_domains)} allowlisted.")

    # Phase 3: MAC lists
    mac_remote_url = config.get('mac_remote_url', '')
    mac_lists_dir = 'dnsdist/lists'

    if mac_remote_url:
        print(f"\n[MAC lists]")
        print(f"  Downloading remote MAC list → {mac_remote_url}")
        mac_content = download(mac_remote_url, label="mac-remote")
        if mac_content:
            remote_macs = set()
            for line in mac_content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                mac = normalize_mac(line)
                if mac:
                    remote_macs.add(mac)
            write_file(os.path.join(mac_lists_dir, 'mac-remote.txt'), remote_macs)
            print(f"    mac-remote.txt: {len(remote_macs)} MACs")
        else:
            print(f"  [FAILED] remote MAC list — skipping", file=sys.stderr)

    # Merge MAC lists: remote + local → mac-clean.txt
    all_macs = set()
    mac_remote_path = os.path.join(mac_lists_dir, 'mac-remote.txt')
    mac_local_path = os.path.join(mac_lists_dir, 'mac-local.txt')

    for path in [mac_remote_path, mac_local_path]:
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    mac = normalize_mac(line)
                    if mac:
                        all_macs.add(mac)

    if all_macs:
        write_file(os.path.join(mac_lists_dir, 'mac-clean.txt'), {format_mac(m) for m in all_macs})
        print(f"  mac-clean.txt: {len(all_macs)} MACs (merged remote + local, colon format)")

    # Phase 4: Geosite CN domains
    geosite_url = config.get('geosite_url', '')
    if geosite_url and HAS_PROTOBUF:
        print(f"\n[Geosite CN]")
        print(f"  Downloading: {geosite_url}")
        geo_data = download_binary(geosite_url, label="geosite")
        if geo_data:
            print(f"  Size: {len(geo_data)} bytes")
            cn_domains = extract_cn_domains(geo_data)
            if cn_domains:
                write_file(os.path.join(mac_lists_dir, 'cn.txt'), cn_domains)
                print(f"  cn.txt: {len(cn_domains)} domains")
            else:
                print(f"  [ERROR] No CN domains extracted", file=sys.stderr)
        else:
            print(f"  [FAILED] geosite download — skipping", file=sys.stderr)
    elif geosite_url and not HAS_PROTOBUF:
        print(f"\n[Geosite CN] Skipped — protobuf not installed", file=sys.stderr)


if __name__ == '__main__':
    main()

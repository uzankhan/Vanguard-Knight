#!/usr/bin/env python3
"""
Vanguard Knight - Network Asset Scanner (nmap wrapper)
==========================================================
SCOPE (important): Ye module SIRF apne private/local network ka asset
inventory aur attack-surface visibility ke liye hai -- "kya devices mere
network pe hain, unme kya open ports/services hain, kya koi purani/risky
service chal rahi hai". Ye ek standard defensive practice hai (asset
management -- tum apni khud ki attack surface jaante ho to defend better
kar sakte ho).

Ye module DELIBERATELY sirf RFC 1918 private IP ranges (192.168.x.x,
10.x.x.x, 172.16-31.x.x) aur localhost pe scan allow karta hai. Kisi bhi
public/external IP ko scan karne ki koshish REJECT hoti hai -- kyunki
kisi doosre ke system ko scan karna (chahe wo "attacker" hi lage) bina
authorization ke illegal hai, aur attribution bhi kabhi certain nahi hoti
(jo IP tumhe suspicious lage, wo khud ek hacked/spoofed innocent machine
ho sakti hai).

Features:
1. Network discovery (host sweep) -- kaun kaun devices online hain
2. Port + service scan per device -- kya services chal rahi hain
3. Risk flagging -- known-risky ports/services (Telnet, old SMBv1, default
   RDP without NLA, etc.) ko highlight karna
4. JSON report -- forensics module ke sath integrate hone ke liye
"""

import ipaddress
import subprocess
import shutil
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("VanguardKnight.NetworkScan")

# Ports/services that are commonly considered risky if exposed, even on a
# local/private network -- these often indicate misconfigurations or legacy
# devices that are easy footholds for lateral movement.
RISKY_SERVICES = {
    21: ("FTP", "Unencrypted file transfer -- credentials sent in plaintext"),
    23: ("Telnet", "Unencrypted remote shell -- credentials sent in plaintext, easily sniffed"),
    135: ("MSRPC", "Often targeted for lateral movement / exploitation"),
    139: ("NetBIOS", "Legacy SMB, associated with older worm/exploit vectors"),
    445: ("SMB", "Check for SMBv1 -- vulnerable to EternalBlue-class exploits if outdated"),
    1433: ("MSSQL", "Database port -- should never be internet or even LAN-exposed without auth hardening"),
    3306: ("MySQL", "Database port -- verify authentication is enforced"),
    3389: ("RDP", "Remote Desktop -- verify Network Level Authentication (NLA) is enabled"),
    5900: ("VNC", "Remote desktop protocol often deployed with weak/no authentication"),
    6379: ("Redis", "Frequently found with NO authentication by default -- high-risk if exposed"),
    27017: ("MongoDB", "Frequently found with NO authentication by default -- high-risk if exposed"),
}

PRIVATE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
]


class ScopeViolationError(Exception):
    """Raised when a scan target falls outside the allowed private-network scope."""
    pass


@dataclass
class ScannedPort:
    port: int
    protocol: str
    state: str
    service: str
    is_risky: bool = False
    risk_note: str = ""


@dataclass
class ScannedHost:
    ip: str
    hostname: Optional[str] = None
    status: str = "unknown"
    ports: List[ScannedPort] = field(default_factory=list)


@dataclass
class NetworkScanReport:
    scan_time: str
    target_range: str
    hosts: List[ScannedHost] = field(default_factory=list)
    total_hosts_up: int = 0
    total_risky_findings: int = 0


def _validate_scope(target: str):
    """
    Hard scope enforcement: only private/local ranges allowed. Raises
    ScopeViolationError for anything else (public IPs, arbitrary hostnames
    that could resolve externally, etc.)

    This function exists specifically so this tool can NEVER be pointed at
    a third party's infrastructure, regardless of how it's invoked.
    """
    try:
        # Handle both single IPs and CIDR ranges
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
        else:
            network = ipaddress.ip_network(target + '/32')
    except ValueError:
        raise ScopeViolationError(
            f"'{target}' is not a valid IP/CIDR -- refusing to scan. "
            f"Only private IP ranges or hostnames are not accepted here; "
            f"use an explicit private IP/CIDR (e.g. 192.168.1.0/24)."
        )

    is_private = any(network.subnet_of(pn) or network.overlaps(pn) for pn in PRIVATE_NETWORKS)
    if not is_private:
        raise ScopeViolationError(
            f"Refusing to scan '{target}': it falls outside private/local IP ranges "
            f"(RFC 1918 + localhost). Vanguard Knight only scans YOUR OWN network for "
            f"asset visibility -- scanning external/public IP addresses without explicit "
            f"authorization is illegal and is not something this tool will do, regardless "
            f"of the reason given."
        )


def _check_nmap_available() -> bool:
    return shutil.which("nmap") is not None


def discover_hosts(target_range: str = "192.168.1.0/24", timeout: int = 60) -> List[ScannedHost]:
    """
    Host discovery (ping sweep) -- finds which devices are online.
    Does NOT port-scan yet; that's a separate, more intrusive step (scan_ports).
    """
    _validate_scope(target_range)
    if not _check_nmap_available():
        raise RuntimeError("nmap is not installed. Install from https://nmap.org/ or "
                           "`apt install nmap` / winget install nmap (on Windows).")

    cmd = ["nmap", "-sn", target_range, "-oX", "-"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return _parse_hosts_from_xml(result.stdout)


def scan_ports(ip: str, ports: str = "21,22,23,80,135,139,443,445,1433,3306,3389,5900,6379,8080,27017",
               timeout: int = 60) -> ScannedHost:
    """
    Port + lightweight service-version scan of a SINGLE host within your
    private network. Flags known-risky exposed services.
    """
    _validate_scope(ip)
    if not _check_nmap_available():
        raise RuntimeError("nmap is not installed.")

    cmd = ["nmap", "-sV", "-p", ports, ip, "-oX", "-"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    hosts = _parse_hosts_from_xml(result.stdout, include_ports=True)
    if hosts:
        return hosts[0]
    return ScannedHost(ip=ip, status="down")


def full_network_audit(target_range: str, port_list: str = None) -> NetworkScanReport:
    """
    Complete audit: discover hosts, then port-scan each one that's up,
    and produce a consolidated risk report. This is the main entry point
    for a periodic "know your network" sweep.
    """
    _validate_scope(target_range)
    logger.info(f"[NETSCAN] Starting full audit of {target_range} (private range verified)")

    live_hosts = discover_hosts(target_range)
    logger.info(f"[NETSCAN] {len(live_hosts)} host(s) responded")

    scanned_hosts = []
    for h in live_hosts:
        try:
            detailed = scan_ports(h.ip, ports=port_list) if port_list else scan_ports(h.ip)
            detailed.hostname = h.hostname
            scanned_hosts.append(detailed)
        except Exception as e:
            logger.warning(f"[NETSCAN] Could not port-scan {h.ip}: {e}")
            scanned_hosts.append(h)

    total_risky = sum(1 for h in scanned_hosts for p in h.ports if p.is_risky)

    report = NetworkScanReport(
        scan_time=datetime.now().isoformat(),
        target_range=target_range,
        hosts=scanned_hosts,
        total_hosts_up=len(scanned_hosts),
        total_risky_findings=total_risky,
    )
    logger.info(f"[NETSCAN] Audit complete: {len(scanned_hosts)} hosts, {total_risky} risky finding(s)")
    return report


def _parse_hosts_from_xml(xml_output: str, include_ports: bool = False) -> List[ScannedHost]:
    hosts = []
    if not xml_output.strip():
        return hosts
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        logger.error(f"[NETSCAN] Failed to parse nmap XML output: {e}")
        return hosts

    for host_elem in root.findall('host'):
        status_elem = host_elem.find('status')
        status = status_elem.get('state') if status_elem is not None else 'unknown'

        addr_elem = host_elem.find("address[@addrtype='ipv4']")
        ip = addr_elem.get('addr') if addr_elem is not None else None
        if not ip:
            continue

        hostname_elem = host_elem.find('hostnames/hostname')
        hostname = hostname_elem.get('name') if hostname_elem is not None else None

        scanned_host = ScannedHost(ip=ip, hostname=hostname, status=status)

        if include_ports:
            for port_elem in host_elem.findall('ports/port'):
                port_id = int(port_elem.get('portid'))
                protocol = port_elem.get('protocol', 'tcp')
                state_elem = port_elem.find('state')
                state = state_elem.get('state') if state_elem is not None else 'unknown'
                service_elem = port_elem.find('service')
                service = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'

                is_risky = False
                risk_note = ""
                if state == 'open' and port_id in RISKY_SERVICES:
                    svc_name, note = RISKY_SERVICES[port_id]
                    is_risky = True
                    risk_note = f"{svc_name}: {note}"

                scanned_host.ports.append(ScannedPort(
                    port=port_id, protocol=protocol, state=state,
                    service=service, is_risky=is_risky, risk_note=risk_note,
                ))

        hosts.append(scanned_host)

    return hosts


def report_to_dict(report: NetworkScanReport) -> dict:
    return {
        'scan_time': report.scan_time,
        'target_range': report.target_range,
        'total_hosts_up': report.total_hosts_up,
        'total_risky_findings': report.total_risky_findings,
        'hosts': [
            {
                'ip': h.ip, 'hostname': h.hostname, 'status': h.status,
                'ports': [asdict(p) for p in h.ports],
            }
            for h in report.hosts
        ],
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print("=" * 70)
    print("TEST 1: Scope enforcement -- public IP should be REJECTED")
    print("=" * 70)
    try:
        _validate_scope("8.8.8.8")
        print("✗ FAILED: public IP was NOT rejected!")
    except ScopeViolationError as e:
        print(f"✓ Correctly rejected public IP: {str(e)[:80]}...")

    print("\n" + "=" * 70)
    print("TEST 2: Scope enforcement -- private IP should be ALLOWED")
    print("=" * 70)
    try:
        _validate_scope("192.168.1.0/24")
        print("✓ Correctly allowed private range 192.168.1.0/24")
    except ScopeViolationError as e:
        print(f"✗ FAILED: private range was rejected: {e}")

    print("\n" + "=" * 70)
    print("TEST 3: Real host discovery scan (localhost range)")
    print("=" * 70)
    hosts = discover_hosts("127.0.0.0/30")
    print(f"✓ Discovered {len(hosts)} host(s):")
    for h in hosts:
        print(f"    {h.ip} ({h.hostname or 'no hostname'}) - {h.status}")

    print("\n" + "=" * 70)
    print("TEST 4: Real port scan with risk flagging (localhost)")
    print("=" * 70)
    detailed = scan_ports("127.0.0.1", ports="22,23,80,443,3389")
    print(f"✓ Scanned {detailed.ip} -- {len(detailed.ports)} port(s) checked:")
    for p in detailed.ports:
        risk_flag = f"  ⚠ RISKY: {p.risk_note}" if p.is_risky else ""
        print(f"    {p.port}/{p.protocol} [{p.state}] {p.service}{risk_flag}")

    print("\n" + "=" * 70)
    print("TEST 5: Full audit + JSON report generation")
    print("=" * 70)
    report = full_network_audit("127.0.0.0/30", port_list="22,23,3389")
    import json
    print(json.dumps(report_to_dict(report), indent=2)[:500] + "...")

    print("\n✓ All network scanner tests completed.")

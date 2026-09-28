#!/usr/bin/env python3

import argparse
from scanner.nmap_scanner import NmapScanner
from scanner.parser import enrich_hosts
from scanner.reporter import Reporter


def print_results(hosts: list[dict]) -> None:
    print("\n" + "=" * 70)
    print("                 SENTINELSCAN RESULTS")
    print("=" * 70)

    if not hosts:
        print("No live hosts or open ports detected.")
        return

    for host in hosts:
        hostname = host["hostname"] or "-"
        print(f"\nHost: {host['ip']}")
        print(f"Hostname: {hostname}")

        if not host["ports"]:
            print("  No open ports discovered.")
            continue

        for port in host["ports"]:
            print(
                f"  {port['port']}/{port['protocol']} "
                f"{port['service'] or '-':15} "
                f"{port['severity']:8} "
                f"{port['risk_reason']}"
            )


def main():
    parser = argparse.ArgumentParser(
        description="SentinelScan - Network Scanner & Asset Enumerator"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Authorized IP, hostname, or network range"
    )

    parser.add_argument(
        "--mode",
        choices=["quick", "service"],
        default="service",
        help="quick = host discovery, service = service enumeration"
    )

    args = parser.parse_args()

    scanner = NmapScanner(args.target)
    reporter = Reporter()

    print(f"\n[*] Target: {args.target}")
    print(f"[*] Mode: {args.mode}")
    print("[*] Running Nmap...\n")

    try:
        if args.mode == "quick":
            xml_output = scanner.quick_scan()
        else:
            xml_output = scanner.service_scan()

        hosts = scanner.parse_xml(xml_output)

        if args.mode == "service":
            hosts = enrich_hosts(hosts)

        print_results(hosts)

        json_file = reporter.save_json(args.target, hosts)
        csv_file = reporter.save_csv(hosts)

        print("\n[*] Reports created:")
        print(f"    JSON: {json_file}")
        print(f"    CSV : {csv_file}")

    except Exception as exc:
        print(f"\n[ERROR] {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()

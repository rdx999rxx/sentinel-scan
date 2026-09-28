import csv
import json
from datetime import datetime
from pathlib import Path


class Reporter:

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _timestamp(self) -> str:
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def save_json(self, target: str, hosts: list[dict]) -> Path:
        filename = self.output_dir / f"scan_{self._timestamp()}.json"

        report = {
            "project": "SentinelScan",
            "target": target,
            "generated_at": datetime.now().isoformat(),
            "hosts": hosts
        }

        filename.write_text(
            json.dumps(report, indent=2),
            encoding="utf-8"
        )

        return filename

    def save_csv(self, hosts: list[dict]) -> Path:
        filename = self.output_dir / f"scan_{self._timestamp()}.csv"

        with filename.open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)

            writer.writerow([
                "IP",
                "Hostname",
                "Port",
                "Protocol",
                "Service",
                "Product",
                "Version",
                "Severity",
                "Risk Reason"
            ])

            for host in hosts:
                for port in host["ports"]:
                    writer.writerow([
                        host["ip"],
                        host["hostname"],
                        port["port"],
                        port["protocol"],
                        port["service"],
                        port["product"],
                        port["version"],
                        port["severity"],
                        port["risk_reason"]
                    ])

        return filename

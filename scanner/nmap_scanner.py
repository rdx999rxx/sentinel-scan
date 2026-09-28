import subprocess
import xml.etree.ElementTree as ET


class NmapScanner:
    """Run Nmap safely through subprocess and return XML output."""

    def __init__(self, target: str):
        self.target = target

    def _run(self, arguments: list[str]) -> str:
        command = ["nmap", *arguments, self.target]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Nmap failed:\n{result.stderr.strip()}"
            )

        return result.stdout

    def quick_scan(self) -> str:
        """Discover live hosts."""
        return self._run([
            "-sn",
            "-oX",
            "-"
        ])

    def service_scan(self) -> str:
        """Scan common ports and detect services/versions."""
        return self._run([
            "-sV",
            "--top-ports",
            "1000",
            "-T4",
            "-oX",
            "-"
        ])

    @staticmethod
    def parse_xml(xml_data: str) -> list[dict]:
        """Convert Nmap XML output into Python dictionaries."""
        root = ET.fromstring(xml_data)

        hosts = []

        for host in root.findall("host"):
            status = host.find("status")

            if status is None or status.get("state") != "up":
                continue

            address = host.find("address")
            ip = address.get("addr") if address is not None else "unknown"

            host_data = {
                "ip": ip,
                "hostname": "",
                "ports": []
            }

            hostname = host.find("./hostnames/hostname")
            if hostname is not None:
                host_data["hostname"] = hostname.get("name", "")

            for port in host.findall("./ports/port"):
                state = port.find("state")

                if state is None or state.get("state") != "open":
                    continue

                service = port.find("service")

                port_data = {
                    "port": int(port.get("portid", 0)),
                    "protocol": port.get("protocol", ""),
                    "state": state.get("state", ""),
                    "service": "",
                    "product": "",
                    "version": ""
                }

                if service is not None:
                    port_data["service"] = service.get("name", "")
                    port_data["product"] = service.get("product", "")
                    port_data["version"] = service.get("version", "")

                host_data["ports"].append(port_data)

            hosts.append(host_data)

        return hosts

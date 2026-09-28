def classify_port(port: int, service: str) -> tuple[str, str]:
    """
    Basic heuristic risk classification.
    This is not a vulnerability assessment.
    """

    critical_ports = {
        23: "Telnet",
        5900: "VNC",
    }

    high_ports = {
        21: "FTP",
        139: "NetBIOS",
        445: "SMB",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
    }

    medium_ports = {
        22: "SSH",
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        8080: "HTTP-Alt",
    }

    if port in critical_ports:
        return "CRITICAL", f"{critical_ports[port]} exposed"

    if port in high_ports:
        return "HIGH", f"{high_ports[port]} exposed"

    if port in medium_ports:
        return "MEDIUM", f"{medium_ports[port]} exposed"

    if port in {80, 443}:
        return "LOW", "Web service exposed"

    if service:
        return "LOW", f"{service} service detected"

    return "INFO", "Open port detected"


def enrich_hosts(hosts: list[dict]) -> list[dict]:
    """Add risk information to discovered ports."""

    for host in hosts:
        for port in host["ports"]:
            severity, reason = classify_port(
                port["port"],
                port["service"]
            )

            port["severity"] = severity
            port["risk_reason"] = reason

    return hosts

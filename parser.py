"""
parser.py — Nmap XML output parser.

Deterministic side of the pipeline: extracts open ports, service banners,
and NSE script output exactly as Nmap reported them. The AI interprets
these facts — it never invents them.
"""

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


@dataclass
class Service:
    port: int
    protocol: str
    state: str
    name: str
    product: str
    version: str
    scripts: dict = field(default_factory=dict)  # {"script-id": "output", ...}

    @property
    def banner(self) -> str:
        parts = [self.product, self.version]
        return " ".join(p for p in parts if p).strip() or self.name


@dataclass
class Host:
    ip: str
    hostname: str = ""
    services: list = field(default_factory=list)

    @property
    def open_services(self):
        return [s for s in self.services if s.state == "open"]

    def context_block(self) -> str:
        """
        Serialize all host data into a single text block for the AI.
        Services are presented together so the AI sees the full attack surface.
        """
        lines = [f"Target: {self.ip}" + (f" ({self.hostname})" if self.hostname else "")]
        lines.append("Open ports and Nmap findings:")
        for s in self.open_services:
            lines.append(f"- {s.port}/{s.protocol} {s.name}: {s.banner}")
            for sid, out in s.scripts.items():
                flat = " ".join(out.split())
                lines.append(f"    [NSE {sid}] {flat[:300]}")
        return "\n".join(lines)


def parse_nmap_xml(path: str) -> list[Host]:
    """Parse an Nmap XML file and return a list of Host objects."""
    tree = ET.parse(path)
    root = tree.getroot()

    hosts = []
    for host_el in root.findall("host"):
        ip = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
                break

        hostname = ""
        hn = host_el.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")

        host = Host(ip=ip, hostname=hostname)

        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            svc_el   = port_el.find("service")

            scripts = {
                scr.get("id", "?"): scr.get("output", "")
                for scr in port_el.findall("script")
            }

            host.services.append(
                Service(
                    port=int(port_el.get("portid", 0)),
                    protocol=port_el.get("protocol", "tcp"),
                    state=state_el.get("state", "") if state_el is not None else "",
                    name=svc_el.get("name", "") if svc_el is not None else "",
                    product=svc_el.get("product", "") if svc_el is not None else "",
                    version=svc_el.get("version", "") if svc_el is not None else "",
                    scripts=scripts,
                )
            )
        hosts.append(host)
    return hosts


if __name__ == "__main__":
    import sys
    src = sys.argv[1] if len(sys.argv) > 1 else "sample_scan.xml"
    for host in parse_nmap_xml(src):
        print(host.context_block())

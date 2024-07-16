import sys
import shlex
from config import logger

if sys.platform == "win32":
    shlex.split = lambda s, comments=False, posix=True: s

import nmap3
from pydantic.v1 import BaseModel, Field
from typing import Optional


class PortResult(BaseModel):
    protocol: Optional[str] = Field(description="协议")
    ip: Optional[str] = Field(description="ip")
    portid: Optional[str] = Field(description="port")
    service: Optional[str] = Field(description="服务")
    product: Optional[str] = Field(description="产品")
    version: Optional[str] = Field(description="版本")
    extrainfo: Optional[str] = Field(description="额外信息")


class Nmap:
    def __init__(self, path: str = None):
        self.nmap = nmap3.NmapScanTechniques(path=path)

    def scan_full(self, target: str) -> [PortResult]:
        args = "-p- -Pn -sV -sC -A"
        logger.debug("nmap {target} {args}", target=target, args=args)
        results = self.nmap.nmap_tcp_scan(target=target, args=args)
        results.pop("stats")
        results.pop("runtime")
        results.pop("task_results")
        ports = []
        for ip, host in results.items():
            for port in host["ports"]:
                pkv = {}
                pkv["ip"] = ip
                pkv["protocol"] = port["protocol"]
                pkv["portid"] = port["portid"]
                if "service" in port:
                    if port["service"]["name"] != "tcpwrapped":
                        pkv["service"] = port["service"]["name"]
                        if "product" in port["service"]:
                            pkv["product"] = port["service"]["product"]
                        if "version" in port["service"]:
                            pkv["version"] = port["service"]["version"]
                        if "extrainfo" in port["service"]:
                            pkv["extrainfo"] = port["service"]["extrainfo"]
                ports.append(PortResult(**pkv))

        return ports

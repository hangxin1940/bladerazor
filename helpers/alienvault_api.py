from typing import Optional, List

import requests
from pydantic.v1 import BaseModel, Field
from tld import get_tld

from config import logger


class SubDomain(BaseModel):
    apex_domain: Optional[str] = Field(description="顶级域名")
    sub_domain: Optional[str] = Field(description="子域名")
    hostname: Optional[str] = Field(description="域名")

    a: List[str] = Field(description="A记录")
    cname: List[str] = Field(description="CNAME记录")
    aaaa: List[str] = Field(description="AAAA记录")
    mx: List[str] = Field(description="MX记录")
    ns: List[str] = Field(description="NS记录")
    soa: List[str] = Field(description="SOA记录")
    txt: List[str] = Field(description="TXT记录")


class AlienVaultResult(BaseModel):
    apex_domain: Optional[str] = Field(description="顶级域名")
    sub_domains: dict[str, SubDomain] = Field(description="子域名")


class AlienVaultApi:
    def __init__(self, base_url: str = "https://otx.alienvault.com/api/v1/indicators", proxies: dict = None,
                 timeout: int = 15):
        self.base_url = base_url
        self.timeout = timeout
        self._session = requests.Session()
        if proxies:
            self._session.proxies.update(proxies)
            self._session.trust_env = False

    def _search(self, stype, value) -> List[AlienVaultResult]:
        url = f"{self.base_url}/{stype}/{value}/passive_dns"
        logger.debug("AlienVault: {upath}", upath=url)
        headers = {
            "Content-Type": "application/json"
        }
        response = self._session.request("GET", url, headers=headers, timeout=self.timeout)
        response.raise_for_status()
        res = response.json()

        domains = {}
        if "passive_dns" in res:
            for item in res["passive_dns"]:

                domain_obj = get_tld(item["hostname"], fail_silently=True, as_object=True, fix_protocol=True)
                apex_domain = domain_obj.fld
                sub_domain = domain_obj.subdomain
                val = item["address"]
                if item["record_type"] == "CNAME":
                    val = item["address"]
                elif item["record_type"] == "SOA" or item["record_type"] == "NS":
                    val = item["address"]

                if apex_domain in domains:
                    domain = domains[apex_domain]
                else:
                    domain = AlienVaultResult(
                        apex_domain=apex_domain,
                        sub_domains={}
                    )
                    domains[apex_domain] = domain

                if sub_domain in domain.sub_domains:
                    record = domain.sub_domains[sub_domain]
                else:
                    record = SubDomain(
                        apex_domain=apex_domain,
                        sub_domain=sub_domain,
                        hostname=item["hostname"],
                        a=[],
                        cname=[],
                        aaaa=[],
                        mx=[],
                        ns=[],
                        soa=[],
                        txt=[]
                    )
                    domain.sub_domains[sub_domain] = record

                if item["record_type"] == "A":
                    record.a.append(val)
                elif item["record_type"] == "AAAA":
                    record.aaaa.append(val)
                elif item["record_type"] == "SOA":
                    record.soa.append(val)
                elif item["record_type"] == "NS":
                    record.ns.append(val)
                elif item["record_type"] == "TXT":
                    record.txt.append(val)
                elif item["record_type"] == "SOA":
                    record.soa.append(val)
                elif item["record_type"] == "MX":
                    record.mx.append(val)
                elif item["record_type"] == "CNAME":
                    record.cname.append(val)

        return list(domains.values())

    def search_domain(self, domain: str) -> List[AlienVaultResult]:
        return self._search("domain", domain)

    def search_ipv4(self, ip: str) -> List[AlienVaultResult]:
        return self._search("IPv4", ip)

    def search_ipv6(self, ip: str) -> List[AlienVaultResult]:
        return self._search("IPv6", ip)

from typing import Optional, List
from tld import get_tld
import requests
from pydantic.v1 import BaseModel, Field
from helpers.utils import get_ip_type
from config import logger

keymapping = {
    "a": "ip",
    "aaaa": "ipv6",
    "mx": "hostname",
    "ns": "nameserver",
    "soa": "email",
    "txt": "value",
}


class Record(BaseModel):
    first_seen: Optional[str] = Field(description="首次发现时间")
    value: Optional[str] = Field(description="值")
    count: Optional[int] = Field(description="数量")
    organization: Optional[str] = Field(description="归属组织")


class DomainInfo(BaseModel):
    apex_domain: Optional[str] = Field(description="顶级域名")
    hostname: Optional[str] = Field(description="主机名")
    subdomain_count: Optional[int] = Field(description="子域名数量")
    a: List[Record] = Field(description="A记录")
    aaaa: List[Record] = Field(description="AAAA记录")
    mx: List[Record] = Field(description="MX记录")
    ns: List[Record] = Field(description="NS记录")
    soa: List[Record] = Field(description="SOA记录")
    txt: List[Record] = Field(description="TXT记录")


class Domain(BaseModel):
    apex_domain: Optional[str] = Field(description="顶级域名")
    hostname: Optional[str] = Field(description="域名")
    subdomain: Optional[str] = Field(description="子域名")
    ips: List[str] = Field(description="IP地址")


class History(BaseModel):
    first_seen: Optional[str] = Field(description="首次发现时间")
    last_seen: Optional[str] = Field(description="最后发现时间")
    hostname: Optional[str] = Field(description="域名")
    ip: Optional[str] = Field(description="IP地址")


class SecurityTrailsApi:
    def __init__(self, api_key: str, base_url: str = "https://api.securitytrails.com/v1", proxies: dict = None,
                 timeout: int = 10):
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self._session = requests.Session()
        if proxies:
            self._session.proxies.update(proxies)
            self._session.trust_env = False

    def _request(self, method: str, path: str, data: dict = None):
        url = f"{self.base_url}{path}"
        headers = {
            "apikey": self.api_key,
            "Content-Type": "application/json"
        }
        response = self._session.request(method, url, headers=headers, timeout=self.timeout, json=data)
        response.raise_for_status()
        return response.json()

    def _search(self, **filters) -> List[Domain]:
        records = []
        qd = {
            "filter": filters
        }
        maxpage = 100
        page = 1
        while True:
            upath = f"/domains/list?include_ips=true&page={page}"
            logger.debug("SecurityTrails: {upath} {qd}", upath=upath, qd=qd)
            res = self._request("POST", upath, qd)
            for item in res["records"]:
                domainobj = get_tld(item["hostname"], fail_silently=True, as_object=True, fix_protocol=True)
                kvs = {
                    "hostname": item["hostname"],
                    "apex_domain": domainobj.fld,
                    "subdomain": domainobj.subdomain,
                    "ips": item["ips"]
                }
                records.append(Domain(**kvs))

            if page >= maxpage or page >= res["meta"]["total_pages"]:
                break
            page += 1

        return records

    def search_domain(self, domain: str) -> List[Domain]:
        filters = {
            "apex_domain": domain,
        }
        return self._search(**filters)

    def search_domain_fuzzy(self, keyword: str) -> List[Domain]:
        filters = {
            "keyword": keyword,
        }
        return self._search(**filters)

    def search_subdomain(self, subdomain: str) -> List[Domain]:
        filters = {
            "subdomain": subdomain,
        }
        return self._search(**filters)

    def search_ip(self, ip: str) -> List[Domain]:
        iptype = get_ip_type(ip)
        filters = {
            iptype: ip,
        }
        return self._search(**filters)

    def _history(self, hostname: str, types="a") -> List[History]:
        records = []
        maxpage = 100
        page = 1
        while True:
            upath = f"/history/{hostname}/dns/{types}?page={page}"
            logger.debug("SecurityTrails: {upath}", upath=upath)
            res = self._request("GET", upath)
            for item in res["records"]:
                for ip in item["values"]:
                    kvs = {
                        "first_seen": item["first_seen"],
                        "last_seen": item["last_seen"],
                        "hostname": hostname,
                        "ip": ip["ip"]
                    }
                    records.append(History(**kvs))

            if page >= maxpage or page >= res["pages"]:
                break
            page += 1

        return records

    def get_history(self, hostname: str) -> List[History]:
        return self._history(hostname, "a")

    def get_current_domain_info(self, domain: str) -> DomainInfo:
        upath = f"/domains/{domain}"
        logger.debug("SecurityTrails: {upath}", upath=upath)
        res = self._request("GET", upath)
        data = {
            "apex_domain": res["apex_domain"],
            "hostname": res["hostname"],
            "subdomain_count": 0,
            "a": [],
            "aaaa": [],
            "mx": [],
            "ns": [],
            "soa": [],
            "txt": [],
        }

        if res["subdomain_count"] is not None:
            data["subdomain_count"] = res["subdomain_count"]

        currentdns = res["current_dns"]
        if "first_seen" in currentdns["a"]:
            for item in currentdns["a"]["values"]:
                data["a"].append(Record(
                    first_seen=currentdns["a"]["first_seen"],
                    value=item["ip"],
                    count=item["ip_count"],
                    organization=item["ip_organization"]
                ))
        if "first_seen" in currentdns["aaaa"]:
            for item in currentdns["aaaa"]["values"]:
                data["aaaa"].append(Record(
                    first_seen=currentdns["aaaa"]["first_seen"],
                    value=item["ipv6"],
                    count=item["ipv6_count"],
                    organization=item["ipv6_organization"]
                ))
        if "first_seen" in currentdns["mx"]:
            for item in currentdns["mx"]["values"]:
                data["mx"].append(Record(
                    first_seen=currentdns["mx"]["first_seen"],
                    value=item["hostname"],
                    count=item["hostname_count"],
                    organization=item["hostname_organization"]
                ))
        if "first_seen" in currentdns["ns"]:
            for item in currentdns["ns"]["values"]:
                data["ns"].append(Record(
                    first_seen=currentdns["ns"]["first_seen"],
                    value=item["nameserver"],
                    count=item["nameserver_count"],
                    organization=item["nameserver_organization"]
                ))
        if "first_seen" in currentdns["soa"]:
            for item in currentdns["soa"]["values"]:
                data["soa"].append(Record(
                    first_seen=currentdns["soa"]["first_seen"],
                    value=item["email"],
                    count=item["email_count"],
                ))
        if "first_seen" in currentdns["txt"]:
            for item in currentdns["txt"]["values"]:
                data["txt"].append(Record(
                    first_seen=currentdns["txt"]["first_seen"],
                    value=item["value"],
                ))

        return DomainInfo(**data)

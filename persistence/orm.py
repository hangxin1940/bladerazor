from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from typing import Union

from psycopg2._psycopg import AsIs
from psycopg2.extensions import register_adapter
from sqlalchemy import DateTime, func, Integer, Boolean, ARRAY, TEXT
from sqlalchemy.dialects.postgresql import JSONB, INET, CIDR
from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from helpers.crawler import Favicon
from helpers.fingers import MatchItem


def adapt_pydantic_ip_address(ip):
    return AsIs(repr(ip.exploded))


def adapt_pydantic_cidr(cidr):
    return AsIs(repr(cidr.exploded))


register_adapter(IPv4Address, adapt_pydantic_ip_address)
register_adapter(IPv6Address, adapt_pydantic_ip_address)

register_adapter(IPv4Network, adapt_pydantic_cidr)
register_adapter(IPv6Network, adapt_pydantic_cidr)


class Base(DeclarativeBase):
    pass


class Port(Base):
    __tablename__: str = "ports"

    id: Mapped[int] = mapped_column(primary_key=True)
    is_passive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, comment="是否被动探测")
    ip: Mapped[Union[IPv4Address, IPv6Address]] = mapped_column(INET(), nullable=False)
    ip_cdn: Mapped[Union[None, str]] = mapped_column(String(32), nullable=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False, comment="协议")
    service: Mapped[str] = mapped_column(String(256), nullable=True, comment="服务类型")
    product: Mapped[str] = mapped_column(String(256), nullable=True, comment="产品")
    version: Mapped[str] = mapped_column(String(256), nullable=True, comment="产品版本")
    extra_info: Mapped[dict] = mapped_column(JSONB, nullable=True, comment="其他信息")

    source: Mapped[str] = mapped_column(String(32), nullable=True, comment="来源")

    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    checked_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=None, nullable=True)

    def __repr__(self) -> str:
        return f"Port(id={self.id!r}, is_passive={self.is_passive!r}, ip={self.ip!r}, port={self.port!r}, " \
               f"protocol={self.protocol!r}, service={self.service!r}, product={self.product!r}, version={self.version!r}, " \
               f"extra_info={self.extra_info!r}, source={self.source!r}, created={self.created!r}, " \
               f"checked_time={self.checked_time!r})"


class Domain(Base):
    __tablename__: str = "domains"

    id: Mapped[int] = mapped_column(primary_key=True)
    host: Mapped[str] = mapped_column(String(512), nullable=False)
    apex_domain: Mapped[str] = mapped_column(String(512), nullable=False)
    subdomain: Mapped[str] = mapped_column(String(512), nullable=True)
    cname: Mapped[str] = mapped_column(String(512), nullable=True)
    cname_cdn: Mapped[Union[None, str]] = mapped_column(String(32), nullable=True)

    a: Mapped[[IPv4Address]] = mapped_column(ARRAY(INET()), nullable=True)
    a_cdn: Mapped[[Union[None, str]]] = mapped_column(ARRAY(String(32)), nullable=True)

    aaaa: Mapped[[IPv6Address]] = mapped_column(ARRAY(INET()), nullable=True)
    aaaa_cdn: Mapped[[Union[None, str]]] = mapped_column(ARRAY(String(32)), nullable=True)

    mx: Mapped[[str]] = mapped_column(ARRAY(String), nullable=True)
    ns: Mapped[[str]] = mapped_column(ARRAY(String), nullable=True)
    soa: Mapped[[str]] = mapped_column(ARRAY(String), nullable=True)
    txt: Mapped[[str]] = mapped_column(ARRAY(String), nullable=True)
    extra_info: Mapped[dict] = mapped_column(JSONB, nullable=True, comment="其他信息")
    source: Mapped[str] = mapped_column(String(32), nullable=True, comment="来源")

    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    checked_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=None, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=None, nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=None, nullable=True)

    def __repr__(self):
        return f"Domain(id={self.id!r}, host={self.host!r}, apex_domain={self.apex_domain!r}, subdomain={self.subdomain!r}, " \
               f"cname={self.cname!r}, cname_cdn={self.cname_cdn!r}, a={self.a!r}, a_cdn={self.a_cdn!r}, " \
               f"aaaa={self.aaaa!r}, aaaa_cdn={self.aaaa_cdn!r}, mx={self.mx!r}, ns={self.ns!r}, soa={self.soa!r}, " \
               f"txt={self.txt!r}, extra_info={self.extra_info!r}, source={self.source!r}, created={self.created!r}, " \
               f"checked_time={self.checked_time!r}, first_seen={self.first_seen!r}, last_seen={self.last_seen!r})"


class Cdn(Base):
    __tablename__: str = "cdns"

    id: Mapped[int] = mapped_column(primary_key=True)
    cname: Mapped[str] = mapped_column(String(512), nullable=True)
    cidr: Mapped[Union[IPv4Network, IPv6Network]] = mapped_column(CIDR(), nullable=True)
    organization: Mapped[str] = mapped_column(String(32), nullable=False)

    def __repr__(self):
        return f"Cdn(id={self.id!r}, cname={self.cname!r}, cidr={self.cidr!r}, organization={self.organization!r})"


class WebInfo(Base):
    __tablename__: str = "web_infos"

    id: Mapped[int] = mapped_column(primary_key=True)
    host: Mapped[str] = mapped_column(String(512), nullable=False)
    schema: Mapped[str] = mapped_column(String(16), nullable=False, comment="协议")
    url: Mapped[str] = mapped_column(String(2048), nullable=True, comment="URL地址")
    current_redirects: Mapped[int] = mapped_column(Integer, nullable=False, default=0, comment="重定向次数")
    redirect_to: Mapped[str] = mapped_column(String(2048), nullable=True, comment="重定向地址")
    ip: Mapped[Union[IPv4Address, IPv6Address]] = mapped_column(INET(), nullable=True)
    ip_cdn: Mapped[str] = mapped_column(String(32), nullable=True)
    port: Mapped[int] = mapped_column(Integer, nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=True)
    status: Mapped[int] = mapped_column(Integer, nullable=False)
    headers: Mapped[dict[str, str]] = mapped_column(JSONB, nullable=True, comment="返回头")
    favicons: Mapped[[Favicon]] = mapped_column(JSONB, nullable=True, comment="图标信息")
    body: Mapped[str] = mapped_column(TEXT, nullable=True, comment="HTML正文")
    certs: Mapped[[dict]] = mapped_column(JSONB, nullable=True, comment="证书信息")

    finger_prints: Mapped[[MatchItem]] = mapped_column(JSONB, nullable=True, comment="指纹信息")

    source: Mapped[str] = mapped_column(String(32), nullable=True, comment="来源")
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    def __repr__(self):
        return f"WebInfo(id={self.id!r}, host={self.host!r}, schema={self.schema!r}, url={self.url!r}, " \
               f"current_redirects={self.current_redirects!r}, redirect_to={self.redirect_to!r}, ip={self.ip!r}, " \
               f"port={self.port!r}, title={self.title!r}, status={self.status!r}, headers={self.headers!r}, " \
               f"favicons={self.favicons!r}, body={self.body!r}, finger_prints={self.finger_prints!r}, " \
               f"created={self.created!r}"


class Vul(Base):
    __tablename__: str = "vuls"

    id: Mapped[int] = mapped_column(primary_key=True)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    host: Mapped[str] = mapped_column(String(512), nullable=False)
    type: Mapped[str] = mapped_column(String(16), nullable=False, comment="类型")
    vul_name: Mapped[str] = mapped_column(String(256), nullable=False, comment="漏洞名称")
    vul_detail: Mapped[str] = mapped_column(TEXT, nullable=True, comment="漏洞详情")
    vul_point: Mapped[str] = mapped_column(TEXT, nullable=True, comment="漏洞利用点")
    solution: Mapped[str] = mapped_column(TEXT, nullable=True, comment="解决方案")
    cve_id: Mapped[[str]] = mapped_column(ARRAY(String), nullable=True, comment="CVE编号")
    cwe_id: Mapped[[str]] = mapped_column(ARRAY(String), nullable=True, comment="CWE编号")
    cnvd_id: Mapped[[str]] = mapped_column(ARRAY(String), nullable=True, comment="CNVD编号")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, comment="严重程度")
    description: Mapped[str] = mapped_column(TEXT, nullable=True, comment="描述")
    extra_info: Mapped[dict] = mapped_column(JSONB, nullable=True, comment="其他信息")
    source: Mapped[str] = mapped_column(String(32), nullable=True, comment="来源")
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    def __repr__(self):
        return f"Vul(id={self.id!r}, target={self.target!r}, host={self.host!r}, type={self.type!r}, " \
               f"vul_name={self.vul_name!r}, vul_detail={self.vul_detail!r}, vul_point={self.vul_point!r}, " \
               f"solution={self.solution!r}, cve_id={self.cve_id!r}, cwe_id={self.cwe_id!r}, cnvd_id={self.cnvd_id!r}, " \
               f"severity={self.severity!r}, description={self.description!r}, extra_info={self.extra_info!r}, " \
               f"source={self.source!r}, created={self.created!r}"

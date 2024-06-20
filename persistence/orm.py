from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from typing import Union

from psycopg2._psycopg import AsIs
from psycopg2.extensions import register_adapter
from sqlalchemy import DateTime, func, Integer, Boolean, ARRAY
from sqlalchemy.dialects.postgresql import JSONB, INET, CIDR
from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column


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

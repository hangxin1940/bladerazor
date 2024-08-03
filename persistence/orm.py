import hashlib
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from textwrap import dedent
from typing import Union

from psycopg2._psycopg import AsIs
from psycopg2.extensions import register_adapter
from sqlalchemy import DateTime, func, Integer, Boolean, ARRAY, TEXT, ForeignKey, event, select, and_, or_
from sqlalchemy.dialects.postgresql import JSONB, INET, CIDR
from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase, relationship, Session
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm.attributes import flag_modified

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


class DuplicateException(Exception):
    pass


class Base(DeclarativeBase):
    pass


def update_assets_associate_cdn(session, ip, cdn):
    domains = session.query(Domain).filter(Domain.a.any(ip)).all()
    for domain in domains:
        modified = False
        for index, fip in enumerate(domain.a):
            if domain.a_cdn[index] is None and fip == ip:
                domain.a_cdn[index] = cdn
                modified = True
        if modified:
            flag_modified(domain, "a_cdn")
    session.commit()

    domains = session.query(Domain).filter(Domain.aaaa.any(ip)).all()
    for domain in domains:
        modified = False
        for index, fip in enumerate(domain.aaaa):
            if domain.aaaa_cdn[index] is None and fip == ip:
                domain.aaaa_cdn[index] = cdn
                modified = True
        if modified:
            flag_modified(domain, "aaaa_cdn")
    session.commit()

    ports = session.query(Port).filter(Port.ip == ip).all()
    for port in ports:
        if port.ip_cdn is None:
            port.ip_cdn = cdn
    session.commit()

    infos = session.query(WebInfo).filter(WebInfo.ip == ip).all()
    for info in infos:
        if info.ip_cdn is None:
            info.ip_cdn = cdn
    session.commit()


class PenTestTask(Base):
    __tablename__: str = "pen_test_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)

    target: Mapped[str] = mapped_column(String(512), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(String(512), nullable=True)

    ports = relationship("Port", back_populates="task")
    domains = relationship("Domain", back_populates="task")
    web_infos = relationship("WebInfo", back_populates="task")
    vuls = relationship("Vul", back_populates="task")
    workflows = relationship("Workflow", back_populates="task")

    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Port(Base):
    __tablename__: str = "ports"

    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("pen_test_tasks.id"))
    task = relationship("PenTestTask", back_populates="ports")
    target: Mapped[str] = mapped_column(String(512), nullable=False)
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

    unique_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, comment="唯一哈希摘要")

    def generate_unique_hash(self):
        unique_str = f"{self.task_id}-{self.is_passive}-{self.ip}-{self.port}-{self.protocol}-{self.service}-"
        unique_str += f"{self.product}-{self.version}-{self.source}"
        return hashlib.sha256(unique_str.encode()).hexdigest()

    def __repr__(self) -> str:
        return f"Port(id={self.id!r}, is_passive={self.is_passive!r}, ip={self.ip!r}, port={self.port!r}, " \
               f"protocol={self.protocol!r}, service={self.service!r}, product={self.product!r}, version={self.version!r}, " \
               f"extra_info={self.extra_info!r}, source={self.source!r}, created={self.created!r}, " \
               f"checked_time={self.checked_time!r})"

    def to_prompt_template(self):
        return dedent(
            f"""
            端口: {self.port} 协议: {self.protocol} 服务类型: {self.service if self.service is not None else ""} 产品: {self.product if self.product is not None else ""} 版本: {self.version if self.version is not None else ""}
            """)

    def associate_cdn(self):
        """
        关联cdn
        """
        cdns = {}
        if self.ip_cdn is not None:
            cdns[self.ip] = self.ip_cdn
        return cdns


@event.listens_for(Port, 'before_insert')
def before_insert_port(mapper, connection, target):
    target.unique_hash = target.generate_unique_hash()

    # 检查是否有重复数据
    with Session(connection) as session:
        existing = session.execute(select(Port).where(Port.unique_hash == target.unique_hash)).scalar_one_or_none()
        if existing:
            raise DuplicateException()


class Domain(Base):
    __tablename__: str = "domains"

    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("pen_test_tasks.id"))
    task = relationship("PenTestTask", back_populates="domains")
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    host: Mapped[str] = mapped_column(String(512), nullable=False)
    host_cdn: Mapped[str] = mapped_column(String(32), nullable=True)
    apex_domain: Mapped[str] = mapped_column(String(512), nullable=False)
    subdomain: Mapped[str] = mapped_column(String(512), nullable=True)
    cname: Mapped[[str]] = mapped_column(ARRAY(String), nullable=True)
    cname_cdn: Mapped[[Union[None, str]]] = mapped_column(ARRAY(String), nullable=True)

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

    unique_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, comment="唯一哈希摘要")

    def generate_unique_hash(self):
        unique_str = f"{self.task_id}-{self.host}-{self.apex_domain}-{self.subdomain}-{self.cname}-{self.a}-"
        unique_str += f"{self.aaaa}-{self.mx}-{self.ns}-{self.soa}-{self.txt}-{self.extra_info}-{self.source}"
        return hashlib.sha256(unique_str.encode()).hexdigest()

    def __repr__(self):
        return f"Domain(id={self.id!r}, host={self.host!r}, apex_domain={self.apex_domain!r}, subdomain={self.subdomain!r}, " \
               f"cname={self.cname!r}, cname_cdn={self.cname_cdn!r}, a={self.a!r}, a_cdn={self.a_cdn!r}, " \
               f"aaaa={self.aaaa!r}, aaaa_cdn={self.aaaa_cdn!r}, mx={self.mx!r}, ns={self.ns!r}, soa={self.soa!r}, " \
               f"txt={self.txt!r}, extra_info={self.extra_info!r}, source={self.source!r}, created={self.created!r}, " \
               f"checked_time={self.checked_time!r}, first_seen={self.first_seen!r}, last_seen={self.last_seen!r})"

    def associate_cdn(self):
        """
        关联cdn
        """
        cdns = {}
        if len(self.cname_cdn) > 0 and (len(self.a) or len(self.aaaa) > 0):
            for index, fip in enumerate(self.a):
                if self.a_cdn[index] is None:
                    cdns[fip] = self.cname_cdn[0]
                else:
                    cdns[fip] = self.a_cdn[0]

            for index, fip in enumerate(self.aaaa):
                if self.aaaa_cdn[index] is None:
                    cdns[fip] = self.cname_cdn[0]
                else:
                    cdns[fip] = self.aaaa_cdn[0]

        if self.host_cdn is not None:
            for ip in self.a:
                cdns[ip] = self.host_cdn
            for ip in self.aaaa:
                cdns[ip] = self.host_cdn
        return cdns


@event.listens_for(Domain, 'before_insert')
def before_insert_domain(mapper, connection, target):
    target.unique_hash = target.generate_unique_hash()

    # 检查是否有重复数据
    with Session(connection) as session:
        existing = session.execute(select(Domain).where(Domain.unique_hash == target.unique_hash)).scalar_one_or_none()
        if existing:
            raise DuplicateException()


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
    task_id: Mapped[int] = mapped_column(ForeignKey("pen_test_tasks.id"))
    task = relationship("PenTestTask", back_populates="web_infos")
    target: Mapped[str] = mapped_column(String(512), nullable=False)
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

    unique_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, comment="唯一哈希摘要")

    def generate_unique_hash(self):
        unique_str = f"{self.task_id}-{self.host}-{self.schema}-{self.url}-"
        unique_str += f"{self.title}-{self.status}-{self.favicons}-{self.source}"
        return hashlib.sha256(unique_str.encode()).hexdigest()

    def __repr__(self):
        return f"WebInfo(id={self.id!r}, host={self.host!r}, schema={self.schema!r}, url={self.url!r}, " \
               f"current_redirects={self.current_redirects!r}, redirect_to={self.redirect_to!r}, ip={self.ip!r}, " \
               f"port={self.port!r}, title={self.title!r}, status={self.status!r}, headers={self.headers!r}, " \
               f"favicons={self.favicons!r}, body={self.body!r}, finger_prints={self.finger_prints!r}, " \
               f"created={self.created!r}"

    def to_prompt_template(self):
        fps = set()
        for fp in self.finger_prints:
            fps.add(fp['name'])

        fptxt = ", ".join(fps)

        return dedent(
            f"""
            url: {self.url}
            指纹特征: {fptxt}
            """)


@event.listens_for(WebInfo, 'before_insert')
def before_insert_web_info(mapper, connection, target):
    target.unique_hash = target.generate_unique_hash()

    # 检查是否有重复数据
    with Session(connection) as session:
        existing = session.execute(
            select(WebInfo).where(WebInfo.unique_hash == target.unique_hash)).scalar_one_or_none()
        if existing:
            raise DuplicateException()


class Vul(Base):
    __tablename__: str = "vuls"

    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("pen_test_tasks.id"))
    task = relationship("PenTestTask", back_populates="vuls")
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

    unique_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, comment="唯一哈希摘要")

    def generate_unique_hash(self):
        unique_str = f"{self.task_id}-{self.target}-{self.host}-{self.type}-{self.vul_name}-{self.vul_detail}-"
        unique_str += f"{self.vul_point}-{self.source}"
        return hashlib.sha256(unique_str.encode()).hexdigest()

    def __repr__(self):
        return f"Vul(id={self.id!r}, target={self.target!r}, host={self.host!r}, type={self.type!r}, " \
               f"vul_name={self.vul_name!r}, vul_detail={self.vul_detail!r}, vul_point={self.vul_point!r}, " \
               f"solution={self.solution!r}, cve_id={self.cve_id!r}, cwe_id={self.cwe_id!r}, cnvd_id={self.cnvd_id!r}, " \
               f"severity={self.severity!r}, description={self.description!r}, extra_info={self.extra_info!r}, " \
               f"source={self.source!r}, created={self.created!r}"

    def to_prompt_template(self):
        cve = "CVE编号: " + ", ".join(self.cve_id) if self.cve_id else ""
        cwe = "CWE编号: " + ", ".join(self.cwe_id) if self.cwe_id else ""
        cnvd = "CNVD编号: " + ", ".join(self.cnvd_id) if self.cnvd_id else ""

        tool = ""
        if self.source == "Nuclei":
            if self.extra_info and "curl" in self.extra_info:
                tool = "利用方式: `" + self.extra_info["curl"] + "`"

        return dedent(
            f"""
            利用点: `{self.vul_point}`
            说明: {self.vul_name} {self.description if self.description else ""}
            严重程度: {self.severity}
            {tool}
            {cve}
            {cwe}
            {cnvd}
            """)


@event.listens_for(Vul, 'before_insert')
def before_insert_web_info(mapper, connection, target):
    target.unique_hash = target.generate_unique_hash()

    # 检查是否有重复数据
    with Session(connection) as session:
        existing = session.execute(
            select(Vul).where(Vul.unique_hash == target.unique_hash)).scalar_one_or_none()
        if existing:
            raise DuplicateException()


class Workflow(Base):
    __tablename__: str = "workflow"

    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("pen_test_tasks.id"))
    task = relationship("PenTestTask", back_populates="workflows")

    work: Mapped[str] = mapped_column(String(32), nullable=False)

    data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[int] = mapped_column(Integer, nullable=False)

    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    edited: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(),
                                             nullable=False)


def ip_is_cdn(session, ip: str):
    ipcdn = session.query(Cdn).filter(Cdn.cidr.op('>>')(ip)).first()
    if ipcdn is not None:
        return True

    ipport = session.query(Port).filter(and_(Port.ip == ip, Port.ip_cdn != None)).first()
    if ipport is not None:
        return True

    winfos = session.query(WebInfo).filter(and_(WebInfo.ip == ip, WebInfo.ip_cdn != None)).first()
    if winfos is not None:
        return True

    ipdomains = session.query(Domain).filter(or_(Domain.a.any(ip), Domain.aaaa.any(ip))).first()
    if ipdomains is not None:
        for index, a in enumerate(ipdomains.a):
            if str(a) == ip:
                if ipdomains.a_cdn[index] is not None:
                    return True
        for index, aaaa in enumerate(ipdomains.aaaa):
            if str(aaaa) == ip:
                if ipdomains.aaaa_cdn[index] is not None:
                    return True

    return False

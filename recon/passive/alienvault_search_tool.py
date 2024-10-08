from ipaddress import ip_address
from typing import Type, Any
from pydantic.v1 import BaseModel, Field
from crewai_tools.tools.base_tool import BaseTool
from requests import HTTPError
from sqlalchemy import exc, and_, func, or_

from helpers.alienvault_api import AlienVaultApi
from helpers.utils import get_ip_type, valid_ip_address
from persistence.database import DB
from persistence.orm import Domain, Cdn, DuplicateException, update_assets_associate_cdn
from config import logger
from recon.passive.cdn_check import CdnCheck


class AlienVaultSearchToolSchema(BaseModel):
    """SecurityTrailsSearchTool 的查询参数"""
    domain: str = Field(
        None,
        description="域名。例如：`example.com`")
    ip: str = Field(None, description="IP地址。例如：`1.1.1.1`。")


class AlienVaultSearchTool(BaseTool):
    name: str = "AlienVault"
    description: str = "网络资产搜索引擎，不直接接触目标资产，对目标无副作用。支持搜索IP地址、域名的解析记录，不适用于内网ip。同一个目标在短时间内也不应当重复查询。"
    args_schema: Type[BaseModel] = AlienVaultSearchToolSchema
    db: DB | None = None
    task_id: int | None = None
    llm: Any = None
    verbose: bool = False
    cdn_autonomous_judgment: bool = False
    cdn_apexdomain_threshold: int = 1
    cdn_subdomain_threshold: int = 1

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, db: DB, task_id: int, llm=None, verbose=False, cdn_autonomous_judgment=False,
                 cdn_apexdomain_threshold=50,
                 cdn_subdomain_threshold=3):
        super().__init__()
        self.db = db
        self.task_id = task_id
        self.llm = llm
        self.verbose = verbose
        self.cdn_autonomous_judgment = cdn_autonomous_judgment
        self.cdn_apexdomain_threshold = cdn_apexdomain_threshold
        self.cdn_subdomain_threshold = cdn_subdomain_threshold

        logger.info("初始化工具 AlienVault")

    def _run(
            self,
            **kwargs: Any,
    ) -> Any:
        domain = kwargs.pop('domain', "")
        ip = kwargs.pop('ip', "")
        results = []

        avapi = AlienVaultApi()
        if domain == "" and ip == "":
            return "domain和ip不能同时为空"
        target = domain
        try:
            if domain != "":
                logger.info("AlienVault查询: {}", domain)
                results = avapi.search_domain(domain)
            else:
                if valid_ip_address(ip) is False:
                    return "IP地址格式错误"
                target = ip
                logger.info("AlienVault查询: {}", ip)
                results = avapi.search_ipv4(ip)
        except HTTPError as e:
            logger.error("AlienVault查询失败: {}", e)
            return f"查询失败: {e}"

        if len(results) == 0:
            return "未发现资产"

        if valid_ip_address(target):
            cdn_check = CdnCheck(self.db, target, llm=self.llm, verbose=self.verbose,
                                 autonomous_judgment=self.cdn_autonomous_judgment,
                                 apexdomain_threshold=self.cdn_apexdomain_threshold,
                                 subdomain_threshold=self.cdn_subdomain_threshold)
            for result in results:
                for vdomain in result.sub_domains.values():
                    cdn_check.add(result.apex_domain, vdomain.sub_domain)

            if cdn_check.check():
                with self.db.DBSession() as session:
                    update_assets_associate_cdn(session, ip, cdn_check.get_name())
                return "CDN服务器"

        try:
            cdns = {}
            with self.db.DBSession() as session:
                for result in results:
                    for vdomain in result.sub_domains.values():
                        domaindb = Domain()
                        domaindb.target = target
                        domaindb.task_id = self.task_id
                        domaindb.apex_domain = result.apex_domain
                        domaindb.host = vdomain.hostname
                        domaindb.subdomain = vdomain.sub_domain
                        domaindb.source = self.name
                        domaindb.cname = []
                        domaindb.cname_cdn = []
                        hostcdn = session.query(Cdn).filter(
                            and_(
                                Cdn.cname != None,
                                or_(
                                    func.lower(vdomain.hostname).ilike(func.concat('%', Cdn.cname)),
                                    func.lower(result.apex_domain).ilike(func.concat('%', Cdn.cname))
                                )
                            )
                        ).first()
                        if hostcdn is not None:
                            domaindb.host_cdn = hostcdn.organization

                        domaindb.a = []
                        domaindb.a_cdn = []
                        domaindb.aaaa = []
                        domaindb.aaaa_cdn = []
                        domaindb.mx = []
                        domaindb.ns = []
                        domaindb.soa = []
                        domaindb.txt = []
                        for record in vdomain.a:
                            ipobj = ip_address(record)
                            ipcdn = session.query(Cdn).filter(Cdn.cidr.op('>>')(ipobj.exploded)).first()
                            ip_type = get_ip_type(ip)
                            domaindb.a.append(ipobj)
                            if ipcdn is not None:
                                domaindb.a_cdn.append(ipcdn.organization)
                            elif domaindb.host_cdn is not None:
                                domaindb.a_cdn.append(domaindb.host_cdn)
                            else:
                                domaindb.a_cdn.append(None)

                        for record in vdomain.aaaa:
                            ipobj = ip_address(record)
                            ipcdn = session.query(Cdn).filter(Cdn.cidr.op('>>')(ipobj.exploded)).first()
                            domaindb.aaaa.append(ipobj)
                            if ipcdn is not None:
                                domaindb.aaaa_cdn.append(ipcdn.organization)
                            elif domaindb.host_cdn is not None:
                                domaindb.aaaa_cdn.append(domaindb.host_cdn)
                            else:
                                domaindb.aaaa_cdn.append(None)

                        for record in vdomain.cname:
                            domaindb.cname = record.split(',')
                            for cn in domaindb.cname:
                                cnamecdn = session.query(Cdn).filter(
                                    and_(
                                        Cdn.cname != None,
                                        func.lower(cn).ilike(func.concat('%', Cdn.cname))
                                    )
                                ).first()
                                if cnamecdn is not None:
                                    domaindb.cname_cdn.append(cnamecdn.organization)
                                else:
                                    domaindb.cname_cdn.append(None)

                        for record in vdomain.mx:
                            domaindb.mx.append(record)
                        for record in vdomain.ns:
                            domaindb.ns.append(record)
                        for record in vdomain.soa:
                            domaindb.soa.append(record)
                        for record in vdomain.txt:
                            domaindb.txt.append(record)

                        try:
                            session.add(domaindb)
                            session.commit()

                            acdns = domaindb.associate_cdn()
                            cdns.update(acdns)

                        except DuplicateException:
                            session.rollback()
                        except Exception:
                            raise
            if len(cdns) > 0:
                with self.db.DBSession() as session:
                    for ip, cdn in cdns.items():
                        update_assets_associate_cdn(session, ip, cdn)

        except exc.SQLAlchemyError as e:
            logger.error("数据库错误: {}", e)
            return "数据库错误"
        except Exception as e:
            logger.error("其他错误: {}", e)
            return f"其他错误: {e}"
        return f"共发现{len(results)}个资产"

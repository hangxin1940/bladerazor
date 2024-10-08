import os
from datetime import datetime
from ipaddress import ip_address
from typing import Type, Any
from pydantic.v1 import BaseModel, Field
from crewai_tools.tools.base_tool import BaseTool
from requests import HTTPError
from sqlalchemy import exc, and_, or_, func

from helpers.security_trails_api import SecurityTrailsApi
from helpers.utils import get_ip_type, valid_ip_address
from persistence.database import DB
from persistence.orm import Domain, Cdn, DuplicateException, update_assets_associate_cdn
from tld import get_tld
from config import logger
from recon.passive.cdn_check import CdnCheck


class SecurityTrailsSearchToolSchema(BaseModel):
    """SecurityTrailsSearchTool 的查询参数"""
    domain: str = Field(
        None,
        description="域名，用于搜索包含此关键字的域名资产，支持精确和模糊搜索。例如：`example.com`")
    ip: str = Field(None, description="IP地址，支持单一IPv4地址。例如：`1.1.1.1`。使用此参数时，不能携带其他参数。")
    history: bool = Field(
        default=False,
        description="是否查询域名解析历史，仅对domain有效，默认为False。只能与domain参数单独使用。")
    fuzzy: bool = Field(
        default=False,
        description="是否模糊搜索，用于拓展资产，但会降低准确性，默认为False。只能与domain参数单独使用。")


class SecurityTrailsSearchTool(BaseTool):
    name: str = "SecurityTrails"
    description: str = "网络资产搜索引擎，不直接接触目标资产，对目标无副作用。支持搜索IP地址、域名、子域名以及域名的解析记录，不适用于内网ip。短时间内大量查询可能会被限制。同一个目标在短时间内也不应当重复查询。"
    args_schema: Type[BaseModel] = SecurityTrailsSearchToolSchema
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
        logger.info("初始化工具 SecurityTrails")

    def _run(
            self,
            **kwargs: Any,
    ) -> Any:
        stapi = SecurityTrailsApi(os.environ.get('SECURITYTRAILS_API_KEY'))
        fuzzy = kwargs.pop('fuzzy', False)
        history = kwargs.pop('history', False)
        domain = kwargs.pop('domain', "")
        ip = kwargs.pop('ip', "")
        results = []

        if history:
            if domain == "":
                return "domain为空。history参数仅对domain有效"
            try:
                logger.info("SecurityTrails查询历史解析: {}", domain)
                results = stapi.get_history(domain)
            except HTTPError as e:
                logger.error("SecurityTrails查询失败: {}", e)
                return f"查询失败: {e}"
            try:
                cdns = {}
                with self.db.DBSession() as session:
                    for result in results:
                        hostobj = get_tld(result.hostname, fail_silently=True, as_object=True, fix_protocol=True)
                        domaindb = Domain()
                        domaindb.target = domain
                        domaindb.task_id = self.task_id
                        domaindb.apex_domain = hostobj.fld
                        domaindb.host = result.hostname
                        domaindb.subdomain = hostobj.subdomain

                        hostcdn = session.query(Cdn).filter(
                            and_(
                                Cdn.cname != None,
                                or_(
                                    func.lower(domaindb.host).ilike(func.concat('%', Cdn.cname)),
                                    func.lower(domaindb.apex_domain).ilike(func.concat('%', Cdn.cname))
                                )
                            )
                        ).first()
                        if hostcdn is not None:
                            domaindb.host_cdn = hostcdn.organization

                        domaindb.source = self.name
                        domaindb.cname = []
                        domaindb.cname_cdn = []
                        domaindb.a = []
                        domaindb.a_cdn = []
                        domaindb.aaaa = []
                        domaindb.aaaa_cdn = []
                        domaindb.mx = []
                        domaindb.ns = []
                        domaindb.soa = []
                        domaindb.txt = []

                        if result.first_seen != "":
                            domaindb.first_seen = datetime.strptime(result.first_seen, "%Y-%m-%d")
                        if result.last_seen != "":
                            domaindb.last_seen = datetime.strptime(result.last_seen, "%Y-%m-%d")

                        if result.ip != "":
                            ipobj = ip_address(result.ip)
                            ipcdn = session.query(Cdn).filter(Cdn.cidr.op('>>')(ipobj.exploded)).first()

                            ip_type = get_ip_type(result.ip)
                            if ip_type == "ipv4":
                                domaindb.a.append(ipobj)
                                if ipcdn is not None:
                                    domaindb.a_cdn.append(ipcdn.organization)
                                elif domaindb.host_cdn is not None:
                                    domaindb.a_cdn.append(domaindb.host_cdn)
                                else:
                                    domaindb.a_cdn.append(None)
                            else:
                                domaindb.aaaa.append(ipobj)
                                if ipcdn is not None:
                                    domaindb.aaaa_cdn.append(ipcdn.organization)
                                elif domaindb.host_cdn is not None:
                                    domaindb.aaaa_cdn.append(domaindb.host_cdn)
                                else:
                                    domaindb.aaaa_cdn.append(None)
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
        try:
            target = domain
            if fuzzy:
                if domain == "":
                    return "domain为空。fuzzy参数仅对domain有效"
                logger.info("SecurityTrails模糊查询: {}", domain)
                results = stapi.search_domain_fuzzy(domain)
            elif domain != "":
                logger.info("SecurityTrails查询: {}", domain)
                results = stapi.search_domain(domain)
            elif ip != "":
                if valid_ip_address(ip) is False:
                    return "IP地址格式错误"
                target = ip
                logger.info("SecurityTrails查询: {}", ip)
                results = stapi.search_ip(ip)
            else:
                return "domain和ip不能同时为空"
        except HTTPError as e:
            logger.error("SecurityTrails查询失败: {}", e)
            return f"查询失败: {e}"

        if len(results) == 0:
            return "未发现资产"

        if valid_ip_address(target):
            cdn_check = CdnCheck(self.db, target, llm=self.llm, verbose=self.verbose,
                                 autonomous_judgment=self.cdn_autonomous_judgment,
                                 apexdomain_threshold=self.cdn_apexdomain_threshold,
                                 subdomain_threshold=self.cdn_subdomain_threshold)
            for result in results:
                cdn_check.add(result.apex_domain, result.subdomain)

            if cdn_check.check():
                with self.db.DBSession() as session:
                    update_assets_associate_cdn(session, target, cdn_check.get_name())
                return "CDN服务器"

        try:
            cdns = {}
            with self.db.DBSession() as session:
                for result in results:
                    domaindb = Domain()
                    domaindb.target = target
                    domaindb.task_id = self.task_id
                    domaindb.apex_domain = result.apex_domain
                    domaindb.host = result.hostname
                    domaindb.subdomain = result.subdomain

                    hostcdn = session.query(Cdn).filter(
                        and_(
                            Cdn.cname != None,
                            or_(
                                func.lower(domaindb.host).ilike(func.concat('%', Cdn.cname)),
                                func.lower(domaindb.apex_domain).ilike(func.concat('%', Cdn.cname))
                            )
                        )
                    ).first()
                    if hostcdn is not None:
                        domaindb.host_cdn = hostcdn.organization

                    domaindb.source = self.name
                    domaindb.cname = []
                    domaindb.cname_cdn = []
                    domaindb.a = []
                    domaindb.a_cdn = []
                    domaindb.aaaa = []
                    domaindb.aaaa_cdn = []
                    domaindb.mx = []
                    domaindb.ns = []
                    domaindb.soa = []
                    domaindb.txt = []
                    for ip in result.ips:
                        ipobj = ip_address(ip)
                        ipcdn = session.query(Cdn).filter(Cdn.cidr.op('>>')(ipobj.exploded)).first()
                        ip_type = get_ip_type(ip)
                        if ip_type == "ipv4":
                            domaindb.a.append(ipobj)
                            if ipcdn is not None:
                                domaindb.a_cdn.append(ipcdn.organization)
                            elif domaindb.host_cdn is not None:
                                domaindb.a_cdn.append(domaindb.host_cdn)
                            else:
                                domaindb.a_cdn.append(None)
                        else:
                            domaindb.aaaa.append(ipobj)
                            if ipcdn is not None:
                                domaindb.aaaa_cdn.append(ipcdn.organization)
                            elif domaindb.host_cdn is not None:
                                domaindb.aaaa_cdn.append(domaindb.host_cdn)
                            else:
                                domaindb.aaaa_cdn.append(None)
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

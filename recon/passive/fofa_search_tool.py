import os
from datetime import datetime
from ipaddress import ip_address
from typing import Type, Any
from pydantic.v1 import BaseModel, Field
from crewai_tools.tools.base_tool import BaseTool
from sqlalchemy import exc, and_, func, or_

from helpers.fofa_api import FofaApi
from helpers.utils import get_ip_type, valid_ip_address
from persistence.database import DB
from persistence.orm import Port, Domain, Cdn, DuplicateException, update_assets_associate_cdn
from tld import get_tld
from config import logger
from recon.passive.cdn_check import CdnCheck


class FofaSearchToolSchema(BaseModel):
    """FofaSearchToolTool 的查询参数"""

    # 基础类
    domain: str = Field(
        None,
        description="域名，用于搜索包含此关键字的域名资产，支持精确和模糊搜索。例如：`example.com`")
    ip: str = Field(None, description="IP地址，支持单一IPv4地址、IPv4 C段和单一IPv6地址。例如：`1.1.1.1` 或 `1.1.1.1/24`")
    org: str = Field(None, description="所属组织，用于搜索包含此组织的资产。例如：`Google`")

    # 标记类
    app: str = Field(
        None,
        description="应用名称，用于搜索包含此应用的资产。小众或自研软件结果精确，通用软件如`Apache` `nginx`结果可能不精确。例如：`Apache`")

    # 网站类
    title: str = Field(None, description="网页标题，用于搜索包含此标题的资产。例如：`Google`")
    header: str = Field(
        None,
        description="响应头，用于搜索响应头包含此关键字的资产。小众或自研软件结果精确。例如：`X-Elastic-Product`")
    body: str = Field(None, description="HTML正文，用于搜索包含此关键字的资产。例如：`百度一下`")
    js_name: str = Field(None, description="HTML正文包含的JS，用于搜索包含此JS引用关键字的资产。例如：`js/jquery.js`")
    icon_hash: str = Field(None, description="网站图标的hash值，用于搜索包含此图标hash值的资产。例如：`-247388890`")
    icp: str = Field(
        None,
        description="ICP备案号，用于搜索包含此备案号的资产。中国大陆网站需ICP备案。例如：`京ICP证030173号`")

    # 证书类
    cert: str = Field(None, description="证书信息，用于搜索证书中包含此关键字的资产。例如：`Let's Encrypt`")
    fuzzy: bool = Field(
        default=False,
        description="是否模糊搜索，用于拓展资产，但会降低准确性，默认为False。只能与domain参数单独使用。")


class FofaSearchTool(BaseTool):
    name: str = "FOFA"
    description: str = "网络资产搜索引擎，不直接接触目标资产，对目标无副作用。支持搜索IP地址、域名、证书等信息，不适用于内网ip。短时间内大量查询可能会被限制。同一个目标在短时间内也不应当重复查询。"
    args_schema: Type[BaseModel] = FofaSearchToolSchema
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
        logger.info("初始化工具 FOFA")

    def _run(
            self,
            **kwargs: Any,
    ) -> Any:
        fofaapi = FofaApi(os.environ.get('FOFA_EMAIL'), os.environ.get('FOFA_API_KEY'),
                          os.environ.get('FOFA_VERSION', 'base'))
        fuzzy = kwargs.pop('fuzzy', False)
        target = ""
        if kwargs.get('domain') is not None:
            target = kwargs.get('domain')
        elif kwargs.get('ip') is not None:
            target = kwargs.get('ip')
            if valid_ip_address(target) is False:
                return "IP地址格式错误"
        results = []
        try:
            logger.info("FOFA查询: {}", kwargs)
            results = fofaapi.search(fuzzy=fuzzy, **kwargs)
        except Exception as e:
            logger.error("fofa查询失败: {}", e)
            return f"查询失败: {e}"
        if len(results) == 0:
            return "未找到任何资产"

        if valid_ip_address(target):
            cdn_check = CdnCheck(self.db, target, llm=self.llm, verbose=self.verbose,
                                 autonomous_judgment=self.cdn_autonomous_judgment,
                                 apexdomain_threshold=self.cdn_apexdomain_threshold,
                                 subdomain_threshold=self.cdn_subdomain_threshold)
            for result in results:
                if result.host is not None and result.host != "":
                    hostobj = get_tld(result.host, fail_silently=True, as_object=True, fix_protocol=True)
                    if hostobj is not None:
                        cdn_check.add(hostobj.fld, hostobj.subdomain)

            if cdn_check.check():
                with self.db.DBSession() as session:
                    update_assets_associate_cdn(session, target, cdn_check.get_name())
                return "CDN服务器"
        try:
            cdns = {}
            with self.db.DBSession() as session:
                for data in results:
                    pdb = Port()
                    pdb.target = target
                    pdb.task_id = self.task_id
                    pdb.ip = ip_address(data.ip)

                    ipcdn = session.query(Cdn).filter(Cdn.cidr.op('>>')(pdb.ip.exploded)).first()
                    if ipcdn is not None:
                        pdb.ip_cdn = ipcdn.organization

                    pdb.protocol = data.base_protocol
                    pdb.port = data.port
                    pdb.service = data.protocol
                    pdb.product = data.product
                    pdb.version = data.version.rstrip("/")
                    if data.lastupdatetime is not None and data.lastupdatetime != "":
                        pdb.checked_time = datetime.strptime(data.lastupdatetime, "%Y-%m-%d %H:%M:%S")
                    pdb.is_passive = True
                    extra_info = {}
                    domaindb = None
                    if data.host is not None and data.host != "":
                        extra_info["host"] = data.host
                        hostobj = get_tld(data.host, fail_silently=True, as_object=True, fix_protocol=True)
                        if hostobj is not None:
                            domaindb = Domain()
                            domaindb.target = target
                            domaindb.task_id = self.task_id
                            if hostobj.subdomain == "":
                                domaindb.host = hostobj.fld
                            else:
                                domaindb.host = hostobj.subdomain + "." + hostobj.fld
                            domaindb.apex_domain = hostobj.fld
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

                            if pdb.checked_time is not None:
                                domaindb.checked_time = pdb.checked_time
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
                            if get_ip_type(data.ip) == "ipv4":
                                ipobj = ip_address(data.ip)
                                domaindb.a.append(ipobj)
                                ipcdn = session.query(Cdn).filter(Cdn.cidr.op('>>')(ipobj.exploded)).first()
                                if ipcdn is not None:
                                    domaindb.a_cdn.append(ipcdn.organization)
                                elif domaindb.host_cdn is not None:
                                    domaindb.a_cdn.append(domaindb.host_cdn)
                                else:
                                    domaindb.a_cdn.append(None)
                            else:
                                ipobj = ip_address(data.ip)
                                domaindb.aaaa.append(ipobj)
                                ipcdn = session.query(Cdn).filter(Cdn.cidr.op('>>')(ipobj.exploded)).first()
                                if ipcdn is not None:
                                    domaindb.aaaa_cdn.append(ipcdn.organization)
                                elif domaindb.host_cdn is not None:
                                    domaindb.aaaa_cdn.append(domaindb.host_cdn)
                                else:
                                    domaindb.aaaa_cdn.append(None)

                    if data.as_organization is not None and data.as_organization != "":
                        extra_info["as_organization"] = data.as_organization
                    if data.cname is not None and data.cname != "":
                        cnametld = get_tld(data.cname, fail_silently=True, as_object=True, fix_protocol=True)
                        extra_info["cname"] = cnametld.parsed_url.hostname
                        if domaindb is not None:
                            domaindb.cname = cnametld.parsed_url.hostname.split(',')
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

                    if data.domain is not None and data.domain != "":
                        extra_info["domain"] = data.domain
                    if data.server is not None and data.server != "":
                        extra_info["server"] = data.server
                    if data.os is not None and data.os != "":
                        extra_info["os"] = data.os
                    if data.icp is not None and data.icp != "":
                        extra_info["icp"] = data.icp
                    if data.title is not None and data.title != "":
                        extra_info["title"] = data.title
                    if data.cert is not None and data.cert != "":
                        extra_info["cert"] = {
                            "data": data.cert,
                            "issuer_org": data.certs_issuer_org,
                            "issuer_cn": data.certs_issuer_cn,
                            "subject_org": data.certs_subject_org,
                            "subject_cn": data.certs_subject_cn,
                        }
                    pdb.extra_info = extra_info
                    pdb.source = self.name
                    try:
                        session.add(pdb)
                        session.commit()

                        acdns = pdb.associate_cdn()
                        cdns.update(acdns)
                    except DuplicateException as e:
                        session.rollback()
                    except Exception as e:
                        raise

                    if domaindb is not None:
                        try:
                            session.add(domaindb)
                            session.commit()

                            acdns = domaindb.associate_cdn()
                            cdns.update(acdns)

                        except DuplicateException as e:
                            session.rollback()
                        except Exception as e:
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

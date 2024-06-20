import os
from datetime import datetime
from ipaddress import ip_address
from typing import Type, Any
from pydantic.v1 import BaseModel, Field
from crewai_tools.tools.base_tool import BaseTool
from sqlalchemy import exc

from helpers.fofa_api import FofaApi
from helpers.utils import get_ip_type
from persistence.database import DB
from persistence.orm import Port, Domain, Cdn
from tld import get_tld
from config import logger


class FofaSearchToolSchema(BaseModel):
    """FofaSearchToolTool 的查询参数"""

    # 基础类
    domain: str = Field(
        description="域名，用于搜索包含此关键字的域名资产，支持精确和模糊搜索。例如：`example.com`")
    ip: str = Field(description="IP地址，支持单一IPv4地址、IPv4 C段和单一IPv6地址。例如：`1.1.1.1` 或 `1.1.1.1/24`")
    org: str = Field(description="所属组织，用于搜索包含此组织的资产。例如：`Google`")

    # 标记类
    app: str = Field(
        description="应用名称，用于搜索包含此应用的资产。小众或自研软件结果精确，通用软件如`Apache` `nginx`结果可能不精确。例如：`Apache`")

    # 网站类
    title: str = Field(description="网页标题，用于搜索包含此标题的资产。例如：`Google`")
    header: str = Field(
        description="响应头，用于搜索响应头包含此关键字的资产。小众或自研软件结果精确。例如：`X-Elastic-Product`")
    body: str = Field(description="HTML正文，用于搜索包含此关键字的资产。例如：`百度一下`")
    js_name: str = Field(description="HTML正文包含的JS，用于搜索包含此JS引用关键字的资产。例如：`js/jquery.js`")
    icon_hash: str = Field(description="网站图标的hash值，用于搜索包含此图标hash值的资产。例如：`-247388890`")
    icp: str = Field(
        description="ICP备案号，用于搜索包含此备案号的资产。中国大陆网站需ICP备案。例如：`京ICP证030173号`")

    # 证书类
    cert: str = Field(description="证书信息，用于搜索证书中包含此关键字的资产。例如：`Let's Encrypt`")
    fuzzy: bool = Field(
        description="是否模糊搜索，用于拓展资产，但会降低准确性，默认为False。只能与domain参数单独使用。", default=False)


class FofaSearchTool(BaseTool):
    name: str = "FOFA"
    description: str = "网络资产搜索引擎，不直接接触目标资产，对目标无副作用。支持搜索IP地址、域名、证书等信息，不适用于内网ip。短时间内大量查询可能会被限制。同一个目标在短时间内也不应当重复查询。"
    args_schema: Type[BaseModel] = FofaSearchToolSchema
    db: DB | None = None

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, db: DB):
        super().__init__()
        self.db = db

    def _run(
            self,
            **kwargs: Any,
    ) -> Any:
        fofaapi = FofaApi(os.environ.get('FOFA_EMAIL'), os.environ.get('FOFA_API_KEY'),
                          os.environ.get('FOFA_VERSION', 'base'))
        fuzzy = kwargs.pop('fuzzy', False)
        results = []
        try:
            logger.info("FOFA查询: {}", kwargs)
            results = fofaapi.search(fuzzy=fuzzy, **kwargs)
        except Exception as e:
            logger.error("fofa查询失败: {}", e)
            return f"查询失败: {e}"
        if len(results) == 0:
            return "未找到任何资产"
        try:
            with self.db.DBSession() as session:
                for data in results:
                    pdb = Port()
                    pdb.ip = ip_address(data.ip)

                    ipcdn = session.query(Cdn).filter(Cdn.cidr.op('>>')(pdb.ip.exploded)).first()
                    if ipcdn is not None:
                        pdb.ip_cdn = ipcdn.organization

                    pdb.protocol = data.base_protocol
                    pdb.port = data.port
                    pdb.service = data.protocol
                    pdb.product = data.product
                    pdb.version = data.version
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
                            if hostobj.subdomain == "":
                                domaindb.host = hostobj.fld
                            else:
                                domaindb.host = hostobj.subdomain + "." + hostobj.fld
                            domaindb.apex_domain = hostobj.fld
                            domaindb.subdomain = hostobj.subdomain
                            if pdb.checked_time is not None:
                                domaindb.checked_time = pdb.checked_time
                            domaindb.source = "fofa"
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
                                else:
                                    domaindb.a_cdn.append(None)
                            else:
                                ipobj = ip_address(data.ip)
                                domaindb.aaaa.append(ipobj)
                                ipcdn = session.query(Cdn).filter(Cdn.cidr.op('>>')(ipobj.exploded)).first()
                                if ipcdn is not None:
                                    domaindb.aaaa_cdn.append(ipcdn.organization)
                                else:
                                    domaindb.aaaa_cdn.append(None)

                    if data.as_organization is not None and data.as_organization != "":
                        extra_info["as_organization"] = data.as_organization
                    if data.cname is not None and data.cname != "":
                        cnametld = get_tld(data.cname, fail_silently=True, as_object=True, fix_protocol=True)
                        extra_info["cname"] = cnametld.parsed_url.hostname
                        if domaindb is not None:
                            domaindb.cname = cnametld.parsed_url.hostname
                            cnamecdn = session.query(Cdn).filter(Cdn.cname == domaindb.cname).first()
                            if cnamecdn is not None:
                                domaindb.cname_cdn = cnamecdn.organization

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
                    pdb.source = "fofa"
                    session.add(pdb)
                    if domaindb is not None:
                        session.add(domaindb)

                session.commit()
        except exc.SQLAlchemyError as e:
            logger.error("数据库错误: {}", e)
            return "数据库错误"
        except Exception as e:
            logger.error("其他错误: {}", e)
            return f"其他错误: {e}"

        return f"共发现{len(results)}个资产"

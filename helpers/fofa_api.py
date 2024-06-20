from typing import Any, Optional

from fofa.client import Client
from pydantic.v1 import BaseModel, Field
from config import logger


class FofaResult(BaseModel):
    ip: Optional[str] = Field(ver='base', description="ip地址")
    port: Optional[str] = Field(ver='base', description="port")
    protocol: Optional[str] = Field(ver='base', description="协议名")
    country: Optional[str] = Field(ver='base', description="国家代码")
    country_name: Optional[str] = Field(ver='base', description="国家名")
    region: Optional[str] = Field(ver='base', description="区域")
    city: Optional[str] = Field(ver='base', description="城市")
    as_number: Optional[str] = Field(ver='base', description="asn编号")
    as_organization: Optional[str] = Field(ver='base', description="asn组织")
    host: Optional[str] = Field(ver='base', description="完全限定域名 (FQDN)")
    domain: Optional[str] = Field(ver='base', description="域名")
    os: Optional[str] = Field(ver='base', description="操作系统")
    server: Optional[str] = Field(ver='base', description="网站server")
    icp: Optional[str] = Field(ver='base', description="icp备案号")
    title: Optional[str] = Field(ver='base', description="网站标题")
    jarm: Optional[str] = Field(ver='base', description="jarm 指纹")
    header: Optional[str] = Field(ver='base', description="网站header")
    banner: Optional[str] = Field(ver='base', description="协议 banner")
    base_protocol: Optional[str] = Field(ver='base', description="基础协议，比如tcp/udp")
    link: Optional[str] = Field(ver='base', description="资产的URL链接")
    cert: Optional[str] = Field(ver='base', description="证书")
    certs_issuer_org: Optional[str] = Field(ver='base', description="证书颁发者组织")
    certs_issuer_cn: Optional[str] = Field(ver='base', description="证书颁发者通用名称")
    certs_subject_org: Optional[str] = Field(ver='base', description="证书持有者组织")
    certs_subject_cn: Optional[str] = Field(ver='base', description="证书持有者通用名称")
    tls_ja3s: Optional[str] = Field(ver='base', description="ja3s指纹信息")
    tls_version: Optional[str] = Field(ver='base', description="tls协议版本")
    product: Optional[str] = Field(ver='pro', description="专业版本及以上")
    product_category: Optional[str] = Field(ver='pro', description="产品分类")
    version: Optional[str] = Field(ver='pro', description="产品版本号")
    lastupdatetime: Optional[str] = Field(ver='pro', description="FOFA最后更新时间")
    cname: Optional[str] = Field(ver='pro', description="域名cname")
    icon_hash: Optional[str] = Field(ver='bus', description="返回的icon_hash值")
    certs_valid: Optional[str] = Field(ver='bus', description="证书是否有效")
    version: Optional[str] = Field(ver='bus', description="产品版本号")
    cname_domain: Optional[str] = Field(ver='bus', description="cname的域名")
    body: Optional[str] = Field(ver='bus', description="网站正文内容")
    icon: Optional[str] = Field(ver='ent', description="icon 图标")
    fid: Optional[str] = Field(ver='ent', description="fid")
    structinfo: Optional[str] = Field(ver='ent', description="结构化信息 (部分协议支持、比如elastic、mongodb)")

    @classmethod
    def GetFields(cls, ver='base'):
        vers = ['base']
        if ver == 'pro':
            vers = ['base', 'pro']
        elif ver == 'bus':
            vers = ['base', 'pro', 'bus']
        elif ver == 'ent':
            vers = ['base', 'pro', 'bus', 'ent']

        fields = []
        for field in cls.__fields__.values():
            if field.field_info.extra['ver'] in vers:
                fields.append(field.name)
        return fields

    @classmethod
    def LoadFromList(cls, datas: list, fields: list) -> '[FofaResult]':
        results = []
        for data in datas:
            kv = {}
            for i, item in enumerate(data):
                kv[fields[i]] = item
            results.append(cls.parse_obj(kv))
        return results


def _assembly_query_str(fuzzy=True, **kwargs: Any) -> (str, str):
    for key, value in kwargs.items():
        if key == "domain":
            if fuzzy:
                return f"domain=\"{value}\" || host=\"{value}\" || cname=\"{value}\"  || cname_domain=\"{value}\"", value
            else:
                return f"domain=\"{value}\" || cname=\"{value}\"  || cname_domain=\"{value}\"", value
        elif key == "app":
            return f"app=\"{value}\" || product=\"{value}\"", value
        else:
            return f"{key}=\"{value}\"", value


class FofaApi:
    """
    使用FOFA API进行搜索
    """

    def __init__(self, email: str, api_key: str, version: str = 'base'):
        self.client = Client(email=email, key=api_key)
        self.client._session.trust_env = False
        self.fields = FofaResult.GetFields(version)

    def search(self, fuzzy=False, max_size=500, page_size=200, **kwargs: Any) -> [FofaResult]:
        """
        搜索
        fuzzy: bool, 是否模糊搜索
        max_size: int, 最大返回数量
        page_size: int, 每页数量
        """
        fields = ','.join(self.fields)
        query_str, val = _assembly_query_str(fuzzy=fuzzy, **kwargs)
        next = ""
        results = []
        while True:
            logger.debug("FOFA: {query_str} {next}", query_str=query_str, next=next)
            r = self.client.search_next(query_str=query_str, size=page_size, fields=fields, full=True, next=next)
            data = r['results']
            if fuzzy is False:
                for item in data:
                    if val in ' '.join(item):
                        results.append(item)
            else:
                results += data
            if len(results) >= max_size or len(data) <= 0 or r['next'] == "":
                break
            next = r['next']
        return FofaResult.LoadFromList(results, self.fields)

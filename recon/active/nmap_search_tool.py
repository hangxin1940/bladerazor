from datetime import datetime
from ipaddress import ip_address
from typing import Type, Any
from pydantic.v1 import BaseModel, Field
from crewai_tools.tools.base_tool import BaseTool
from sqlalchemy import exc

from helpers.nmap import Nmap
from persistence.database import DB
from persistence.orm import Port
from config import logger


class NmapSearchToolSchema(BaseModel):
    """NmapSearchToolSchema 的查询参数"""
    ip: str = Field(description="ip地址")


class NmapSearchTool(BaseTool):
    name: str = "Nmap"
    description: str = "使用Nmap扫描ip地址，发现开放端口和服务等信息。仅用于ip地址扫描。"
    args_schema: Type[BaseModel] = NmapSearchToolSchema
    nmap_path: str | None = None
    db: DB | None = None

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, db: DB, nmap_path: str = None):
        super().__init__()
        self.db = db
        self.nmap_path = None
        logger.info("初始化工具 Nmap")

    def _run(
            self,
            **kwargs: Any,
    ) -> Any:
        nmap = Nmap(self.nmap_path)
        ip = kwargs.pop('ip')
        now = datetime.now()
        results = []
        try:
            results = nmap.scan_full(ip)
        except Exception as e:
            logger.error("nmap扫描失败: {}", e)
            return f"扫描失败: {e}"
        if len(results) == 0:
            return "未找到任何开放端口"
        try:
            with self.db.DBSession() as session:
                for port in results:
                    pdb = Port()
                    pdb.ip = ip_address(port.ip).exploded
                    pdb.protocol = port.protocol
                    pdb.port = port.portid
                    pdb.service = port.service
                    pdb.product = port.product
                    pdb.version = port.version
                    pdb.checked_time = now
                    pdb.is_passive = False
                    pdb.extra_info = {
                        "info": port.extrainfo,
                    }
                    pdb.source = self.name
                    session.add(pdb)
                session.commit()
        except exc.SQLAlchemyError as e:
            logger.error("数据库错误: {}", e)
            return "数据库错误"
        except Exception as e:
            logger.error("其他错误: {}", e)
            return f"其他错误: {e}"

        return f"共发现{len(results)}个开放端口"

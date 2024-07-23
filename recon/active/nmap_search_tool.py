from datetime import datetime
from ipaddress import ip_address
from typing import Type, Any
from pydantic.v1 import BaseModel, Field
from crewai_tools.tools.base_tool import BaseTool
from sqlalchemy import exc

from helpers.nmap import Nmap
from persistence.database import DB
from persistence.orm import Port, DuplicateException
from config import logger


class NmapSearchToolSchema(BaseModel):
    """NmapSearchToolSchema 的查询参数"""
    ip: str = Field(..., description="ip地址")
    ports: str = Field("-", description="端口，','分割")


class NmapSearchTool(BaseTool):
    name: str = "Nmap"
    description: str = "使用Nmap扫描ip地址，发现开放端口的服务信息。扫描较慢，但结果精准。"
    args_schema: Type[BaseModel] = NmapSearchToolSchema
    nmap_path: str | None = None
    db: DB | None = None
    task_id: int | None = None

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, db: DB, task_id: int, nmap_path: str = None):
        super().__init__()
        self.db = db
        self.task_id = task_id
        self.nmap_path = nmap_path
        logger.info("初始化工具 Nmap")

    def _run(
            self,
            **kwargs: Any,
    ) -> Any:
        nmap = Nmap(self.nmap_path)
        ip = kwargs.pop('ip')
        ports = kwargs.pop('ports')

        now = datetime.now()
        results = []
        openports = []
        try:
            results = nmap.scan(ip, ports)
        except Exception as e:
            logger.error("nmap扫描失败: {}", e)
            return f"扫描失败: {e}"
        if len(results) == 0:
            return "未找到任何开放端口"
        try:
            with self.db.DBSession() as session:
                for port in results:
                    openports.append(f"{port.portid} {port.service}")
                    pdb = Port()
                    pdb.target = ip
                    pdb.task_id = self.task_id
                    pdb.ip = ip_address(port.ip).exploded
                    pdb.protocol = port.protocol
                    pdb.port = port.portid
                    pdb.service = port.service
                    pdb.product = port.product
                    pdb.version = port.version
                    pdb.checked_time = now
                    pdb.is_passive = False
                    if port.extrainfo is not None:
                        pdb.extra_info = {
                            "info": port.extrainfo,
                        }
                    pdb.source = self.name
                    try:
                        session.add(pdb)
                        session.commit()
                    except DuplicateException:
                        session.rollback()
                    except Exception:
                        raise

        except exc.SQLAlchemyError as e:
            logger.error("数据库错误: {}", e)
            return "数据库错误"
        except Exception as e:
            logger.error("其他错误: {}", e)
            return f"其他错误: {e}"

        return f"IP: {ip} 共发现{len(openports)}个开放端口\n{','.join(openports)}"

from datetime import datetime
from ipaddress import ip_address
from typing import Type, Any
from pydantic.v1 import BaseModel, Field
from crewai_tools.tools.base_tool import BaseTool
from sqlalchemy import exc

from helpers.masscan import Masscan
from persistence.database import DB
from persistence.orm import Port, DuplicateException
from config import logger


class MasscanSearchToolSchema(BaseModel):
    """MasscanSearchToolSchema 的查询参数"""
    ip: str = Field(..., description="ip地址")


class MasscanSearchTool(BaseTool):
    name: str = "Masscan"
    description: str = "使用Masscan扫描ip地址，扫描全端口，仅用于发现开放端口。扫描速度较快，但结果可能会不准确。"
    args_schema: Type[BaseModel] = MasscanSearchToolSchema
    masscan_path: str | None = None
    db: DB | None = None
    task_id: int | None = None

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, db: DB, task_id: int, masscan_path: str = None):
        super().__init__()
        self.db = db
        self.task_id = task_id
        self.masscan_path = masscan_path
        logger.info("初始化工具 Masscan")

    def _run(
            self,
            **kwargs: Any,
    ) -> Any:
        masscan = Masscan(self.masscan_path)
        ip = kwargs.pop('ip')
        now = datetime.now()
        results = []
        openports = []
        try:
            results = masscan.scan(hosts=ip)
        except Exception as e:
            logger.error("masscan扫描失败: {}", e)
            return f"扫描失败: {e}"
        if len(results) == 0:
            return "未找到任何开放端口"
        try:
            with self.db.DBSession() as session:
                for port in results:
                    openports.append(port.port)
                    pdb = Port()
                    pdb.target = ip
                    pdb.task_id = self.task_id
                    pdb.ip = ip_address(port.ip).exploded
                    pdb.protocol = port.proto
                    pdb.port = port.port
                    pdb.checked_time = now
                    pdb.is_passive = False
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

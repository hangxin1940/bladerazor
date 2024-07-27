from typing import Type, Any

from crewai_tools import BaseTool
from pydantic.v1 import BaseModel, Field

from rag.rag import RAG
from config import logger


class RagSearchToolSchema(BaseModel):
    """RagSearchTool 的查询参数"""
    search_query: str = Field(..., description="搜索的内容")


class RagSearchTool(BaseTool):
    name: str = "RAG知识搜索"
    description: str = "搜索本地知识库"
    args_schema: Type[BaseModel] = RagSearchToolSchema
    masscan_path: str | None = None
    rag: RAG | None = None

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, rag: RAG):
        super().__init__()
        self.rag = rag
        logger.info("初始化工具 RAG知识搜索")

    def _run(
            self,
            **kwargs: Any,
    ) -> Any:
        search_query = kwargs.pop('search_query')

        try:
            anser = self.rag.query(search_query)
            return anser
        except Exception as e:
            logger.error("知识库搜索失败: {}", e)
            return f"查询失败: {e}"

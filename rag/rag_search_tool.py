import re
from textwrap import dedent
from typing import Type, Any

from crewai import Task, Agent, Crew
from crewai_tools import BaseTool
from pydantic.v1 import BaseModel, Field

from helpers.html_information_leak_analyze import find_paths
from helpers.utils import is_domain
from rag.rag import RAG
from config import logger


class RagSearchToolSchema(BaseModel):
    """RagSearchTool 的查询参数"""
    search_query: str = Field(..., description="搜索的内容，问题应当具有代表性，使用实体关键词，避免使用自然语言")


class RagSearchTool(BaseTool):
    name: str = "RAG知识搜索"
    description: str = "搜索本地知识库。对于特定ip地址或者特定域名，不可以使用该工具。"
    args_schema: Type[BaseModel] = RagSearchToolSchema
    masscan_path: str | None = None
    rag: RAG | None = None
    verbose: bool = False
    llm: Any | None = None

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, rag: RAG, llm, verbose=False):
        super().__init__()
        self.rag = rag
        self.verbose = verbose
        self.llm = llm
        logger.info("初始化工具 RAG知识搜索")

    def _run(
            self,
            **kwargs: Any,
    ) -> Any:
        search_query = kwargs.pop('search_query')

        # TODO
        ips = re.findall(
            r'(?:\d|1?\d\d|2[0-4]\d|25[0-5])(?:\.(?:\d|1?\d\d|2[0-4]\d|25[0-5])){3}', search_query)
        if len(ips) > 0:
            return "不可以使用该工具搜索特定ip地址"

        paths = find_paths(search_query)
        if len(paths) > 0:
            return "不可以使用该工具搜索特定路径"

        if is_domain(search_query):
            return "不可以使用该工具搜索特定域名"

        try:
            answer = self.rag.query(search_query)
            out = self.review(search_query, str(answer))
            if "PASS" in out:
                return answer
            elif "FAIL" in out:
                return "查询结果不符合要求, 请重新查询"
            else:
                return out
        except Exception as e:
            logger.error("知识库搜索失败: {}", e)
            return f"查询失败: {e}"

    def review(self, query: str, answer: str) -> str:
        agent = Agent(
            role='搜索结果审核专家',
            goal='确保RAG工具的搜索输出与查询意图完全一致，优化搜索效率和结果的相关性。',
            backstory=dedent(
                """
                你是一名专注于搜索技术和结果验证的专家，隶属于技术保障团队。
                你的任务是对RAG等智能搜索工具的输出进行精确的审核，确保每个搜索结果都严格符合预设的查询意图和技术需求。

                你具备深厚的技术背景，特别擅长：
                - 分析和解析复杂的搜索结果。
                - 识别与查询意图不符的搜索输出。
                - 使用逻辑和技术知识来评估搜索结果的技术相关性。
                - 提出实用的改进建议，帮助改进搜索工具的算法和查询策略。

                你的目标是通过严格的审核流程，提升搜索工具的准确性和效率，从而支持团队的技术决策和安全操作。
                """
            ),
            verbose=self.verbose,
            llm=self.llm,
            allow_delegation=True,
            max_rpm=300,
            cache=False,
        )

        task = Task(
            agent=agent,
            description=dedent(
                f"""                  
                审核RAG搜索工具输出的结果，确保搜索结果与查询意图保持一致性。
                在进行技术栈、漏洞和配置信息的搜索时，需要特别注意结果的相关性。

                审核流程如下：
                1. 确认每一项搜索结果是否直接相关于查询的技术栈或问题。例如，如果搜索关键词为Java相关技术，结果应严格限于Java环境，不应包含如.NET或其他无关技术的信息。
                2. 分析搜索结果中的误报，标识出那些明显不符合查询条件的内容。
                3. 提出改进搜索策略的建议，如调整关键词、使用更精确的查询语句等，以减少未来的误报。

                这个任务的目的是提高搜索效率和准确性，确保团队能够获得最相关和可行的信息。
                
                请根据以下搜索结果，回答是否通过审核：
                查询内容：
                {query}
                
                ------------------------
                
                搜索结果：
                {answer}
                """),
            expected_output=dedent(
                """
                最终答案应为以下三种类型之一，不要编造其他内容：
                
                如果审核通过：
                    只需要回答字符串`PASS`
                如果不通过，但是存在合理回答：
                    移除不合理的回答，然后提供合理的回答
                如果不通过，且没有合理回答：
                    只需要回答字符串`FAIL`
                """),
        )

        return Crew(
            agents=[agent],
            tasks=[task],
            verbose=self.verbose,
            share_crew=False,
            cache=True
        ).kickoff()

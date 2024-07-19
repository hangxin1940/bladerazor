import os
from ipaddress import ip_address

from crewai import Agent, Task, Crew
from crewai_tools import BaseTool
from textwrap import dedent

from persistence.database import DB
from recon.active.masscan_search_tool import MasscanSearchTool
from recon.active.nmap_search_tool import NmapSearchTool
from recon.passive.fofa_search_tool import FofaSearchTool
from recon.passive.security_trails_search_tool import SecurityTrailsSearchTool
import validators
from config import logger


class CyberAssetsResearchers:
    """
    网络资产研究员
    主要用于网络资产的被动侦察和主动扫描，以扩大攻击面
    """

    def __init__(self, db: DB, llm=None, masscan_path=None, nmap_path=None, verbose: bool = False):
        self.llm = llm
        self.db = db
        self.masscan_path = masscan_path
        self.nmap_path = nmap_path
        self.verbose = verbose

    def agent_cyber_asset_intelligence_scout(self, llm=None, tools: [BaseTool] = []) -> Agent:
        logger.info("初始化代理 网络资产情报侦察员")
        agent = Agent(
            role='网络资产情报侦察员',
            goal='通过被动侦察工具获取相关网络资产信息',
            backstory=dedent(
                """
                你是一名经验丰富的网络资产情报侦察员，主要任务是发现网络资产以扩大攻击面。
                你精通互联网协议和各种服务器应用程序，特别是对DNS、HTTP、HTTPS、SMTP、POP3、IMAP等协议有深入的了解。
                你擅长使用网络工具搜索目标的相关资产，专业在于识别和过滤搜索结果中与目标相关或不相关的网络资产。
                你主要使用不同的被动信息收集工具，以避免对目标产生任何影响，如避免生成访问日志等。
                你的工作至关重要，你的工作成果将直接影响后续工作的开展。
                """
            ),
            tools=tools,
            verbose=self.verbose,
            allow_delegation=True,
            max_rpm=300,
            # max_iter=1,
            llm=llm,
            cache=False,
        )
        if llm is not None:
            agent.llm = llm
        return agent

    def agent_ip_scanner(self, llm=None, tools: [BaseTool] = []) -> Agent:
        logger.info("初始化代理 IP扫描员")
        agent = Agent(
            role='IP扫描员',
            goal='使用扫描器对目标IP进行扫描以获取开放端口和服务信息',
            backstory=dedent(
                """
                你是一名经验丰富的IP扫描员。你只扫描ip地址。
                你精通互联网协议和各种服务器应用程序，特别是对DNS、HTTP、HTTPS、SMTP、POP3、IMAP等协议有深入的了解。
                你擅长使用各种扫描具对目标进行端口扫描。
                """
            ),
            tools=tools,
            verbose=self.verbose,
            allow_delegation=False,
            max_rpm=300,
            # max_iter=1,
            llm=llm,
            cache=False,
        )
        if llm is not None:
            agent.llm = llm
        return agent

    def task_cyber_assets_recon(self, agent: Agent, target: str) -> Task:
        logger.info("初始化任务 资产侦察")
        return Task(
            description=dedent(
                f"""
                使用多种网络资产搜索引擎搜索目标的相关资产信息。
                尽可能多的获取目标相关资产信息，越多资产这对于后续工作的开展越有利。
                最终结果会被存入数据库以便后续使用。对于同一个目标，每个工具最多只能调用一次。
                根据目标类型选择合适的工具进行搜索。
                需要注意以下几点:
                - 如果目标为ipv4或ipv6地址，则必须为公网地址，否则不进行扫描。
                
                目标: `{target}`
                """
            ),
            expected_output=dedent(
                """
                最终答案是本次搜索结果资产数量，具体的结果已存储在数据库中。不要编造其他额外内容。
                """),
            agent=agent,
        )

    def task_ip_scan(self, agent: Agent, target: str) -> Task:
        logger.info("初始化任务 IP扫描")
        return Task(
            description=dedent(
                f"""
                使用多种端口扫描工具，对ip进行端口扫描。
                尽可能多的获取目标开放端口和服务信息，开放端口的数量以及服务信息的准确性对后续工作的开展至关重要。
                最终结果会被存入数据库以便后续使用。
                你首先判断目标类型，根据目标类型选择合适的工具进行扫描。
                不要将辅助性工具的结果作为最终答案。
                目标: `{target}`
                """
            ),
            expected_output=dedent(
                """
                最终答案是本次搜索结果资产数量，具体的结果已存储在数据库中。不要编造其他额外内容。
                """),
            agent=agent,
        )

    def _reconIpCrew(self, task_id: int, target: str, passive: bool = True):
        ip = ip_address(target)
        if ip.is_private:
            # TODO
            raise NotImplementedError("暂不支持内网地址的扫描")

        agents = []
        tasks = []
        tools = self._getPassiveReconTools(task_id)
        if len(tools) > 0:
            agscout = self.agent_cyber_asset_intelligence_scout(self.llm, tools)
            agents.append(agscout)

            taskscout = self.task_cyber_assets_recon(agscout, ip.exploded)
            tasks.append(taskscout)
        if passive is False:
            agip = self.agent_ip_scanner(
                self.llm,
                [
                    MasscanSearchTool(self.db, task_id, self.masscan_path),
                    NmapSearchTool(self.db, task_id, self.nmap_path)
                ]
            )
            agents.append(agip)

            taskip = self.task_ip_scan(agip, ip.exploded)
            tasks.append(taskip)

        if len(agents) == 0:
            raise Exception("无可用工具")

        logger.info("初始化智能体 IP侦察")
        return Crew(
            agents=agents,
            tasks=tasks,
            verbose=self.verbose,
        )

    def _getPassiveReconTools(self, task_id: int) -> []:
        tools = []
        if os.environ.get('FOFA_EMAIL') is not None and os.environ.get('FOFA_API_KEY') is not None:
            tools.append(FofaSearchTool(self.db, task_id))
        if os.environ.get('SECURITYTRAILS_API_KEY') is not None:
            tools.append(SecurityTrailsSearchTool(self.db, task_id))
        return tools

    def _reconDomainCrew(self, task_id: int, target: str):
        agents = []
        tasks = []

        tools = self._getPassiveReconTools(task_id)
        if len(tools) > 0:
            agscout = self.agent_cyber_asset_intelligence_scout(self.llm, tools)
            agents.append(agscout)
            taskscout = self.task_cyber_assets_recon(agscout, target)
            tasks.append(taskscout)

        if len(agents) == 0:
            raise Exception("无可用工具")

        logger.info("初始化智能体 域名侦察")
        return Crew(
            agents=agents,
            tasks=tasks,
            verbose=self.verbose,
        )

    def reconCrew(self, task_id: int, target: str, passive: bool = False):

        try:
            # ip地址
            ipobj = ip_address(target)
            logger.info("IP目标 {}", target)
            return self._reconIpCrew(task_id, target, passive)
        except ValueError:
            pass

        if validators.url(target):
            # url
            logger.info("url目标 {}", target)
            return self._reconDomainCrew(task_id, target)
        elif validators.domain(target):
            # domain
            logger.info("domain目标 {}", target)
            return self._reconDomainCrew(task_id, target)
        raise ValueError("目标类型不支持")

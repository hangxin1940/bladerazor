from textwrap import dedent

from crewai import Agent, Task, Crew


class CdnCheck:

    def __init__(self, db, ip, llm=None, verbose=False, autonomous_judgment=True, apexdomain_threshold=50,
                 subdomain_threshold=3):
        """
        :param db:
        :param ip:
        :param llm:
        :param verbose:
        :param autonomous_judgment: 是否自主判断，开启时，不考虑数量阈值
        :param apexdomain_threshold: 主域名数量阈值
        :param subdomain_threshold: 子域名数量阈值
        """
        self.llm = llm
        self.db = db
        self.verbose = verbose
        self.ip = ip
        self.apexdomain_threshold = apexdomain_threshold
        self.subdomain_threshold = subdomain_threshold
        self.domains = {}
        self.autonomous_judgment = autonomous_judgment

    def get_name(self):
        return f"CdnCheck: 自主判断: {self.autonomous_judgment}, 主域名数量阈值: {self.apexdomain_threshold}, 子域名数量阈值: {self.subdomain_threshold}"

    def add(self, apex_domain: str, sub_domain: str):
        """
        添加域名信息
        """
        if apex_domain not in self.domains:
            self.domains[apex_domain] = set()
        self.domains[apex_domain].add(sub_domain)

    def get_statistics(self) -> str:
        apex_domains = len(self.domains)
        st = f"域名总数: {apex_domains}\n域名列表:\n"
        for apex_domain, sub_domains in self.domains.items():
            st += f" {apex_domain}: {len(sub_domains)}\n"
        return st

    def check(self) -> bool:

        agent = Agent(
            role='CDN服务器甄别人员',
            goal='通过ip反查出的域名，判断ip是否为CDN服务器',
            backstory=dedent(
                """
                你是一名经验丰富的网络安全专家，专门从事CDN服务提供商的研究和分析。
                你的任务是通过分析关联域名的信息，判断给定的IP地址是否为CDN前置。
                你将利用你丰富的知识和经验，综合关联域名的数量、多样性、结构和模式等因素，做出准确的判断。
                """
            ),
            verbose=self.verbose,
            allow_delegation=False,
            max_rpm=300,
            # max_iter=1,
            llm=self.llm,
            cache=False,
        )

        threshold = ''
        if self.autonomous_judgment is False:
            threshold = f"\n我们可以简单的认为，当主域名数量超过{self.apexdomain_threshold}个，或者存在多个拥有超过{self.subdomain_threshold}个子域名的主域名时，此IP为CDN前置。"

        task = Task(
            description=dedent(
                f"""
                       分析给定的IP地址及其关联域名的统计，判断该IP地址是否为CDN前置。具体分析包括以下几个方面：
                       - 关联域名的数量和多样性。
                       - 域名的结构和模式。
                       - 主域名的特点。
                       {threshold}

                       以下数据为 ip `{self.ip}` 反查出的主域名总数，主域名列表，以及每个域名对应的子域名数量：
                       {self.get_statistics()}
                       """
            ),
            expected_output=dedent(
                """
                最终答案是一个明确的判断，该IP地址是否为CDN前置，输出为描述是与否的特定字符`Y`或`N`。
                不要编造其他额外内容。
                """),
            agent=agent,
        )

        crew = Crew(
            agents=[agent],
            tasks=[task],
            verbose=self.verbose,
            share_crew=False
        )

        out = crew.kickoff()
        return "Y" in out

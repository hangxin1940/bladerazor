from typing import Optional

from exploits.attack_surface_research import AttackSurfaceResearch
from exploits.deploy_attack import DeployAttack
from exploits.vul_scan_expert import VulScanExpert
from persistence.database import DB
from rag.rag import RAG
from recon.cyber_assets_researcher import CyberAssetsResearchers


class Team:
    """团队"""

    cyberAssetsResearchers: CyberAssetsResearchers | None = None
    vulScanExpert: VulScanExpert | None = None
    attackSurfaceResearch: AttackSurfaceResearch | None = None
    deployAttack: DeployAttack | None = None

    def __init__(self,
                 db: DB,
                 rag: RAG,
                 llm,
                 debug: Optional[bool] = None,
                 masscan_path: Optional[str] = None,
                 nmap_path: Optional[str] = None,
                 gobuster_path: str = None,
                 gobuster_wordlist_path: str = None,
                 nuclei_path: Optional[str] = None,
                 nuclei_templates_path: Optional[str] = None):
        self.cyberAssetsResearchers = CyberAssetsResearchers(
            db=db,
            llm=llm,
            masscan_path=masscan_path,
            nmap_path=nmap_path,
            verbose=debug
        )

        self.vulScanExpert = VulScanExpert(
            db=db,
            llm=llm,
            gobuster_path=gobuster_path,
            gobuster_wordlist_path=gobuster_wordlist_path,
            nuclei_path=nuclei_path,
            nuclei_templates_path=nuclei_templates_path,
            verbose=debug
        )

        self.attackSurfaceResearch = AttackSurfaceResearch(
            db=db,
            rag=rag,
            llm=llm,
            verbose=debug
        )

        self.deployAttack = DeployAttack(
            db=db,
            rag=rag,
            llm=llm,
            verbose=debug
        )

    def get_recon_crew(self, task_id: int, target: str):
        """
        获取侦察队伍
        """
        return self.cyberAssetsResearchers.reconCrew(task_id, target)

    def get_mapping_crew(self, task_id: int, target: str):
        """
        获取测绘队伍
        """
        return self.vulScanExpert.fingerprintingCrew(task_id, target)

    def get_vulscan_crew(self, task_id: int, target: str):
        """
        获取漏扫队伍
        """
        return self.vulScanExpert.vulScanCrew(task_id, target)

    def get_intelligence_analysis_crew(self, target: str):
        """
        获取情报分析队伍
        """
        return self.attackSurfaceResearch.intelligenceAnalysisCrew(target)

    def get_establishing_foothold_research_crew(self, target: str, intelligence: str):
        """
        获取攻击面研究队伍
        """
        return self.attackSurfaceResearch.establishingFootholdResearchCrew(target, intelligence)

    def get_attack_plan_review_crew(self, assets: str, intelligence: str, plan: str, review: str | None = None):
        """
        获取攻击计划审核队伍
        """
        return self.attackSurfaceResearch.attackPlanReviewCrew(assets, intelligence, plan, review)

    def get_establishing_foothold_deploy_attack_crew(self, asset: str, plan: str):
        """
        获取攻击队伍
        """
        return self.deployAttack.establishingFootholdAttackCrew(asset, plan)

from typing import Optional

from exploits.cybersecurity_expert import CybersecurityExperts
from persistence.database import DB
from recon.cyber_assets_researcher import CyberAssetsResearchers


class Team:
    """团队"""

    cyberAssetsResearchers: CyberAssetsResearchers | None = None
    cyberAssetsExperts: CybersecurityExperts | None = None

    def __init__(self,
                 db: DB,
                 llm,
                 debug: Optional[bool] = None,
                 masscan_path: Optional[str] = None,
                 nmap_path: Optional[str] = None,
                 nuclei_path: Optional[str] = None,
                 nuclei_templates_path: Optional[str] = None):
        self.cyberAssetsResearchers = CyberAssetsResearchers(
            db=db,
            llm=llm,
            masscan_path=masscan_path,
            nmap_path=nmap_path,
            verbose=debug
        )

        self.cyberAssetsExperts = CybersecurityExperts(
            db=db,
            llm=llm,
            nuclei_path=nuclei_path,
            templates_path=nuclei_templates_path,
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
        return self.cyberAssetsExperts.fingerprintingCrew(task_id, target)

    def get_exploit_crew(self, task_id: int, target: str):
        """
        获取打点队伍
        """
        return self.cyberAssetsExperts.vulScanCrew(task_id, target)

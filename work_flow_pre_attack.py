from enum import IntEnum
from urllib.parse import urlparse

import validators
from langgraph.graph import StateGraph
from typing import TypedDict, Optional, Any

from langgraph.graph.graph import CompiledGraph
from sqlalchemy import and_, func
from tld import get_tld

from helpers.utils import is_domain
from persistence.database import DB
from persistence.orm import Domain, Port, WebInfo
from team import Team
from config import logger


class StatePreAttack(IntEnum):
    INIT = 0  # 初始化
    RECON = 1  # 侦察
    MAPPING = 2  # 测绘
    VULSCAN = 3  # 漏扫
    FINISH = 99  # 结束


class Target:
    def __init__(self, task_id: int, target: str, db: DB | None = None, orm_id=0, orm_class: Any = None):
        self.db = db
        self.orm_id = orm_id
        self.orm_class = orm_class
        self.task_id = task_id
        self.target = target
        self.status = StatePreAttack.INIT

    def __repr__(self):
        return f'{self.status} {self.task_id}: {self.target}'

    def __eq__(self, other):
        return self.task_id == other.task_id and self.target == other.target

    def __hash__(self):
        return hash((self.task_id, self.target))

    def next_status(self):
        if self.status == StatePreAttack.INIT:
            self.status = StatePreAttack.RECON
        elif self.status == StatePreAttack.RECON:
            self.status = StatePreAttack.MAPPING
        elif self.status == StatePreAttack.MAPPING:
            self.status = StatePreAttack.VULSCAN
        elif self.status == StatePreAttack.VULSCAN:
            self.status = StatePreAttack.FINISH

        if self.db is not None and self.orm_id > 0 and self.orm_class is not None:
            with self.db.DBSession() as session:
                orm = session.query(self.orm_class).get(self.orm_id)
                orm.task_state = self.status
                session.commit()


class TaskStatePreAttack(TypedDict):
    task_id: int
    targets: set[Target]


class TaskNodesPreAttack:
    team: Team | None = None
    db: DB | None = None

    def __init__(self, db: DB, team: Team):
        self.db = db
        self.team = team

    def init_task(self, state: TaskStatePreAttack):
        """
        初始化任务
        """
        for target in state['targets']:
            target.next_status()
        return state

    def recon(self, state: TaskStatePreAttack):
        """
        侦察目标
        """
        for target in state['targets']:
            taskid = target.task_id
            if target.status == StatePreAttack.INIT:
                target.next_status()
            if target.status == StatePreAttack.RECON:
                try:
                    crew = self.team.cyberAssetsResearchers.reconCrew(target.task_id, target.target)
                    out = crew.kickoff()
                    logger.info("[recon {}] {}: {}", target.task_id, target, out)
                except Exception as e:
                    logger.error("[recon {}] {}: {}", target.task_id, target, e)
                target.next_status()

        self._padding_new_assets(state["task_id"], state)
        return state

    def mapping(self, state: TaskStatePreAttack):
        """
        测绘
        """
        for target in state['targets']:
            taskid = target.task_id
            if target.status == StatePreAttack.MAPPING:
                try:
                    crew = self.team.vulScanExpert.fingerprintingCrew(target.task_id, target.target)
                    out = crew.kickoff()
                    logger.info("[mapping {}] {}: {}", target.task_id, target, out)
                except ValueError as e:
                    logger.debug("[mapping {}] {}: {}", target.task_id, target, e)
                except Exception as e:
                    logger.error("[mapping {}] {}: {}", target.task_id, target, e)
                target.next_status()
        self._padding_new_assets(state["task_id"], state)
        return state

    def port_scan(self, state: TaskStatePreAttack):
        """
        端口扫描
        """
        # 获取所有ip资源
        allips = set()
        with self.db.DBSession() as session:
            domains = session.query(Domain).filter(
                and_(
                    Domain.task_id == state["task_id"],
                )
            ).all()
            for domain in domains:
                if len(domain.a) > 0:
                    for idx, a in enumerate(domain.a):
                        if domain.a_cdn[idx] is None:
                            allips.add(a)

            ports = session.query(Port).filter(
                and_(
                    Port.task_id == state["task_id"],
                    Port.ip_cdn == None
                )
            ).all()
            for port in ports:
                allips.add(port.ip)

            webinfos = session.query(WebInfo).filter(
                and_(
                    WebInfo.task_id == state["task_id"],
                    WebInfo.ip != None,
                    WebInfo.ip_cdn == None
                )
            ).all()
            for webinfo in webinfos:
                allips.add(webinfo.ip)

        for ip in allips:
            try:
                self.team.cyberAssetsResearchers.portScanCrew(state["task_id"], ip)
            except Exception as e:
                logger.error("[port_scan {}] {}: {}", state["task_id"], ip, e)

        return state

    def vulscan(self, state: TaskStatePreAttack):
        """
        漏扫
        """
        for target in state['targets']:
            if target.status == StatePreAttack.VULSCAN:
                try:
                    crew = self.team.vulScanExpert.vulScanCrew(target.task_id, target.target)
                    out = crew.kickoff()
                    logger.info("[vulscan {}] {}: {}", target.task_id, target, out)
                except ValueError as e:
                    logger.debug("[vulscan {}] {}: {}", target.task_id, target, e)
                except Exception as e:
                    logger.error("[vulscan {}] {}: {}", target.task_id, target, e)
            target.next_status()
        return state

    def exploit(self, state: TaskStatePreAttack):
        """
        漏洞利用
        """
        datas = self._assets_intelligence(state['task_id'])
        for target, data in datas.items():
            try:
                datastr = f"目标: {target}\n{'\n\n---------------\n\n'.join(data)}"
                # TODO
                crew = self.team.get_establishing_foothold_research_crew(datastr)
                out = crew.kickoff()
                logger.info("[exploit {}]\n{}", state['task_id'], out)
            except ValueError as e:
                logger.debug("[exploit {}]\n{}", state['task_id'], e)
            except Exception as e:
                logger.error("[exploit {}]\n{}", state['task_id'], e)
        return state

    def finish(self, state: TaskStatePreAttack):
        """
        结束任务
        """
        # TODO
        for target in state['targets']:
            print('finish', target)
        return state

    def edge_shuld_recon(self, state: TaskStatePreAttack):
        """
        条件边
        """

        for target in state['targets']:
            if target.status == StatePreAttack.RECON or target.status == StatePreAttack.INIT:
                return 'recon'
        return 'pass'

    def _padding_new_assets(self, task_id: int, state: TaskStatePreAttack):
        """
        获取新资产以进一步侦察
        """
        with self.db.DBSession() as session:
            domains = session.query(Domain).filter(
                and_(
                    Domain.task_id == task_id,
                    Domain.task_state.in_((StatePreAttack.INIT, StatePreAttack.RECON))
                )
            ).all()
            for domain in domains:
                if domain.host_cdn is None:
                    target = Target(task_id, domain.host, self.db, domain.id, Domain)
                    state['targets'].add(target)
                if len(domain.a) > 0:
                    for idx, a in enumerate(domain.a):
                        if domain.a_cdn[idx] is None:
                            target = Target(task_id, a)
                            state['targets'].add(target)
                if domain.cname is not None:
                    for idx, cname in enumerate(domain.cname):
                        if domain.cname_cdn[idx] is None:
                            target = Target(task_id, cname)
                            state['targets'].add(target)

            ports = session.query(Port).filter(
                and_(
                    Port.task_id == task_id,
                    Port.task_state == StatePreAttack.INIT,
                    Port.ip_cdn == None
                )
            ).all()
            for port in ports:
                target = Target(task_id, port.ip)
                state['targets'].add(target)
                if port.service is not None and port.service.startswith('http'):
                    target = Target(task_id, f'{port.service}://{port.ip}:{port.port}', self.db, port.id, Port)
                    state['targets'].add(target)

                if port.extra_info is not None:
                    if "domain" in port.extra_info:
                        target = Target(task_id, port.extra_info["domain"])
                        state['targets'].add(target)
                    if "host" in port.extra_info:
                        target = Target(task_id, port.extra_info["host"])
                        state['targets'].add(target)
                    if "cname" in port.extra_info:
                        for cname in port.extra_info['cname'].split(','):
                            target = Target(task_id, cname)
                            state['targets'].add(target)
                    if "cert" in port.extra_info:
                        if "subject_cn" in port.extra_info['cert']:
                            target = Target(task_id, port.extra_info['cert']['subject_cn'])
                            state['targets'].add(target)

            webinfos = session.query(WebInfo).filter(
                and_(
                    WebInfo.task_id == task_id,
                    WebInfo.ip != None,
                    WebInfo.ip_cdn == None
                )
            ).all()
            for webinfo in webinfos:
                target = Target(task_id, webinfo.ip)
                state['targets'].add(target)


class WorkFlowPreAttack:
    app: CompiledGraph | None = None
    debug: bool = False
    team: Team | None = None
    db: DB | None = None

    def __init__(self, db: DB, team: Team, debug: Optional[bool] = None):
        self.db = db
        self.team = team

        nodes = TaskNodesPreAttack(db, team)
        workflow = StateGraph(TaskStatePreAttack)
        workflow.add_node('init_task', nodes.init_task)
        workflow.add_node('recon', nodes.recon)
        workflow.add_node('mapping', nodes.mapping)
        workflow.add_node('port_scan', nodes.port_scan)
        workflow.add_node('vulscan', nodes.vulscan)
        workflow.add_node('finish', nodes.finish)

        workflow.set_entry_point('init_task')
        workflow.set_finish_point('finish')

        workflow.add_edge('init_task', 'recon')
        workflow.add_conditional_edges(
            source='recon',
            # 条件边, 有新目标则继续侦察
            path=nodes.edge_shuld_recon,
            path_map={
                'recon': 'recon',
                'pass': 'mapping'
            }
        )
        workflow.add_conditional_edges(
            source='mapping',
            # 条件边, 有新目标则继续侦察
            path=nodes.edge_shuld_recon,
            path_map={
                'recon': 'recon',
                'pass': 'port_scan'
            }
        )
        workflow.add_edge('port_scan', 'vulscan')
        workflow.add_edge('vulscan', 'finish')

        self.app = workflow.compile(debug=debug)

    def run(self, taskid: int, target: str):
        state = {
            'task_id': taskid,
            'targets': set(),
        }

        if validators.url(target):
            hu = urlparse(target)

            domain_obj = get_tld(hu.netloc, fail_silently=True, as_object=True, fix_protocol=True)
            state['targets'].add(Target(taskid, domain_obj.fld))

            state['targets'].add(Target(taskid, hu.netloc))

        elif is_domain(target, rfc_2782=True):
            domain_obj = get_tld(target, fail_silently=True, as_object=True, fix_protocol=True)
            state['targets'].add(Target(taskid, domain_obj.fld))

        state['targets'].add(Target(taskid, target))

        self.app.invoke(state)

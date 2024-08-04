from enum import IntEnum
from urllib.parse import urlparse

import validators
from langgraph.graph import StateGraph
from typing import TypedDict, Optional

from langgraph.graph.graph import CompiledGraph
from sqlalchemy import and_
from tld import get_tld

from helpers.utils import is_domain, valid_ip_address
from persistence.database import DB
from persistence.orm import Domain, Port, WebInfo, Workflow, ip_is_cdn
from team import Team
from config import logger

WORK = 'pre_attack'


class StatePreAttack(IntEnum):
    INIT = 0  # 初始化
    RECON = 1  # 侦察
    MAPPING = 2  # 测绘
    PORTSCAN = 3  # 端口扫描
    VULSCAN = 4  # 漏扫
    FINISH = 99  # 结束
    IGNORE = -1  # 忽略


class Target:
    def __init__(self, db: DB, task_id: int, parent_target: str, target: str, workflow_id=0,
                 status=StatePreAttack.INIT):
        self.workflow_id = workflow_id
        self.db = db
        self.task_id = task_id
        self.parent_target = parent_target
        self.target = target
        self.status = status

    def init(self):
        with self.db.DBSession() as session:
            if self.workflow_id == 0:
                wf = Workflow()
                wf.work = WORK
                wf.task_id = self.task_id
                wf.status = int(self.status)
                wf.data = {'parent_target': self.parent_target, 'target': self.target}
                session.add(wf)
                session.flush()
                session.commit()
                self.workflow_id = wf.id

    def update_status(self):
        with self.db.DBSession() as session:
            wf = session.query(Workflow).filter(
                and_(
                    Workflow.id == self.workflow_id
                )
            ).first()
            wf.status = int(self.status)

            session.commit()

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
            if valid_ip_address(self.target):
                self.status = StatePreAttack.PORTSCAN
            else:
                self.status = StatePreAttack.MAPPING
        elif self.status == StatePreAttack.MAPPING:
            if valid_ip_address(self.target):
                self.status = StatePreAttack.PORTSCAN
            else:
                self.status = StatePreAttack.VULSCAN
        elif self.status == StatePreAttack.PORTSCAN:
            self.status = StatePreAttack.VULSCAN
        elif self.status == StatePreAttack.VULSCAN:
            self.status = StatePreAttack.FINISH

        self.update_status()


class TaskStatePreAttack(TypedDict):
    task_id: int
    targets: set[Target]


def add_target_to_state(db: DB, state: TaskStatePreAttack, parent_target: str, target: str, workflow_id=0,
                        status=StatePreAttack.INIT):
    target = Target(db, state['task_id'], parent_target, target, workflow_id, status)
    if target not in state['targets']:
        state['targets'].add(target)
        if workflow_id == 0:
            target.init()


def check_target_cdn(db: DB, state: TaskStatePreAttack):
    """ 检查是否为CDN地址 """
    for target in state['targets']:
        if valid_ip_address(target.parent_target):
            iscdn = False
            with db.DBSession() as session:
                iscdn = ip_is_cdn(session, target.parent_target)
            if iscdn:
                target.status = StatePreAttack.IGNORE
                target.update_status()
                continue

        if valid_ip_address(target.target):
            iscdn = False
            with db.DBSession() as session:
                iscdn = ip_is_cdn(session, target.target)
            if iscdn:
                target.status = StatePreAttack.IGNORE
                target.update_status()


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
        # for target in state['targets']:
        #     target.next_status()
        check_target_cdn(self.db, state)
        return state

    def recon(self, state: TaskStatePreAttack):
        """
        侦察目标
        """
        check_target_cdn(self.db, state)
        for target in state['targets']:
            if target.status == StatePreAttack.INIT:
                target.next_status()
            if target.status == StatePreAttack.RECON:
                try:
                    crew = self.team.cyberAssetsResearchers.reconCrew(target.task_id, target.target)
                    out = crew.kickoff()
                    target.next_status()
                    logger.info("[recon {}] {}: {}", target.task_id, target, out)
                except Exception as e:
                    logger.error("[recon {}] {}: {}", target.task_id, target, e)

        self._padding_new_assets(state["task_id"], state)
        return state

    def mapping(self, state: TaskStatePreAttack):
        """
        测绘
        """
        check_target_cdn(self.db, state)
        for target in state['targets']:
            if target.status == StatePreAttack.MAPPING:
                try:
                    crew = self.team.vulScanExpert.fingerprintingCrew(target.task_id, target.target)
                    out = crew.kickoff()
                    target.next_status()
                    logger.info("[mapping {}] {}: {}", target.task_id, target, out)
                except ValueError as e:
                    logger.debug("[mapping {}] {}: {}", target.task_id, target, e)
                except Exception as e:
                    logger.error("[mapping {}] {}: {}", target.task_id, target, e)
        self._padding_new_assets(state["task_id"], state)
        return state

    def port_scan(self, state: TaskStatePreAttack):
        """
        端口扫描
        """
        check_target_cdn(self.db, state)
        for target in state['targets']:
            if target.status == StatePreAttack.PORTSCAN:
                try:
                    self.team.cyberAssetsResearchers.portScanCrew(state["task_id"], target.target)
                    target.next_status()
                except Exception as e:
                    logger.error("[port_scan {}] {}: {}", state["task_id"], target.target, e)

        return state

    def vulscan(self, state: TaskStatePreAttack):
        """
        漏扫
        """
        check_target_cdn(self.db, state)
        for target in state['targets']:
            if target.status == StatePreAttack.VULSCAN:
                try:
                    crew = self.team.vulScanExpert.vulScanCrew(target.task_id, target.target)
                    out = crew.kickoff()
                    target.next_status()
                    logger.info("[vulscan {}] {}: {}", target.task_id, target, out)
                except ValueError as e:
                    logger.debug("[vulscan {}] {}: {}", target.task_id, target, e)
                except Exception as e:
                    logger.error("[vulscan {}] {}: {}", target.task_id, target, e)

        return state

    def finish(self, state: TaskStatePreAttack):
        """
        结束任务
        """
        # TODO
        for target in state['targets']:
            print('finish', target)
        return state

    def edge_shuld_recon_or_mapping(self, state: TaskStatePreAttack):
        """
        条件边
        """
        for target in state['targets']:
            if target.status == StatePreAttack.RECON or target.status == StatePreAttack.INIT:
                return 'recon'
        return 'mapping'

    def edge_shuld_recon_or_portscan(self, state: TaskStatePreAttack):
        """
        条件边
        """

        for target in state['targets']:
            if target.status == StatePreAttack.RECON or target.status == StatePreAttack.INIT:
                return 'recon'
        return 'port_scan'

    def _padding_new_assets(self, task_id: int, state: TaskStatePreAttack):
        """
        获取新资产以进一步侦察
        """
        targets = set()
        with self.db.DBSession() as session:
            domains = session.query(Domain).filter(Domain.task_id == task_id).all()
            for domain in domains:
                if domain.host_cdn is None:
                    targets.add((domain.target, domain.host))
                if len(domain.a) > 0:
                    for idx, a in enumerate(domain.a):
                        if domain.a_cdn[idx] is None:
                            targets.add((domain.target, a))
                if domain.cname is not None:
                    for idx, cname in enumerate(domain.cname):
                        if domain.cname_cdn[idx] is None:
                            targets.add((domain.target, cname))

            ports = session.query(Port).filter(
                and_(
                    Port.task_id == task_id,
                    Port.ip_cdn == None
                )
            ).all()
            for port in ports:
                targets.add(port.ip)
                if port.service is not None and port.service.startswith('http'):
                    targets.add((domain.target, f'{port.service}://{port.ip}:{port.port}'))

                if port.extra_info is not None:
                    if "domain" in port.extra_info:
                        targets.add((domain.target, port.extra_info["domain"]))
                    if "host" in port.extra_info:
                        targets.add((domain.target, port.extra_info["host"]))
                    if "cname" in port.extra_info:
                        for cname in port.extra_info['cname'].split(','):
                            targets.add((domain.target, cname))
                    if "cert" in port.extra_info:
                        if "subject_cn" in port.extra_info['cert']:
                            targets.add((domain.target, port.extra_info['cert']['subject_cn']))

            webinfos = session.query(WebInfo).filter(
                and_(
                    WebInfo.task_id == task_id,
                    WebInfo.ip != None,
                    WebInfo.ip_cdn == None
                )
            ).all()
            for webinfo in webinfos:
                targets.add((webinfo.ip, webinfo.ip))
                targets.add((webinfo.ip, f'http://{webinfo.ip}'))
                targets.add((webinfo.ip, f'https://{webinfo.ip}'))

        for parent_target, target in targets:
            add_target_to_state(self.db, state, parent_target, target)


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
            path=nodes.edge_shuld_recon_or_mapping,
            path_map={
                'recon': 'recon',
                'mapping': 'mapping'
            }
        )
        workflow.add_conditional_edges(
            source='mapping',
            # 条件边, 有新目标则继续侦察
            path=nodes.edge_shuld_recon_or_portscan,
            path_map={
                'recon': 'recon',
                'port_scan': 'port_scan'
            }
        )
        workflow.add_edge('port_scan', 'vulscan')
        workflow.add_edge('vulscan', 'finish')

        self.app = workflow.compile(debug=debug)

    def run(self, taskid: int, target: str | None = None):
        state = {
            'task_id': taskid,
            'targets': set(),
        }

        with self.db.DBSession() as session:
            wfs = session.query(Workflow).filter(
                and_(
                    Workflow.task_id == taskid,
                    Workflow.work == WORK
                )
            ).all()
            for wf in wfs:
                add_target_to_state(self.db, state, wf.data['parent_target'], wf.data['target'], workflow_id=wf.id,
                                    status=StatePreAttack(wf.status))

        if target is not None:
            if validators.url(target):
                hu = urlparse(target)

                if is_domain(hu.netloc, rfc_2782=True):
                    domain_obj = get_tld(hu.netloc, fail_silently=True, as_object=True, fix_protocol=True)
                    add_target_to_state(self.db, state, target, domain_obj.fld)
                if ":" in hu.netloc:
                    host, separator, port = hu.netloc.rpartition(':')
                    add_target_to_state(self.db, state, target, host)
                else:
                    add_target_to_state(self.db, state, target, hu.netloc)


            elif is_domain(target, rfc_2782=True):
                domain_obj = get_tld(target, fail_silently=True, as_object=True, fix_protocol=True)
                add_target_to_state(self.db, state, target, domain_obj.fld)

            add_target_to_state(self.db, state, target, target)

        self.app.invoke(state)

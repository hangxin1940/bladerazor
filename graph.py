from enum import IntEnum

from langgraph.graph import StateGraph
from typing import TypedDict, Optional, Any

from langgraph.graph.graph import CompiledGraph
from sqlalchemy import and_

from persistence.database import DB
from persistence.orm import Domain, Port
from team import Team
from config import logger


class State(IntEnum):
    INIT = 0  # 初始化
    RECON = 1  # 侦察
    MAPPING = 2  # 测绘
    VULSCAN = 3  # 漏扫
    EXPLOIT = 4  # 利用
    FINISH = 99  # 结束


class Target:
    def __init__(self, task_id: int, target: str, db: DB | None = None, orm_id=0, orm_class: Any = None):
        self.db = db
        self.orm_id = orm_id
        self.orm_class = orm_class
        self.task_id = task_id
        self.target = target
        self.status = State.INIT

    def __repr__(self):
        return f'{self.status} {self.task_id}: {self.target}'

    def __eq__(self, other):
        return self.task_id == other.task_id and self.target == other.target

    def __hash__(self):
        return hash((self.task_id, self.target))

    def next_status(self):
        if self.status == State.INIT:
            self.status = State.RECON
        elif self.status == State.RECON:
            self.status = State.MAPPING
        elif self.status == State.MAPPING:
            self.status = State.VULSCAN
        elif self.status == State.VULSCAN:
            self.status = State.EXPLOIT
        elif self.status == State.EXPLOIT:
            self.status = State.FINISH

        if self.db is not None and self.orm_id > 0 and self.orm_class is not None:
            with self.db.DBSession() as session:
                orm = session.query(self.orm_class).get(self.orm_id)
                orm.task_state = self.status
                session.commit()


class TaskState(TypedDict):
    task_id: int
    targets: set[Target]


class TaskNodes:
    team: Team | None = None
    db: DB | None = None

    def __init__(self, db: DB, team: Team):
        self.db = db
        self.team = team

    def init_task(self, state: TaskState):
        """
        初始化任务
        """
        for target in state['targets']:
            target.next_status()
        return state

    def recon(self, state: TaskState):
        """
        侦察目标
        """
        taskid = 0
        for target in state['targets']:
            taskid = target.task_id
            if target.status == State.INIT:
                target.next_status()
            if target.status == State.RECON:
                try:
                    crew = self.team.cyberAssetsResearchers.reconCrew(target.task_id, target.target)
                    out = crew.kickoff()
                    logger.info("[{}] {}: {}", target.task_id, target, out)
                except Exception as e:
                    logger.error("[{}] {}: {}", target.task_id, target, e)
                target.next_status()

        self._padding_new_assets(taskid, state)
        return state

    def mapping(self, state: TaskState):
        """
        测绘
        """
        for target in state['targets']:
            if target.status == State.MAPPING:
                try:
                    crew = self.team.cyberAssetsExperts.fingerprintingCrew(target.task_id, target.target)
                    out = crew.kickoff()
                    logger.info("[{}] {}: {}", target.task_id, target, out)
                except ValueError as e:
                    logger.debug("[{}] {}: {}", target.task_id, target, e)
                except Exception as e:
                    logger.error("[{}] {}: {}", target.task_id, target, e)
                target.next_status()
        return state

    def vulscan(self, state: TaskState):
        """
        漏扫
        """
        for target in state['targets']:
            if target.status == State.VULSCAN:
                try:
                    crew = self.team.cyberAssetsExperts.vulScanCrew(target.task_id, target.target)
                    out = crew.kickoff()
                    logger.info("[{}] {}: {}", target.task_id, target, out)
                except ValueError as e:
                    logger.debug("[{}] {}: {}", target.task_id, target, e)
                except Exception as e:
                    logger.error("[{}] {}: {}", target.task_id, target, e)
            target.next_status()
        return state

    def exploit(self, state: TaskState):
        """
        漏洞利用
        """
        for target in state['targets']:
            if target.status == State.EXPLOIT:
                # TODO
                print("#TODO exploit", target)
                target.next_status()
        return state

    def finish(self, state: TaskState):
        """
        结束任务
        """
        # TODO
        for target in state['targets']:
            print('finish', target)
        return state

    def edge_shuld_recon(self, state: TaskState):
        """
        条件边
        """

        for target in state['targets']:
            if target.status == State.RECON or target.status == State.INIT:
                return 'recon'
        return 'mapping'

    def _padding_new_assets(self, task_id: int, state: TaskState):
        """
        获取新资产以进一步侦察
        """
        with self.db.DBSession() as session:
            domains = session.query(Domain).filter(
                and_(
                    Domain.task_id == task_id,
                    Domain.task_state.in_((State.INIT, State.RECON))
                )
            ).all()
            for domain in domains:
                target = Target(task_id, domain.host, self.db, domain.id, Domain)
                state['targets'].add(target)
                if len(domain.a) > 0:
                    for idx, a in enumerate(domain.a):
                        if domain.a_cdn[idx] is None:
                            target = Target(task_id, a)
                            state['targets'].add(target)

            ports = session.query(Port).filter(
                and_(
                    Port.task_id == task_id,
                    Port.task_state == State.INIT,
                    Port.ip_cdn == None
                )
            ).all()
            for port in ports:
                target = Target(task_id, port.ip)
                state['targets'].add(target)
                if port.service.startswith('http'):
                    target = Target(task_id, f'{port.service}://{port.ip}:{port.port}', self.db, port.id, Port)
                    state['targets'].add(target)

                if "domain" in port.extra_info:
                    target = Target(task_id, port.extra_info["domain"])
                    state['targets'].add(target)


class WorkFlow:
    app: CompiledGraph | None = None
    debug: bool = False
    team: Team | None = None
    db: DB | None = None

    def __init__(self, db: DB, team: Team, debug: Optional[bool] = None):
        self.db = db
        self.team = team

        nodes = TaskNodes(db, team)
        workflow = StateGraph(TaskState)
        workflow.add_node('init_task', nodes.init_task)
        workflow.add_node('recon', nodes.recon)
        workflow.add_node('mapping', nodes.mapping)
        workflow.add_node('vulscan', nodes.vulscan)
        workflow.add_node('exploit', nodes.exploit)
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
                'mapping': 'mapping'
            }
        )
        workflow.add_edge('mapping', 'vulscan')
        workflow.add_edge('vulscan', 'exploit')
        workflow.add_edge('exploit', 'finish')

        self.app = workflow.compile(debug=debug)

    def run(self, taskid: int, target: str):
        state = {
            'task_id': taskid,
            'targets': set(),
        }

        state['targets'].add(Target(taskid, target))

        self.app.invoke(state)

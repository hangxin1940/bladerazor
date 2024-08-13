from enum import IntEnum
from langgraph.graph import StateGraph
from typing import TypedDict, Optional
from langgraph.graph.graph import CompiledGraph
from sqlalchemy import and_

import workflow_attack_plan
from persistence.database import DB
from persistence.orm import Workflow
from team import Team
from config import logger

WORK = 'deploy_attack'


class StateDeployAttack(IntEnum):
    INIT = 0  # 初始化
    DEPLOY = 1  # 部署
    ATTACK = 2  # 攻击
    REWORK = 3  # 重试
    FINISH = 99  # 结束


class Target:
    target: str
    asset: str
    plan: str
    status: StateDeployAttack

    def __init__(self, db: DB, task_id: int, target: str, asset: str, plan: str, workflow_id=0, status=StateDeployAttack.INIT):
        self.db = db
        self.task_id = task_id
        self.workflow_id = workflow_id
        self.target = target
        self.asset = asset
        self.plan = plan
        self.status = status

    def init(self):
        with self.db.DBSession() as session:
            if self.workflow_id == 0:
                wf = Workflow()
                wf.work = WORK
                wf.task_id = self.task_id
                wf.status = int(self.status)
                wf.data = {'target': self.target, 'asset': self.asset, 'plan': self.plan}
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
            wf.data = {'target': self.target, 'asset': self.asset, 'plan': self.plan}
            session.commit()


class TaskStateDeployAttack(TypedDict):
    task_id: int
    targets: list[Target]


class TaskNodesDeployAttack:
    team: Team | None = None
    db: DB | None = None

    def __init__(self, db: DB, team: Team):
        self.db = db
        self.team = team

    def init_task(self, state: TaskStateDeployAttack):
        """
        初始化任务
        """
        if len(state['targets']) == 0:
            # 必须处理完所有遗留任务
            state['targets'] = self._load_attack_plan(state['task_id'])
            for target in state['targets']:
                target.init()

        return state

    def deploy(self, state: TaskStateDeployAttack):
        for target in state['targets']:
            if target.status in [StateDeployAttack.INIT, StateDeployAttack.REWORK, StateDeployAttack.DEPLOY]:
                # TODO
                target.status = StateDeployAttack.ATTACK
                target.update_status()

        return state

    def attack(self, state: TaskStateDeployAttack):
        for target in state['targets']:
            if target.status in [StateDeployAttack.ATTACK]:
                try:
                    crew = self.team.get_establishing_foothold_deploy_attack_crew(target.asset, target.plan)
                    out = crew.kickoff()
                    # TODO 判定攻击是否成功
                    target.status = StateDeployAttack.FINISH
                    target.update_status()

                    logger.info("[attack {}] {}\n{}", state['task_id'], target.target, out)
                except Exception as e:
                    logger.error("[attack {}] {}\n{}", state['task_id'], target.target, e)

        return state

    def finish(self, state: TaskStateDeployAttack):
        """
        结束任务 TODO
        """
        return state

    def edge_shuld_finish(self, state: TaskStateDeployAttack):
        """
        条件边
        """

        for target in state['targets']:
            if target.status in [StateDeployAttack.REWORK]:
                return 'rework'
        return 'pass'

    def _load_attack_plan(self, task_id: int) -> [Target]:
        targets = []
        with self.db.DBSession() as session:
            wfs = session.query(Workflow).filter(
                and_(
                    Workflow.task_id == task_id,
                    Workflow.work == workflow_attack_plan.WORK,
                    Workflow.status == workflow_attack_plan.StatePlanReview.PASS
                )
            ).all()
            for wf in wfs:
                targets.append(
                    Target(
                        db=self.db,
                        task_id=wf.task_id,
                        target=wf.data['target'],
                        asset=wf.data['asset'],
                        plan=wf.data['plan']
                    )
                )
        return targets


class WorkFlowDeployAttack:
    app: CompiledGraph | None = None
    debug: bool = False
    team: Team | None = None
    db: DB | None = None

    def __init__(self, db: DB, team: Team, debug: Optional[bool] = None):
        self.db = db
        self.team = team
        self.debug = debug

        nodes = TaskNodesDeployAttack(db, team)
        workflow = StateGraph(TaskStateDeployAttack)
        workflow.add_node('init_task', nodes.init_task)
        workflow.add_node('deploy', nodes.deploy)
        workflow.add_node('attack', nodes.attack)
        workflow.add_node('finish', nodes.finish)

        workflow.set_entry_point('init_task')
        workflow.set_finish_point('finish')

        workflow.add_edge('init_task', 'deploy')
        workflow.add_edge('deploy', 'attack')

        workflow.add_conditional_edges(
            source='attack',
            path=nodes.edge_shuld_finish,
            path_map={
                'rework': 'deploy',
                'pass': 'finish'
            }
        )

        self.app = workflow.compile(debug=debug)

    def run(self, taskid: int):
        state = {
            'task_id': taskid,
            'targets': []
        }

        with self.db.DBSession() as session:
            wfs = session.query(Workflow).filter(
                and_(
                    Workflow.task_id == taskid,
                    Workflow.work == WORK,
                    Workflow.status != StateDeployAttack.FINISH
                )
            ).all()
            for wf in wfs:
                state['targets'].append(
                    Target(
                        db=self.db,
                        task_id=wf.task_id,
                        target=wf.data['target'],
                        asset=wf.data['asset'],
                        plan=wf.data['plan'],
                        workflow_id=wf.id,
                        status=StateDeployAttack(wf.status)
                    )
                )

        self.app.invoke(state)

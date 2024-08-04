from enum import IntEnum
from langgraph.graph import StateGraph
from typing import TypedDict, Optional
from langgraph.graph.graph import CompiledGraph
from sqlalchemy import and_, func

from persistence.database import DB
from persistence.orm import Port, WebInfo, Vul, Workflow
from team import Team
from config import logger

WORK = 'attack_plan'


class StatePlanReview(IntEnum):
    INIT = 0  # 初始化
    REVIEW = 1  # 审核
    PASS = 2  # 通过
    FAIL = 3  # 否决
    REWORK = 4  # 重做


class Target:
    target: str
    asset: str
    plan: str | None
    review: str | None
    status: StatePlanReview

    def __init__(self, db: DB, task_id: int, target: str, asset: str, plan: str | None, review: str | None,
                 workflow_id=0, status=StatePlanReview.INIT):
        self.db = db
        self.task_id = task_id
        self.workflow_id = workflow_id
        self.target = target
        self.asset = asset
        self.plan = plan
        self.review = review
        self.status = status

    def init(self):
        with self.db.DBSession() as session:
            if self.workflow_id == 0:
                wf = Workflow()
                wf.work = WORK
                wf.task_id = self.task_id
                wf.status = int(self.status)
                wf.data = {'asset': self.asset, 'plan': self.plan, 'review': self.review, 'target': self.target}
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
            wf.data = {'asset': self.asset, 'plan': self.plan, 'review': self.review, 'target': self.target}
            session.commit()


class TaskStateAttackPlan(TypedDict):
    task_id: int
    targets: list[Target]


class TaskNodesAttackPlan:
    team: Team | None = None
    db: DB | None = None

    def __init__(self, db: DB, team: Team):
        self.db = db
        self.team = team

    def init_task(self, state: TaskStateAttackPlan):
        """
        初始化任务
        """
        if len(state['targets']) == 0:
            # 必须处理完所有遗留任务
            state['targets'] = self._assets_intelligence(state['task_id'])
            for target in state['targets']:
                target.init()

        return state

    def establishing_foothold_research(self, state: TaskStateAttackPlan):
        """
        打点研究
        """
        for target in state['targets']:
            if target.status in [StatePlanReview.INIT, StatePlanReview.REWORK]:
                try:
                    if target.status == StatePlanReview.REWORK and target.review is not None:
                        crew = self.team.get_attack_plan_review_crew(target.asset, target.plan, target.review)
                    else:
                        crew = self.team.get_establishing_foothold_research_crew(target.asset)
                    out = crew.kickoff()
                    target.plan = out
                    target.status = StatePlanReview.REVIEW
                    target.update_status()
                    logger.info("[establishing_foothold_research {}] {}\n{}", state['task_id'], target.target, out)
                except ValueError as e:
                    logger.debug("[establishing_foothold_research {}] {}\n{}", state['task_id'], target.target, e)
                except Exception as e:
                    logger.error("[establishing_foothold_research {}] {}\n{}", state['task_id'], target.target, e)
        return state

    def attack_plan_review(self, state: TaskStateAttackPlan):
        """
        检查计划
        """
        for target in state['targets']:
            if target.status in [StatePlanReview.REVIEW]:
                try:
                    crew = self.team.get_attack_plan_review_crew(target.asset, target.plan)
                    out = crew.kickoff().strip()
                    if out.startswith("PASS"):
                        target.status = StatePlanReview.PASS
                        target.review = out[5:]
                    elif out.startswith("FAIL"):
                        target.status = StatePlanReview.FAIL
                        target.review = out[5:]
                    else:
                        target.status = StatePlanReview.REWORK
                        target.review = out
                    target.update_status()
                    logger.info("[attack_plan_review {}] {}\n{}", state['task_id'], target.target, out)
                except ValueError as e:
                    logger.debug("[attack_plan_review {}] {}\n{}", state['task_id'], target.target, e)
                except Exception as e:
                    logger.error("[attack_plan_review {}] {}\n{}", state['task_id'], target.target, e)
        return state

    def finish(self, state: TaskStateAttackPlan):
        """
        结束任务
        """
        # TODO
        # for target in state['targets']:
        #     print('finish', target.target)
        #     print(target.plan)
        return state

    def edge_shuld_finish(self, state: TaskStateAttackPlan):
        """
        条件边
        """

        for target in state['targets']:
            if target.status in [StatePlanReview.REWORK]:
                return 'rework'
        return 'pass'

    def _assets_intelligence(self, task_id: int) -> [Target]:
        """
        获取已探明的资产
        """
        datas = {}
        with self.db.DBSession() as session:
            infos = session.query(WebInfo).filter(
                and_(
                    WebInfo.task_id == task_id,
                    WebInfo.finger_prints != None,
                    func.jsonb_array_length(WebInfo.finger_prints) >= 1
                )
            ).all()
            for info in infos:
                if info.target not in datas:
                    datas[info.host] = []
                datas[info.host].append(info.to_prompt_template())

            vuls = session.query(Vul).filter(Vul.task_id == task_id).all()
            for vul in vuls:
                if vul.target not in datas:
                    datas[vul.target] = []
                datas[vul.target].append(vul.to_prompt_template())

            ports = session.query(Port).filter(
                and_(
                    Port.task_id == task_id,
                    Port.ip_cdn == None
                )
            ).all()
            for port in ports:
                if port.ip not in datas:
                    datas[port.ip] = []
                datas[port.ip].append(port.to_prompt_template())

        targets = []
        for target, data in datas.items():
            targets.append(
                Target(
                    self.db,
                    task_id=task_id,
                    target=target,
                    asset=f"目标: {target}\n{'\n\n---------------\n\n'.join(data)}",
                    plan=None,
                    review=None
                ))
        return targets


class WorkFlowAttackPlan:
    app: CompiledGraph | None = None
    debug: bool = False
    team: Team | None = None
    db: DB | None = None

    def __init__(self, db: DB, team: Team, debug: Optional[bool] = None):
        self.db = db
        self.team = team

        nodes = TaskNodesAttackPlan(db, team)
        workflow = StateGraph(TaskStateAttackPlan)
        workflow.add_node('init_task', nodes.init_task)
        workflow.add_node('establishing_foothold_research', nodes.establishing_foothold_research)
        workflow.add_node('attack_plan_review', nodes.attack_plan_review)
        workflow.add_node('finish', nodes.finish)

        workflow.set_entry_point('init_task')
        workflow.set_finish_point('finish')

        workflow.add_edge('init_task', 'establishing_foothold_research')
        workflow.add_edge('establishing_foothold_research', 'attack_plan_review')
        workflow.add_conditional_edges(
            source='attack_plan_review',
            # 条件边, 有新目标则继续侦察
            path=nodes.edge_shuld_finish,
            path_map={
                'rework': 'establishing_foothold_research',
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
                    Workflow.status.notin_([StatePlanReview.PASS, StatePlanReview.FAIL])
                )
            ).all()
            for wf in wfs:
                state['targets'].append(
                    Target(self.db, wf.task_id, wf.data['target'], wf.data['asset'], wf.data['plan'], wf.data['review'],
                           wf.id, StatePlanReview(wf.status))
                )

        self.app.invoke(state)

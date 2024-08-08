from enum import IntEnum
from langgraph.graph import StateGraph
from typing import TypedDict, Optional
from langgraph.graph.graph import CompiledGraph
from sqlalchemy import and_, func

from persistence.database import DB
from persistence.orm import Port, WebInfo, Vul, Workflow, UrlEnum
from team import Team
from config import logger

WORK = 'attack_plan'


class StatePlanReview(IntEnum):
    INIT = 0  # 初始化
    PREPARATION = 1  # 准备工作
    MAKE_PLAN = 2  # 制定计划
    REVIEW = 3  # 审核
    PASS = 4  # 通过
    FAIL = 5  # 否决
    REWORK = 6  # 重做


class Target:
    target: str
    asset: str
    plan: str | None
    review: str | None
    status: StatePlanReview

    def __init__(self, db: DB, task_id: int, target: str, asset: str, intelligence: str | None, plan: str | None,
                 review: str | None,
                 workflow_id=0, status=StatePlanReview.INIT):
        self.db = db
        self.task_id = task_id
        self.workflow_id = workflow_id
        self.target = target
        self.asset = asset
        self.intelligence = intelligence
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
                wf.data = {'asset': self.asset, 'intelligence': self.intelligence, 'plan': self.plan,
                           'review': self.review, 'target': self.target}
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
            wf.data = {'asset': self.asset, 'intelligence': self.intelligence, 'plan': self.plan, 'review': self.review,
                       'target': self.target}
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

    def preparation(self, state: TaskStateAttackPlan):
        """
        准备工作
        """
        for target in state['targets']:
            if target.status in [StatePlanReview.INIT, StatePlanReview.PREPARATION, StatePlanReview.REWORK]:
                try:
                    crew = self.team.get_intelligence_analysis_crew(target.asset)
                    out = crew.kickoff()
                    target.intelligence = out
                    target.status = StatePlanReview.MAKE_PLAN
                    target.update_status()
                    logger.info("[preparation {}] {}\n{}", state['task_id'], target.target, out)
                except ValueError as e:
                    logger.debug("[preparation {}] {}\n{}", state['task_id'], target.target, e)
                except Exception as e:
                    logger.error("[preparation {}] {}\n{}", state['task_id'], target.target, e)
        return state

    def make_plan(self, state: TaskStateAttackPlan):
        """
        制定计划
        """
        for target in state['targets']:
            if target.status in [StatePlanReview.MAKE_PLAN, StatePlanReview.REWORK]:
                try:
                    if target.status == StatePlanReview.REWORK and target.review is not None:
                        crew = self.team.get_attack_plan_review_crew(target.asset, target.intelligence, target.plan,
                                                                     target.review)
                    else:
                        crew = self.team.get_establishing_foothold_research_crew(target.asset, target.intelligence)
                    out = crew.kickoff()
                    if out.startswith("FAIL") is False:
                        target.plan = out
                        target.status = StatePlanReview.REVIEW
                        target.update_status()
                    logger.info("[make_plan {}] {}\n{}", state['task_id'], target.target, out)
                except ValueError as e:
                    logger.debug("[make_plan {}] {}\n{}", state['task_id'], target.target, e)
                except Exception as e:
                    logger.error("[make_plan {}] {}\n{}", state['task_id'], target.target, e)
        return state

    def attack_plan_review(self, state: TaskStateAttackPlan):
        """
        检查计划
        """
        for target in state['targets']:
            if target.status in [StatePlanReview.REVIEW]:
                try:
                    crew = self.team.get_attack_plan_review_crew(target.asset, target.intelligence, target.plan)
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
            urlenums = session.query(UrlEnum).filter(
                and_(
                    UrlEnum.task_id == task_id,
                    UrlEnum.finger_prints != None,
                    func.jsonb_array_length(UrlEnum.finger_prints) >= 1
                )
            ).all()
            webs = infos + urlenums
            if len(webs) == 0:
                infos = session.query(WebInfo).filter(WebInfo.task_id == task_id).all()
                urlenums = session.query(UrlEnum).filter(UrlEnum.task_id == task_id).all()
                webs = infos + urlenums
            for web in webs:
                if isinstance(web, WebInfo):
                    host = web.host
                    target = web.target
                else:
                    host = web.web_info.host
                    target = web.web_info.target
                if target not in datas:
                    datas[host] = []
                datas[host].append(web.to_prompt_template())

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
                    db=self.db,
                    task_id=task_id,
                    target=target,
                    asset=f"目标: {target}\n{'\n\n---------------\n\n'.join(data)}",
                    intelligence=None,
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
        workflow.add_node('preparation', nodes.preparation)
        workflow.add_node('make_plan', nodes.make_plan)
        workflow.add_node('attack_plan_review', nodes.attack_plan_review)
        workflow.add_node('finish', nodes.finish)

        workflow.set_entry_point('init_task')
        workflow.set_finish_point('finish')

        workflow.add_edge('init_task', 'preparation')
        workflow.add_edge('preparation', 'make_plan')
        workflow.add_edge('make_plan', 'attack_plan_review')
        workflow.add_conditional_edges(
            source='attack_plan_review',
            path=nodes.edge_shuld_finish,
            path_map={
                'rework': 'preparation',
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
                    Target(
                        db=self.db,
                        task_id=wf.task_id,
                        target=wf.data['target'],
                        asset=wf.data['asset'],
                        intelligence=wf.data['intelligence'],
                        plan=wf.data['plan'],
                        review=wf.data['review'],
                        workflow_id=wf.id,
                        status=StatePlanReview(wf.status)
                    )
                )

        self.app.invoke(state)

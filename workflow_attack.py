from enum import IntEnum
from langgraph.graph import StateGraph
from typing import TypedDict, Optional, Any
from langgraph.graph.graph import CompiledGraph
from sqlalchemy import and_, func
from persistence.database import DB
from persistence.orm import Domain, Port, WebInfo, Vul
from team import Team
from config import logger


class StatePlanReview(IntEnum):
    INIT = 0  # 初始化
    PASS = 1  # 通过
    FAIL = 2  # 否决
    REWORK = 3  # 重做


class Target:
    target: str
    asset: str
    plan: str | None
    review: str | None
    status: StatePlanReview

    def __init__(self, target: str, asset: str, plan: str | None):
        self.target = target
        self.asset = asset
        self.plan = plan
        self.review = None
        self.status = StatePlanReview.INIT


class TaskStateAttack(TypedDict):
    task_id: int
    targets: list[Target]


class TaskNodesAttack:
    team: Team | None = None
    db: DB | None = None

    def __init__(self, db: DB, team: Team):
        self.db = db
        self.team = team

    def init_task(self, state: TaskStateAttack):
        """
        初始化任务
        """
        state['targets'] = self._assets_intelligence(state['task_id'])

        return state

    def establishing_foothold_research(self, state: TaskStateAttack):
        """
        打点研究
        """
        for target in state['targets']:
            if target.status in [StatePlanReview.PASS, StatePlanReview.FAIL]:
                continue
            try:
                if target.status == StatePlanReview.REWORK and target.review is not None:
                    crew = self.team.get_attack_plan_review_crew(target.asset, target.plan, target.review)
                else:
                    crew = self.team.get_establishing_foothold_research_crew(target.asset)
                out = crew.kickoff()
                target.plan = out
                logger.info("[establishing_foothold_research {}] {}\n{}", state['task_id'], target.target, out)
            except ValueError as e:
                logger.debug("[establishing_foothold_research {}] {}\n{}", state['task_id'], target.target, e)
            except Exception as e:
                logger.error("[establishing_foothold_research {}] {}\n{}", state['task_id'], target.target, e)
        return state

    def attack_plan_review(self, state: TaskStateAttack):
        """
        检查计划
        """
        for target in state['targets']:
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
                logger.info("[attack_plan_review {}] {}\n{}", state['task_id'], target.target, out)
            except ValueError as e:
                logger.debug("[attack_plan_review {}] {}\n{}", state['task_id'], target.target, e)
            except Exception as e:
                logger.error("[attack_plan_review {}] {}\n{}", state['task_id'], target.target, e)
        return state

    def finish(self, state: TaskStateAttack):
        """
        结束任务
        """
        # TODO
        for target in state['targets']:
            print('finish', target.target)
            print(target.plan)
        return state

    def edge_shuld_finish(self, state: TaskStateAttack):
        """
        条件边
        """

        for target in state['targets']:
            if target.status in [StatePlanReview.INIT, StatePlanReview.REWORK]:
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
                    target=target,
                    asset=f"目标: {target}\n{'\n\n---------------\n\n'.join(data)}",
                    plan=None
                ))
        return targets


class WorkFlowAttack:
    app: CompiledGraph | None = None
    debug: bool = False
    team: Team | None = None
    db: DB | None = None

    def __init__(self, db: DB, team: Team, debug: Optional[bool] = None):
        self.db = db
        self.team = team

        nodes = TaskNodesAttack(db, team)
        workflow = StateGraph(TaskStateAttack)
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
        }

        self.app.invoke(state)

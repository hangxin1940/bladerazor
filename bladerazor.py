import logging
import os

import opentelemetry.sdk.trace
from embedchain.config import BaseLlmConfig
from embedchain.embedder.openai import OpenAIEmbedder
from embedchain.llm.openai import OpenAILlm
from sqlalchemy import func, and_

from exploits.attack_surface_research import AttackSurfaceResearch
from workflow_attack_plan import WorkFlowAttackPlan
from workflow_deploy_attack import WorkFlowDeployAttack
from workflow_pre_attack import WorkFlowPreAttack
from persistence.vectordb import NewEmbedChain
from rag.rag import RAG
from rag.rag_search_tool import RagSearchTool
from team import Team

opentelemetry.sdk.trace.logger.setLevel(logging.CRITICAL)
from langchain_openai import ChatOpenAI

from persistence.database import DB
from persistence.orm import PenTestTask, Vul, WebInfo, Port
from recon.cyber_assets_researcher import CyberAssetsResearchers

if __name__ == '__main__':
    # TODO 移至 cmd 目录
    # PROXY_SOCKS = "http://localhost:1080"
    # os.environ['http_proxy'] = PROXY_SOCKS
    # os.environ['HTTP_PROXY'] = PROXY_SOCKS
    # os.environ['https_proxy'] = PROXY_SOCKS
    # os.environ['HTTPS_PROXY'] = PROXY_SOCKS
    # os.environ["OPENAI_API_KEY"] = OPENAI_KEY
    # os.environ["OPENAI_MODEL_NAME"] = "gpt-3.5-turbo"

    debug = True
    # 初始化数据库
    db = DB(
        user='bladerazor',
        password='123456',
        host='localhost',
        port=15432,
        dbname='bladerazor',
        # echo=debug,
    )

    # 初始化RAG
    embder = OpenAIEmbedder()
    rag = RAG(db=db, embder=embder)

    # ragtool = RagSearchTool(rag)

    # 初始化LLM
    llm = ChatOpenAI(
        temperature=0.9,
        # max_tokens=16385,
        # http_client=httpx.Client(proxy=os.environ['PROXY']),
        # http_client=httpx.AsyncClient(proxy=os.environ['PROXY']),
    )

    # 初始化团队
    team = Team(
        db=db,
        rag=rag,
        llm=llm,
        debug=debug,
        nmap_path=os.getenv('NMAP_PATH'),
        nuclei_path=os.environ['NUCLEI_PATH'],
        nuclei_templates_path=os.environ['NUCLEI_TEMPLATES_PATH'],
        gobuster_path=os.environ['GOBUSTER_PATH'],
        gobuster_wordlist_path=os.environ['GOBUSTER_WORDLIST_PATH'],
    )

    # 目标
    target = 'https://www.example.com/'
    print('target', target)
    task_id = 0

    with db.DBSession() as session:
        task = PenTestTask()
        task.target = target
        task.name = target
        session.add(task)
        session.commit()
        task_id = task.id



    # 工作流 - 预攻击
    workflow = WorkFlowPreAttack(
        db=db,
        team=team,
        debug=debug
    )
    workflow.run(task_id, target)

    # 工作流 - 攻击计划
    workflowAttack = WorkFlowAttackPlan(
        db=db,
        team=team,
        debug=debug
    )

    workflowAttack.run(task_id)

    # 工作流 - 部署攻击
    workflowDeployAttack = WorkFlowDeployAttack(
        db=db,
        team=team,
        debug=debug
    )

    workflowDeployAttack.run(task_id)

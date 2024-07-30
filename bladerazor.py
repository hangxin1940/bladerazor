import logging
import os

import opentelemetry.sdk.trace
from embedchain.embedder.openai import OpenAIEmbedder
from sqlalchemy import func, and_

from exploits.attack_surface_research import AttackSurfaceResearch
from graph import WorkFlow
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
    # PROXY_SOCKS = "http://localhost:1080"
    # os.environ['http_proxy'] = PROXY_SOCKS
    # os.environ['HTTP_PROXY'] = PROXY_SOCKS
    # os.environ['https_proxy'] = PROXY_SOCKS
    # os.environ['HTTPS_PROXY'] = PROXY_SOCKS
    # os.environ["OPENAI_API_KEY"] = OPENAI_KEY
    # os.environ["OPENAI_MODEL_NAME"] = "gpt-3.5-turbo"

    debug = True
    db = DB(
        user='bladerazor',
        password='123456',
        host='localhost',
        port=15432,
        dbname='bladerazor',
        # echo=debug,
    )

    embder = OpenAIEmbedder()

    rag = RAG(db=db, embder=embder)

    # ragtool = RagSearchTool(rag)

    target = 'https://www.example.com/'
    print('target', target)
    # task_id = 1
    with db.DBSession() as session:
        task = PenTestTask()
        task.target = target
        task.name = target
        session.add(task)
        session.commit()
        task_id = task.id

    llm = ChatOpenAI(
        temperature=0.8,
        # max_tokens=16385,
        # http_client=httpx.Client(proxy=os.environ['PROXY']),
        # http_client=httpx.AsyncClient(proxy=os.environ['PROXY']),
    )

    # cyberAssetsResearchers = CyberAssetsResearchers(
    #     db=db,
    #     llm=llm,
    #     verbose=debug
    # )
    #
    # crew = cyberAssetsResearchers.reconCrew(task_id, target)
    #
    # assets = crew.kickoff()
    # print(assets)

    # vulScanExpert = VulScanExpert(
    #     db=db,
    #     llm=llm,
    #     nuclei_path=os.environ['NUCLEI_PATH'],
    #     templates_path=os.environ['NUCLEI_TEMPLATES_PATH'],
    #     verbose=debug
    # )

    # attackSurfaceResearch = AttackSurfaceResearch(
    #     db=db,
    #     rag=rag,
    #     llm=llm,
    #     verbose=debug
    # )
    #
    # datas = {}
    # with db.DBSession() as session:
    #     infos = session.query(WebInfo).filter(
    #         and_(
    #             WebInfo.task_id == 1,
    #             WebInfo.finger_prints != None,
    #             func.jsonb_array_length(WebInfo.finger_prints) >= 1
    #         )
    #     ).all()
    #     for info in infos:
    #         if info.target not in datas:
    #             datas[info.target] = []
    #         datas[info.target].append(info.to_prompt_template())
    #
    #     vuls = session.query(Vul).filter(Vul.task_id == 1).all()
    #     for vul in vuls:
    #         if vul.target not in datas:
    #             datas[vul.target] = []
    #         datas[vul.target].append(vul.to_prompt_template())
    #
    #     ports = session.query(Port).filter(Port.task_id == 1).all()
    #     for port in ports:
    #         if port.ip not in datas:
    #             datas[port.ip] = []
    #         datas[port.ip].append(port.to_prompt_template())
    #
    # attacks = []
    # for target, data in datas.items():
    #     datastr = f"目标: {target}\n{'\n\n---------------\n\n'.join(data)}"
    #     crew = attackSurfaceResearch.establishingFootholdResearchCrew(datastr)
    #
    #     vuls = crew.kickoff()
    #     attacks.append(vuls)
    #
    # print(vuls)

    team = Team(
        db=db,
        rag=rag,
        llm=llm,
        debug=debug,
        nmap_path=os.getenv('NMAP_PATH'),
        nuclei_path=os.environ['NUCLEI_PATH'],
        nuclei_templates_path=os.environ['NUCLEI_TEMPLATES_PATH'],
    )

    workflow = WorkFlow(
        db=db,
        team=team,
        debug=debug
    )
    workflow.run(task_id, target)

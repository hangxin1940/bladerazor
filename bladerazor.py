import logging
import os

import opentelemetry.sdk.trace
from embedchain.embedder.openai import OpenAIEmbedder

from graph import WorkFlow
from persistence.vectordb import NewEmbedChain
from team import Team

opentelemetry.sdk.trace.logger.setLevel(logging.CRITICAL)
from langchain_openai import ChatOpenAI

from exploits.cybersecurity_expert import CybersecurityExperts
from persistence.database import DB
from persistence.orm import PenTestTask
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

    ragdb = NewEmbedChain(db=db, embder=embder)

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

    # cyberAssetsExperts = CybersecurityExperts(
    #     db=db,
    #     llm=llm,
    #     nuclei_path=os.environ['NUCLEI_PATH'],
    #     templates_path=os.environ['NUCLEI_TEMPLATES_PATH'],
    #     verbose=debug
    # )
    #
    # crew = cyberAssetsExperts.vulScanCrew(task_id, target)
    #
    # vuls = crew.kickoff()
    # print(vuls)

    team = Team(
        db=db,
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

import os
from langchain_openai import ChatOpenAI

from persistence.database import DB
from recon.cyber_assets_researcher import CyberAssetsResearchers

if __name__ == '__main__':
    PROXY_SOCKS = "http://localhost:1080"
    os.environ['http_proxy'] = PROXY_SOCKS
    os.environ['HTTP_PROXY'] = PROXY_SOCKS
    os.environ['https_proxy'] = PROXY_SOCKS
    os.environ['HTTPS_PROXY'] = PROXY_SOCKS
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

    target = 'example.com'
    print('target', target)

    llm = ChatOpenAI(
        temperature=0.5,
        # max_tokens=16385,
        # http_client=httpx.Client(proxy=os.environ['PROXY']),
        # http_client=httpx.AsyncClient(proxy=os.environ['PROXY']),
    )

    cyberAssetsResearchers = CyberAssetsResearchers(
        db=db,
        llm=llm,
        verbose=debug
    )

    crew = cyberAssetsResearchers.reconCrew(target)

    assets = crew.kickoff()
    print(assets)

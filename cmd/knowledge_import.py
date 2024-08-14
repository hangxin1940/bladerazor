from embedchain.embedder.openai import OpenAIEmbedder

from persistence.database import DB
from rag.rag import RAG


def add_knowledge():
    print('add_knowledge')
    pass


if __name__ == '__main__':
    # TODO 修改为命令行模式
    db = DB(
        user='bladerazor',
        password='123456',
        host='localhost',
        port=15432,
        dbname='bladerazor',
        # echo=debug,
    )

    # 默认嵌入式模型为 text-embedding-ada-002
    embder = OpenAIEmbedder()

    rag = RAG(db=db, embder=embder)
    # 添加目录，例如某个从git克隆的知识库
    rag.add_knowledge_folder('/my/knowledge/folder')
    # 添加url，例如某个在线的知识
    rag.add_knowledge_url("urlfor://online/sec/knowledge")
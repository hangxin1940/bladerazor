import threading
from typing import Optional, List

from embedchain.embedder.base import BaseEmbedder
from embedchain.loaders.directory_loader import DirectoryLoader
from embedchain.models.data_type import DataType
from pydantic import Field
from pydantic.v1 import BaseModel

from persistence.database import DB
from persistence.vectordb import NewEmbedChain


class Source(BaseModel):
    content: Optional[str] = Field(description="内容")
    data_type: Optional[str] = Field(description="类型")
    src: Optional[str] = Field(description="引用来源")

    def __str__(self):
        if self.data_type == DataType.WEB_PAGE:
            return f"来源: {self.src}\n内容:\n{self.content}"
        return self.content

    def __repr__(self):
        return self.__str__()


class Answer(BaseModel):
    answer: Optional[str] = Field(description="答案")
    sources: List[Source] = Field(description="来源")

    def __str__(self):
        srcs = "\n\n====================\n\n".join([str(src) for src in self.sources])
        return f"答案: {self.answer}\n\n详情:\n{srcs}"


class RAG(object):
    _instance_lock = threading.Lock()

    def __init__(self, db: DB, embder: BaseEmbedder, collection_name="knowledge_vectors"):
        self._embedchain_app = NewEmbedChain(db=db, embder=embder, collection_name=collection_name)

    def __new__(cls, *args, **kwargs):
        if not hasattr(RAG, "_instance"):
            with RAG._instance_lock:
                if not hasattr(RAG, "_instance"):
                    RAG._instance = object.__new__(cls)
        return RAG._instance

    def add_knowledge_url(self, url: str):
        self._embedchain_app.add(url, data_type=DataType.WEB_PAGE)

    def add_knowledge_folder(self, folder_path: str):
        lconfig = {
            "recursive": True,
            "extensions": [".txt", ".md", ".readme", ".README"]
        }
        loader = DirectoryLoader(config=lconfig)

        self._embedchain_app.add(folder_path, data_type=DataType.DIRECTORY, loader=loader)

    def search(self, query: str, num_documents=3):
        return self._embedchain_app.search(query, num_documents=num_documents)

    def query(self, query: str) -> Answer:
        answer, sources = self._embedchain_app.query(query, citations=True)

        srclist = []
        for content, metadata in sources:
            src = Source(content=content, data_type=metadata['data_type'], src=metadata['url'])
            srclist.append(src)

        return Answer(answer=answer, sources=srclist)

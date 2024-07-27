import os
from typing import Any, Optional, Union

from embedchain.config import AppConfig
from embedchain.config.vectordb.base import BaseVectorDbConfig
from embedchain.embedder.base import BaseEmbedder
from embedchain.helpers.json_serializable import register_deserializable
from embedchain.vectordb.base import BaseVectorDB
from sqlalchemy import Table, MetaData, Column, Text, String, inspect, func, and_
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, aliased
from pgvector.sqlalchemy import Vector

from embedchain import App
from config import logger

from persistence.database import DB


@register_deserializable
class PostgresqlDBConfig(BaseVectorDbConfig):
    def __init__(
            self,
            collection_name: Optional[str] = None,
            dir: Optional[str] = None,
    ):
        """
        Initializes a configuration class instance for an Postgresql client.
        """
        super().__init__(collection_name=collection_name, dir=dir)


@register_deserializable
class PgvectorDB(BaseVectorDB):
    """
    PostgresqlDB as vector database
    """

    def __init__(
            self,
            db: DB,
            config: PostgresqlDBConfig,
    ):

        self.db = db
        self.config = config
        self.cls_KnowledgeVectors = None

        super().__init__(config)

    def _initialize(self):
        pass

    def _get_or_create_db(self):
        """Called during initialization"""
        return self.db

    def _get_or_create_collection(self):
        try:
            with self.db.DBSession() as session:
                engine = session.get_bind()
                if not inspect(engine).has_table(self.config.collection_name):
                    metadata = MetaData()
                    metadata.reflect(bind=engine)
                    table = Table(self.config.collection_name, metadata,
                                  Column('id', String, primary_key=True, nullable=False),
                                  Column('vector', Vector(self.embedder.vector_dimension)),
                                  Column('doc', Text),
                                  Column('meta_data', JSONB)
                                  )
                    metadata.create_all(engine, [table])
                    session.commit()
        except Exception as e:
            logger.error(e)

        if self.cls_KnowledgeVectors is None:
            class KnowledgeVectors(Base):
                __tablename__: str = self.config.collection_name

                id: Mapped[str] = mapped_column(String(), primary_key=True)
                vector: Mapped[[float]] = mapped_column(Vector())
                doc: Mapped[str] = mapped_column(Text())
                meta_data: Mapped[object] = mapped_column(JSONB)

                @hybrid_property
                def distance(self):
                    # 仅用于标识，在实际查询中不会用到
                    pass

                @distance.expression
                def distance(cls, query_vector):
                    return cls.vector.cosine_distance(query_vector)

            KnowledgeVectors.__name__ = f"KnowledgeVectors_{self.config.collection_name}"
            self.cls_KnowledgeVectors = KnowledgeVectors
        return self.db

    def get(self, ids: Optional[list[str]] = None, where: Optional[dict[str, any]] = None, limit: Optional[int] = None):
        result = {"ids": [], "metadatas": []}
        try:
            with self.db.DBSession() as session:
                kncls = self.cls_KnowledgeVectors

                clauses = []
                if ids:
                    clauses.append(kncls.id.in_(ids))
                if where:
                    clauses = clauses + [func.jsonb_extract_path_text(kncls.meta_data, key) == value for key, value in
                                         where.items()]

                query = session.query(kncls).filter(and_(*clauses))
                if limit:
                    query = query.limit(limit)

                datas = query.all()
                for data in datas:
                    result["ids"].append(data.id)
                    result["metadatas"].append(data.meta_data)
        except Exception as e:
            logger.error(e)
        return result

    def add(self, documents: list[str], metadatas: list[object], ids: list[str]) -> Any:
        to_ingest = list(zip(documents, metadatas, ids))

        try:
            with self.db.DBSession() as session:
                count = 0
                for doc, meta, id in to_ingest:
                    kvobj = self.cls_KnowledgeVectors()
                    kvobj.id = id
                    kvobj.doc = doc
                    kvobj.meta_data = meta
                    kvobj.vector = self.embedder.embedding_fn([doc])[0]
                    session.add(kvobj)
                    count += 1
                    if count >= 10:
                        session.commit()
                        count = 0
                session.commit()
        except Exception as e:
            logger.error(e)

    def query(
            self,
            input_query: str,
            n_results: int,
            where: dict[str, any],
            citations: bool = False,
            **kwargs: Optional[dict[str, Any]],
    ) -> Union[list[tuple[str, dict]], list[str]]:
        input_query_vector = self.embedder.embedding_fn([input_query])
        query_vector = input_query_vector[0]

        result = []
        try:
            with self.db.DBSession() as session:
                kncls = self.cls_KnowledgeVectors

                clauses = []
                if where:
                    clauses = clauses + [func.jsonb_extract_path_text(kncls.meta_data, key) == value for key, value in
                                         where.items()]

                subquery = session.query(
                    kncls.id,
                    kncls.vector.cosine_distance(query_vector).label('distance')
                ).filter(
                    and_(*clauses)
                ).subquery()

                alias_knowledge_vectors = aliased(kncls, subquery)

                query = session.query(
                    kncls,
                    subquery.c.distance
                ).join(
                    subquery, kncls.id == subquery.c.id
                ).order_by(
                    subquery.c.distance.asc()
                ).limit(n_results)

                datas = query.all()
                for data, distance in datas:
                    if citations:
                        metadata = data.meta_data
                        metadata['score'] = distance
                        result.append((data.doc, metadata))
                    else:
                        result.append(data.doc)
        except Exception as e:
            logger.error(e)
        return result

    def set_collection_name(self, name: str):
        """
        Set the name of the collection. A collection is an isolated space for vectors.

        :param name: Name of the collection.
        :type name: str
        """
        if not isinstance(name, str):
            raise TypeError("Collection name must be a string")
        self.config.collection_name = '{prefix}_{suffix}'.format(prefix=name, suffix=self.embedder.config.model)
        self._get_or_create_collection()

    def count(self) -> int:
        count = 0
        try:
            with self.db.DBSession() as session:
                count = session.query(func.count(self.cls_KnowledgeVectors.id)).scalar()
        except Exception as e:
            logger.error(e)
        return count

    def delete(self, where):
        try:
            with self.db.DBSession() as session:
                kncls = self.cls_KnowledgeVectors
                clauses = [func.jsonb_extract_path_text(kncls.meta_data, key) == value for key, value in where.items()]
                session.query(kncls).filter(and_(*clauses)).delete()
                session.commit()
        except Exception as e:
            logger.error(e)

    def reset(self):
        try:
            with self.db.DBSession() as session:
                session.query(self.cls_KnowledgeVectors).delete()
                session.commit()
        except Exception as e:
            logger.error(e)


class Base(DeclarativeBase):
    pass


def NewEmbedChain(db: DB, embder: BaseEmbedder, collection_name="knowledge_vectors") -> App:
    # embedchain元数据存储在Postgresql数据库中
    os.environ['EMBEDCHAIN_DB_URI'] = db.DBSession.bind.url.render_as_string(False)

    cfg = PostgresqlDBConfig(collection_name=collection_name)
    pdb = PgvectorDB(db, config=cfg)

    app_config = AppConfig(collect_metrics=False)

    app = App(
        config=app_config,
        llm=None,
        db=pdb,
        embedding_model=embder,
        config_data=None,
        auto_deploy=False,
        chunker=None,
        cache_config=None,
        memory_config=None,
    )
    return app

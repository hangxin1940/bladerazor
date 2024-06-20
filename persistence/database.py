from sqlalchemy import create_engine, func
import threading

from sqlalchemy.orm import sessionmaker, scoped_session

from persistence.orm import Base, Cdn


class DB(object):
    _instance_lock = threading.Lock()

    def __init__(self, user: str, password: str, host: str, port: int, dbname: str, echo: bool = False):
        self._engine = create_engine(
            url=f"postgresql://{user}:{password}@{host}:{port}/{dbname}",
            echo=echo,  # echo 设为 True 会打印出实际执行的 sql，调试的时候更方便
            future=True,  # 使用 SQLAlchemy 2.0 API，向后兼容
            pool_size=5,  # 连接池的大小默认为 5 个，设置为 0 时表示连接无限制
            pool_recycle=3600,  # 设置时间以限制数据库自动断开
        )
        Base.metadata.create_all(self._engine)
        self.DBSession = scoped_session(sessionmaker(bind=self._engine))
        with self.DBSession() as session:
            cdncount = session.query(func.count(Cdn.id)).scalar()
            if cdncount == 0:
                import yaml
                from ipaddress import ip_network
                with open("cdn_servers.yaml") as yamlstream:
                    try:
                        yamldata = yaml.safe_load(yamlstream)
                        for cdn, vals in yamldata["cidr"].items():
                            for cidr in vals:
                                session.add(Cdn(organization=cdn, cidr=ip_network(cidr)))
                        for cdn, vals in yamldata["cname"].items():
                            for cname in vals:
                                session.add(Cdn(organization=cdn, cname=cname))
                        session.commit()
                    except Exception as e:
                        raise e

    def __new__(cls, *args, **kwargs):
        if not hasattr(DB, "_instance"):
            with DB._instance_lock:
                if not hasattr(DB, "_instance"):
                    DB._instance = object.__new__(cls)
        return DB._instance

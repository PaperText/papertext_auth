from typing import Any, Callable, Dict, List, NoReturn, Tuple

from fastapi import Header
from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine

from paperback import BaseAuth


class AuthImplemented(BaseAuth):
    DEFAULTS = {
        "test": False,
        "DB": {
            "type": "PostgreSQL",
            "host": "127.0.0.1",
            "port": "5432",
            "username": "postgres",
            "password": "password",
            "dbname": "postgres",
        },
    }

    def __init__(self, cfg: Dict[str, Any]):
        self.engine = create_engine(
            f"postgresql://{cfg.DB.username}:{cfg.DB.password}@{cfg.DB.host}:{cfg.DB.port}/{cfg.DB.dbname}",
            echo=True,
            client_encoding="utf8",
        )
        self.meta = MetaData(bind=self.engine, reflect=True)

        if "users" not in self.meta.tables:
            self.users = Table(
                "users",
                self.meta,
                Column("id", Integer, primary_key=True),
                Column("username", String),
                Column("password", String),
                Column("loa", Integer),
                Column("org", Integer),
            )
        else:
            self.users = self.meta.tables['users']
        self.meta.create_all(self.engine)
        if len([u for u in self.engine.execute(self.users.select())]) == 0:
            self.engine.execute(
                self.users.insert().values(username='guest', password="guest", loa=0, org=0)
            )
        for table in self.meta.tables:
            print(table)
        for user in self.engine.execute(self.users.select()):
            print(user)

    def setup(self, cfg: Dict[str, Any]) -> NoReturn:
        pass

    def create_user(
        self,
        email: str,
        password: str,
        name: str = "",
        organization: str = 0,
        access_level: int = 0,
    ) -> bool:
        pass

    def read_user(self, email: str) -> Dict[str, Tuple[str, int]]:
        pass

    def update_user(
        self,
        email: str,
        password: str = None,
        name: str = None,
        organization: int = None,
        access_level: int = None,
    ) -> bool:
        pass

    def delete_user(self, email: str) -> bool:
        pass

    def sign_in(self, email: str, password: str,) -> str:
        pass

    def sign_out(self,) -> bool:
        pass

    def sign_out_everywhere(self,) -> bool:
        pass

    def remove_token(self, token: str) -> bool:
        pass

    def remove_tokens(self, token: List[str]) -> bool:
        pass

    def test_token(
        self, greater_or_equal: int, one_of: List[int]
    ) -> Callable[[Header], NoReturn]:
        pass

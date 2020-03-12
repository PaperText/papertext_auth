from typing import Any, Callable, Dict, List, Mapping, NoReturn, Tuple

from fastapi import FastAPI, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
)

from paperback import BaseAuth, NewUser

from .crypto import crypt_context


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
        "crypto": {"default": "argon2"},
    }

    def __init__(self, cfg: Mapping[str, Any]):
        crypt_context.update(default=cfg.crypto.default)

        self.engine = create_engine(
            f"postgresql://{cfg.DB.username}:{cfg.DB.password}@{cfg.DB.host}:{cfg.DB.port}/{cfg.DB.dbname}",
            # echo=True,
        )
        self.metadata = MetaData(bind=self.engine)
        self.users = Table(
            "users",
            self.metadata,
            Column("id", Integer, primary_key=True),
            Column("username", String(256)),
            Column("hashed_password", String),
            Column("access_level", Integer),
            Column("organization", String(256)),
        )

        self.tokens = Table(
            "tokens",
            self.metadata,
            Column("id", Integer, primary_key=True),
            Column("token", String),
            Column("location", String),
            Column("device", String),
        )
        self.metadata.create_all(self.engine)

    async def create_user(
        self,
        username: str,
        password: str,
        access_level: int = 0,
        organization: str = "Public",
    ):
        ins = self.users.insert().values(
            username=username,
            hashed_password=crypt_context.hash(password),
            access_level=access_level,
            organization=organization,
        )
        print(ins)
        conn = self.engine.connect()
        res = conn.execute(ins)
        print(res)

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

    def sign_up(self, user: NewUser) -> str:
        pass

    def remove_token(self, token: str) -> bool:
        pass

    def remove_tokens(self, token: List[str]) -> bool:
        pass

    def add_CORS(self, api: FastAPI) -> NoReturn:
        api.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    def test_token(self, greater_or_equal: int, one_of: List[int]) -> bool:
        pass

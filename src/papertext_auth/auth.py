from logging import getLogger
from pathlib import Path
from types import SimpleNamespace
from typing import List, Mapping, NoReturn, Union

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from paperback import BaseAuth, NewUser, UserInfo
from sqlalchemy import (
    Column,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
)

from .crypto import crypt_context


class AuthImplemented(BaseAuth):
    DEFAULTS: Mapping[str, Union[str, Mapping[str, str]]] = {
        "db": {
            "host": "127.0.0.1",
            "port": "5432",
            "username": "postgres",
            "password": "password",
            "dbname": "papertext",
        },
        "crypto": {"algo": "argon2"},
        "token": {"algo": "ecsda", "generate_keys": "False", "regenerate_keys": "False"},
    }

    def __init__(self, cfg: SimpleNamespace, storage_dir: Path):
        self.log = getLogger("papertext.auth")

        crypt_context.update(default=cfg.crypto.algo)
        self.log.info("updated crypto context")

        if str(cfg.token.regenerate_keys).lower() == "false":
            cfg.token.regenerate_keys = False
        else:
            cfg.token.generate_keys = True
        if str(cfg.token.generate_keys).lower() == "false":
            cfg.token.generate_keys = False
        else:
            cfg.token.generate_keys = True

        if cfg.token.regenerate_keys or cfg.token.generate_keys:
            self.log.info("(re)generating keys")
        elif not ((storage_dir / "private.key").exists() or (storage_dir / "public.key").exists()):
            self.log.warning("unable to find keys")
            raise FileExistsError("unable to find keys")

        self.private_key = storage_dir / "private.key"
        self.public_key = storage_dir / "public.key"

        self.engine = create_engine(
            f"postgresql://{cfg.db.username}:{cfg.db.password}@{cfg.db.host}:{cfg.db.port}/{cfg.db.dbname}",
        )
        self.metadata = MetaData(bind=self.engine)
        self.users = Table(
            "users",
            self.metadata,
            Column("id", Integer, primary_key=True),
            Column("username", String(256)),
            Column("hashed_password", String),
            Column("full_name", String(256)),
            Column("access_level", Integer),
            Column("organization", String(256)),
            extend_existing=True,
        )

        self.tokens = Table(
            "tokens",
            self.metadata,
            Column("id", Integer, primary_key=True),
            Column("token", String),
            Column("location", String),
            Column("device", String),
            extend_existing=True,
        )

        self.invitation_codes = Table(
            "invitation_codes",
            self.metadata,
            Column("id", Integer, primary_key=True),
            Column("code", String),
            Column("issued_by", Integer),
            extend_existing=True,
        )
        self.metadata.create_all(self.engine)

    async def create_user(
        self,
        username: str,
        password: str,
        full_name: str = None,
        access_level: int = 0,
        organization: str = "Public",
    ) -> NoReturn:
        if full_name is None:
            full_name = username
        select = self.users.select().where(self.users.c.username == username)
        insert = self.users.insert().values(
            username=username,
            hashed_password=crypt_context.hash(password),
            full_name=full_name,
            access_level=access_level,
            organization=organization,
        )

        conn = self.engine.connect()
        if len(conn.execute(select).fetchall()) > 0:
            pass
        else:
            conn.execute(insert)

    async def read_user(self, username: str) -> UserInfo:
        select = self.users.select().where(self.users.c.username == username)
        conn = self.engine.connect()
        result = conn.execute(select).fetchone()
        user = UserInfo(
            username=result.username,
            full_name=result.full_name,
            organization=result.organization,
            access_level=result.access_level,
        )
        return user

    def update_user(self, email: str, password: str = None, name: str = None, organization: int = None,
                    access_level: int = None, **kwargs) -> bool:
        pass

    def delete_user(self, email: str) -> bool:
        pass

    async def read_users(self) -> List[UserInfo]:
        pass

    def sign_in(self, username: str, password: str, ) -> str:
        pass

    def sign_out(self, ) -> bool:
        pass

    def sign_out_everywhere(self, ) -> bool:
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

    async def get_user_from_token(self) -> UserInfo:
        pass

    async def get_tokens(self, username: str) -> List[str]:
        pass

    def test_token(self, greater_or_equal: int, one_of: List[int]) -> bool:
        return True

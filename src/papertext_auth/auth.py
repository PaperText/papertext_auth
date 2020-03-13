from typing import Any, Callable, Dict, List, Mapping, NoReturn, Tuple, Union

from fastapi import FastAPI, Header, status
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

from paperback import BaseAuth, NewUser, UserInfo

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
            Column("full_name", String(256)),
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

        self.invitation_codes = Table(
            "invitation_codes",
            self.metadata,
            Column("id", Integer, primary_key=True),
            Column("code", String),
            Column("issued_by", Integer),
        )
        self.metadata.create_all(self.engine)

    async def create_user(
        self,
        username: str,
        password: str,
        full_name: str = None,
        access_level: int = 0,
        organization: str = "Public",
    ) -> Tuple[int, str]:
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
            return status.HTTP_400_BAD_REQUEST, {"detail": f"User with username `{username}` already exists"}
        else:
            conn.execute(insert)
            return status.HTTP_200_OK, {"detail": "Successfully created new user"}

    async def read_user(self, username: str) -> Tuple[int, str, UserInfo]:
        select = self.users.select().where(self.users.c.username == username)
        conn = self.engine.connect()
        result = conn.execute(select).fetchone()
        print(result)
        user = UserInfo(username=result.username, full_name=result.full_name, organization=result.organization, access_level=result.access_level)
        return status.HTTP_200_OK, {"detail": f"Successfully found user {result.id} by username"}, user


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

    def test_token(self, greater_or_equal: int, one_of: List[int]) -> bool:
        pass

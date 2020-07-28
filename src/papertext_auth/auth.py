import asyncio
from types import SimpleNamespace
from typing import List, Union, Mapping, NoReturn, Optional
import logging
from pathlib import Path
from collections import defaultdict

from databases import Database
from fastapi import FastAPI
import ecdsa
from sqlalchemy import Table, Column, String, Integer, MetaData, create_engine
from pydantic import BaseModel

from paperback.abc import (
    NewUser,
    BaseAuth,
    UserInfo,
    InviteCode,
    Organisation,
    MinimalOrganisation,
)

from .crypto import crypto_context


class AuthImplemented(BaseAuth):
    DEFAULTS: Mapping[str, Union[str, Mapping[str, str]]] = {
        "db": {
            "host": "127.0.0.1",
            "port": "5432",
            "username": "postgres",
            "password": "password",
            "dbname": "papertext",
        },
        "hash": {"algo": "pbkdf2_sha512"},
        "token": {
            "curve": "secp521r1",
            "generate_keys": False,
        },
    }

    requires_dir = True

    def __init__(self, cfg: SimpleNamespace, storage_dir: Path):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.getLogger("paperback").level)
        self.logger.info("initializing papertext_auth module")

        self.storage_dir = storage_dir
        self.cfg = cfg
        # TODO: add check for configuration,
        #  i.e. that hash.algo lib and token.curve lib are present

        self.logger.debug("updating crypto context")
        crypto_context.update(default=cfg.hash.algo)

        self.logger.debug("getting JWT keys")

        self.private_key_file = self.storage_dir / "private.pem"
        self.public_key_file = self.storage_dir / "public.pem"

        if cfg.token.generate_keys:
            self.logger.debug("option for generation keys is enabled")
            if self.public_key_file.exists():
                self.logger.warning("public key exist, saving it")
                bak_public_key_file = self.storage_dir / "public.pem.bak"
                self.public_key_file.rename(bak_public_key_file)
                self.public_key_file.touch(exist_ok=True)
            if self.private_key_file.exists():
                self.logger.warning("private key exist, saving it")
                bak_private_key_file = self.storage_dir / "private.pem.bak"
                self.private_key_file.rename(bak_private_key_file)
                self.private_key_file.touch(exist_ok=True)
            if not (self.public_key_file.exists() and self.private_key_file.exists()):
                self.logger.debug("no keys found")
                self.public_key_file.touch(exist_ok=True)
                self.private_key_file.touch(exist_ok=True)
            self.logger.debug("generating new keys")
            self.private_key, self.public_key = self.generate_keys(cfg.token.curve)
            self.logger.debug("saving new keys")
            self.private_key_file.write_bytes(self.private_key.to_pem())
            self.public_key_file.write_bytes(self.public_key.to_pem())
        else:
            if self.public_key_file.exists() and self.private_key_file.exists():
                self.logger.debug("both keys are present")
            else:
                self.logger.error("one of the keys if missing")
                raise FileExistsError("one of the keys if missing")
            self.private_key, self.public_key = self.read_keys(cfg.token.curve)

        self.logger.info("acquired token keys")

        database_url: str = f"postgresql://{cfg.db.username}:{cfg.db.password}@{cfg.db.host}:{cfg.db.port}/{cfg.db.dbname}"
        database: Database = Database(database_url)
        asyncio.get_event_loop().run_until_complete(database.connect())

        self.logger.debug("connecting to db")
        self.engine = create_engine(
            database_url
        )
        self.logger.debug("acquiring db metadata")
        self.metadata = MetaData(bind=self.engine)
        self.logger.debug("creating tables/ensuring they are present")
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
        self.logger.info("connected to db")

    def generate_keys(self, curve: str) -> NoReturn:
        def default():
            self.logger.error("can't find specified curve")
            raise KeyError("can't find specified curve")
        def secp521r1():
            self.logger.debug("creating secp521r1 keys")
            sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST521p)
            vk = sk.verifying_key
            return sk, vk
        case = defaultdict(default)
        case["secp521r1"] = secp521r1
        return case[curve]()

    def read_keys(self, curve: str) -> NoReturn:
        def default():
            self.logger.error("can't find specified curve")
            raise KeyError("can't find specified curve")
        def secp521r1():
            self.logger.debug("creating secp521r1 keys")
            sk = ecdsa.SigningKey.from_pem(self.private_key_file.read_text())
            vk = sk.verifying_key
            return sk, vk
        case = defaultdict(default)
        case["secp521r1"] = secp521r1
        return case[curve]()

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
            hashed_password=crypto_context.hash(password),
            full_name=full_name,
            access_level=access_level,
            organization=organization,
        )

        conn = self.engine.connect()
        if len(conn.execute(select).fetchall()) > 0:
            pass
        else:
            conn.execute(insert)

    async def get_users(self) -> List[UserInfo]:
        pass

    async def read_user(self, username: str) -> UserInfo:
        select = self.users.select().where(self.users.c.username == username)
        conn = self.engine.connect()
        result = conn.execute(select).fetchone()
        user = UserInfo(
            username=result.username,
            fullname=result.fullname,
            organization=result.organisation,
            access_level=result.access_level,
        )
        return user

    def token2user(self, token: str) -> UserInfo:
        pass

    async def update_user(
        self,
        username: str,
        new_username: Optional[str] = None,
        password: Optional[str] = None,
        name: Optional[str] = None,
        access_level: Optional[int] = None,
        organization: Optional[str] = None,
    ) -> NoReturn:
        pass

    async def delete_user(self, username: str) -> NoReturn:
        pass

    async def sign_in(self, username: str, password: str) -> str:
        pass

    async def sign_out(self) -> NoReturn:
        pass

    async def sign_out_everywhere(self) -> NoReturn:
        pass

    async def sign_up(self, user: NewUser) -> NoReturn:
        pass

    async def remove_token(self, token: str) -> NoReturn:
        pass

    async def remove_tokens(self, token: List[str]) -> NoReturn:
        pass

    async def get_tokens(self, username: str) -> List[str]:
        pass

    async def create_org(self, name: str, title: str):
        pass

    async def update_org(self, org_name: str, org_title: str):
        pass

    async def delete_org(self, org_name: str):
        pass

    async def get_orgs(self) -> List[MinimalOrganisation]:
        pass

    async def get_org_with_users(self, org_name: str) -> Organisation:
        pass

    async def create_invite_code(self, gives_access: List[str]) -> str:
        pass

    async def read_invite_codes(self) -> List[InviteCode]:
        pass

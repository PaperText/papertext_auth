from types import SimpleNamespace
from typing import List, Union, Mapping, NoReturn, Optional
from logging import getLogger
from pathlib import Path

from fastapi import FastAPI
from sqlalchemy import Table, Column, String, Integer, MetaData, create_engine

from paperback.abc import Organisation, NewUser, BaseAuth, MinimalOrganisation, UserInfo, InviteCode

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
        "hash": {"algo": "pbkdf2_sha512"},
        "token": {
            "algo": "ecdsa",
            "generate_keys": False,
            "regenerate_keys": False,
        },
    }

    requires_dir = True

    def __init__(self, cfg: SimpleNamespace, storage_dir: Path):
        self.log = getLogger("papertext.auth")
        self.log.debug("initialized papertext.auth logger")

        self.log.debug("updating crypto context")
        crypt_context.update(default=cfg.hash.algo)
        self.log.info("updated crypto context")

        self.log.debug("getting token keys")
        if str(cfg.token.regenerate_keys).lower() == "false":
            cfg.token.regenerate_keys = False
        else:
            cfg.token.generate_keys = True
        if str(cfg.token.generate_keys).lower() == "false":
            cfg.token.generate_keys = False
        else:
            cfg.token.generate_keys = True

        private_key = storage_dir / "private.pem"
        public_key = storage_dir / "public.pem"

        if cfg.token.regenerate_keys:
            self.log.debug("regenerating both of the keys")
            self.regenerate_keys(cfg.token.algo)
        else:
            if private_key and public_key:
                if cfg.token.generate_keys:
                    self.log.debug("both keys are present, nothing to generate")
            else:
                if cfg.token.generate_keys:
                    if not private_key and not public_key:
                        self.log.debug("both keys are missing, regenerating")
                    else:
                        self.log.debug("one of the keys is missing")
                        if private_key.exists():
                            self.log.debug("private key is present, regenerating public")
                            self.private2public_key(cfg.token.algo)

                        elif public_key.exists():
                            self.log.debug("public key is present, can't regenerate private")
                            self.log.warning("unable to find keys")
                            raise FileExistsError("unable to find private key, "
                                                  "try `auth.token.regenerate_keys = true`in config")

                else:
                    self.log.warning("unable to find keys")
                    raise FileExistsError("unable to find keys"
                                          "try `auth.token.regenerate_keys = true`in config")
        self.log.info("acquired token keys")

        self.log.debug("connecting to db")
        self.engine = create_engine(
            f"postgresql://{cfg.db.username}:{cfg.db.password}@{cfg.db.host}:{cfg.db.port}/{cfg.db.dbname}",
        )
        self.log.debug("acquiring db metadata")
        self.metadata = MetaData(bind=self.engine)
        self.log.debug("creating tables/ensuring they are present")
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
        self.log.info("connected to db")

    def regenerate_keys(self, algo: str) -> NoReturn:
        pass

    def private2public_key(self, algo: str) -> NoReturn:
        pass

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

    async def get_users(self) -> List[UserInfo]:
        pass

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

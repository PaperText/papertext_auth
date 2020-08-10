import datetime
import time
import uuid
import asyncio
import logging
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Tuple, Union, Mapping, NoReturn, Optional
from pathlib import Path
from collections import defaultdict

from authlib.jose import jwt
import ecdsa
import sqlalchemy as sa
from fastapi import FastAPI, HTTPException, status, Request
from databases import Database
from pydantic import EmailStr
from email_validator import EmailNotValidError, validate_email
from user_agents import parse
from ipstack import GeoLookup

from paperback.abc import (
    NewUser,
    BaseAuth,
    UserInfo,
    InviteCode,
    Credentials,
    Organisation,
    NewInvitedUser,
    UserUpdatePassword,
    MinimalOrganisation,
)
from paperback.abc.models import custom_charset, starts_with


from .crypto import crypto_context


class AuthImplemented(BaseAuth):
    DEFAULTS: Mapping[str, Union[str, Mapping[str, Union[str, bool]]]] = {
        "IPstack_api_key": "",
        "db": {
            "host": "127.0.0.1",
            "port": "5432",
            "username": "postgres",
            "password": "password",
            "dbname": "papertext",
        },
        "hash": {"algo": "pbkdf2_sha512"},
        "token": {"curve": "secp521r1", "generate_keys": False, },
    }

    requires_dir: bool = True

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
        self.logger.info("updated crypto context")

        self.logger.debug("connecting to ipstack")
        self.ip2geo = GeoLookup(cfg.IPstack_api_key)
        self.logger.info("connected to ipstack")

        self.logger.debug("getting JWT keys")

        self.private_key_file = self.storage_dir / "private.pem"
        self.public_key_file = self.storage_dir / "public.pem"
        self.private_key: bytes
        self.public_key: bytes

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
            if not (
                self.public_key_file.exists()
                and self.private_key_file.exists()
            ):
                self.logger.debug("no keys found")
                self.public_key_file.touch(exist_ok=True)
                self.private_key_file.touch(exist_ok=True)
            self.logger.debug("generating new keys")
            self.private_key, self.public_key = self.generate_keys(
                cfg.token.curve
            )
            self.logger.debug("saving new keys")
            self.private_key_file.write_bytes(self.private_key)
            self.public_key_file.write_bytes(self.public_key)
        else:
            if (
                self.public_key_file.exists()
                and self.private_key_file.exists()
            ):
                self.logger.debug("both keys are present")
            else:
                self.logger.error("one of the keys if missing")
                raise FileExistsError("one of the keys if missing")
            self.private_key, self.public_key = self.read_keys(cfg.token.curve)

        self.logger.info("acquired token keys")

        self.logger.debug("setting up database")
        database_url: str = "postgresql://" \
                            f"{cfg.db.username}:{cfg.db.password}" \
                            f"@{cfg.db.host}:{cfg.db.port}/{cfg.db.dbname}"
        self.database = Database(database_url)
        self.engine = sa.create_engine(database_url)

        self.logger.debug("setting up tables")
        self.metadata = sa.MetaData(bind=self.engine)

        self.logger.debug("creating tables or ensuring they are present")
        self.users = sa.Table(
            "users",
            self.metadata,
            sa.Column(
                "user_uuid",
                sa.Binary(16),
                primary_key=True,
                unique=True,
                default=uuid.uuid4,
            ),
            sa.Column("user_id", sa.String(256), unique=True),
            sa.Column("email", sa.String(256), unique=True),
            sa.Column("hashed_password", sa.Text()),
            sa.Column("user_name", sa.String(256)),
            sa.Column("level_of_access", sa.Integer()),
            sa.Column(
                "users_organisation_uuid",
                sa.Binary(16),
                sa.ForeignKey("organisations.organisation_uuid"),
            ),
            extend_existing=True,
        )
        self.organisations = sa.Table(
            "organisations",
            self.metadata,
            sa.Column(
                "organisation_uuid",
                sa.Binary(16),
                primary_key=True,
                unique=True,
                default=uuid.uuid4,
            ),
            sa.Column("organisation_id", sa.String(256), unique=True),
            sa.Column("organisation_name", sa.Text()),
            extend_existing=True,
        )
        self.tokens = sa.Table(
            "tokens",
            self.metadata,
            sa.Column(
                "token_uuid",
                sa.Binary(16),
                primary_key=True,
                unique=True,
                default=uuid.uuid4,
            ),
            sa.Column("location", sa.Text()),
            sa.Column("device", sa.Text()),
            sa.Column("issued_by", sa.Binary(16), sa.ForeignKey("users.user_uuid"),),
            sa.Column("issued_at", sa.Text()),
            extend_existing=True,
        )
        self.invitation_codes = sa.Table(
            "invitation_codes",
            self.metadata,
            sa.Column(
                "invitation_code_uuid",
                sa.Binary(16),
                primary_key=True,
                unique=True,
                default=uuid.uuid4,
            ),
            sa.Column("code", sa.Text()),
            sa.Column("user_uuid", sa.Binary(16)),
            sa.Column("organisation_uuid", sa.Binary(16)),
            extend_existing=True,
        )
        self.metadata.create_all(self.engine)

        self.logger.info("connected to database")

        # TODO: move to dedicated function
        self.logger.debug("creating basic organisation")
        conn = self.engine.connect()
        # organisation_id="pub", name="Публичная организация"
        select_org_with_same_id = self.organisations.select().where(
            self.organisations.c.organisation_id == self.public_org_id
        )
        org_with_same_id = conn.execute(select_org_with_same_id).fetchall()
        if len(org_with_same_id) > 0:
            self.logger.debug("public organisation already exists")
            self.public_org = org_with_same_id
        else:
            self.logger.debug("public organisation doesn't exist")
            org = {
                "organisation_uuid": uuid.uuid4().bytes,
                "organisation_id": self.public_org_id,
                "organisation_name": "Публичная организация",
            }
            insert = self.organisations.insert().values(**org)
            conn.execute(insert)
            self.public_org = org
        conn.close()

    async def run_async(self):
        if not self.database.is_connected:
            self.logger.info("connected to database")
            await self.database.connect()

    def generate_keys(self, curve: str) -> NoReturn:
        def default():
            self.logger.error("can't find specified curve")
            raise KeyError("can't find specified curve")

        def secp521r1():
            self.logger.debug("creating secp521r1 keys")
            sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST521p)
            vk = sk.verifying_key
            sk = sk.to_pem()
            vk = vk.to_pem()
            return sk, vk

        case: Dict[str, Callable[..., Tuple[bytes, bytes]]] = defaultdict(default)
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
            sk = sk.to_pem()
            vk = vk.to_pem()
            return sk, vk

        case = defaultdict(default)
        case["secp521r1"] = secp521r1
        return case[curve]()

    def token2user(self, token: str) -> Dict[str, Union[str, int]]:
        claims = jwt.decode(token, self.public_key)
        user_uuid: bytes = uuid.UUID(claims["sub"]).bytes

        conn = self.engine.connect()
        user = conn.execute(
            sa.sql.select([self.users, self.organisations]).where(
                self.users.c.user_uuid == user_uuid
            )
        ).fetchone()
        print(user)
        print(dict(user))
        conn.close()

        self.logger.debug("decoded token %s for user %s", claims, user)
        return user

    async def signin(
        self,
        request: Request,
        password: str,
        identifier: Union[str, EmailStr],
    ) -> str:
        location: str = "Unknown"
        if "x-real-ip" in request.headers:
            real_ip: str = request.headers["x-real-ip"]
            self.logger.debug("requesters IP adress is %s", real_ip)
            try:
                ipstack_res: Dict = self.ip2geo.get_location(real_ip)
                location = f"{ipstack_res['location']['country_flag_emoji']} " \
                           f"{ipstack_res['city']} / " \
                           f"{ipstack_res['region_name']} / " \
                           f"{ipstack_res['country_name']}"
            except Exception as exception:
                self.logger.error(
                    "an error acquired when requesting ipstack: %s", exception
                )
                location = "Unknown"
        self.logger.debug("requesters geolocation is %s", location)

        device: str = "Unknown"
        if "user-agent" in request.headers:
            ua_str: str = request.headers["user-agent"]
            try:
                ua = parse(ua_str)
                device = str(ua)
            except Exception:
                device = "Unknown"
        self.logger.debug("requesters device is %s", device)

        email: Optional[EmailStr] = None
        user_id: Optional[str] = None
        try:
            email = validate_email(identifier).email
        except EmailNotValidError:
            user_id = identifier
            try:
                user_id = custom_charset(None, user_id)
                user_id = starts_with("usr:")(None, user_id)
            except Exception as exception:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="incorrect identifier",
                )

        await self.run_async()
        try:
            if email:
                user = await self.database.fetch_one(
                    sa.sql.select(
                        [self.users.c.user_uuid, self.users.c.hashed_password]
                    ).where(
                        self.users.c.email == email
                    )
                )
            else:
                user = await self.database.fetch_one(
                    sa.sql.select(
                        [self.users.c.user_uuid, self.users.c.hashed_password]
                    ).where(
                        self.users.c.user_id == user_id
                    )
                )
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An error occurred when working with Auth DB. "
                       "Check logs for more information.",
            )

        user_uuid = user["user_uuid"]
        hashed_password = user["hashed_password"]

        if not crypto_context.verify(password, hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect password"
            )

        now: datetime.datetime = datetime.datetime.now()
        token_uuid: bytes = uuid.uuid4().bytes

        insert = self.tokens.insert().values(
            token_uuid=token_uuid,
            location=location,
            device=device,
            issued_by=user_uuid,
            issued_at=str(now),
        )

        try:
            await self.database.execute(insert)
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An error occurred when working with Auth DB. "
                       "Check logs for more information.",
            )

        header: Dict[str, str] = {"alg": "ES384", "typ": "JWT"}
        payload: Dict[str, Any] = {
            "iss": "paperback",
            "sub": str(uuid.UUID(bytes=user_uuid)),
            "exp": str(now + datetime.timedelta(days=2)),
            "iat": str(now),
            "jti": str(uuid.UUID(bytes=token_uuid)),
        }
        self.logger.debug("created token %s for user %s", payload, user_id)
        return jwt.encode(header, payload, self.private_key)

    async def signup(self, user: NewInvitedUser) -> str:
        pass

    async def signout(self, user: UserInfo) -> NoReturn:
        pass

    async def signout_everywhere(self) -> NoReturn:
        pass

    async def read_tokens(self, username: str) -> List[str]:
        pass

    async def delete_token(self, token: str) -> NoReturn:
        pass

    async def delete_tokens(self, token: List[str]) -> NoReturn:
        pass

    async def create_user(
        self,
        user_id: str,
        email: EmailStr,
        password: str,
        level_of_access: int = 0,
        organisation_id: Optional[str] = None,
        user_name: Optional[str] = None,
    ) -> Dict[str, Union[str, int, Any]]:
        await self.run_async()

        org = await self.database.fetch_all(
            self.organisations.select().where(
                self.organisations.c.organisation_id == organisation_id
            )
        )

        if len(org) == 0:
            self.logger.error(
                "can't find organisation with id %s", organisation_id
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"can't find organisation with id {organisation_id}",
            )

        user = await self.database.fetch_all(
            self.users.select().where(
                self.users.c.user_id == user_id
            )
        )
        if len(user) > 0:
            self.logger.error(
                "user with id %s already exists", user_id
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"user with id {user_id} already exists",
            )

        new_user = {
            "user_id": user_id,
            "user_name": user_name,
            "email": email,
            "level_of_access": level_of_access,
            "hashed_password": crypto_context.hash(password),
            "user_uuid": uuid.uuid4().bytes,
            "users_organisation_uuid": org[0]["organisation_uuid"],
        }
        self.logger.debug("creating user with this info: %s", new_user)
        insert = self.users.insert().values(**new_user)

        try:
            await self.database.execute(insert)
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An error occurred when working with Auth DB. "
                       "Check logs for more information.",
            )
        return dict(**new_user, organisation_id=org[0]["organisation_id"])

    async def read_user(self, user_id: str) -> UserInfo:
        await self.run_async()

        self.logger.debug("querying all user")
        select = sa.sql.select([self.users, self.organisations]).where(
            self.users.c.user_id == user_id
        )

        try:
            user = await self.database.fetch_one(select)
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An error occurred when working with Auth DB. "
                       "Check logs for more information.",
            )
        return user

    async def read_users(self) -> List[Dict[str, Union[str, int]]]:
        await self.run_async()

        self.logger.debug("querying all user")
        select = sa.sql.select([self.users, self.organisations])

        try:
            users = await self.database.fetch_all(select)
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An error occurred when working with Auth DB. "
                       "Check logs for more information.",
            )
        return users

    async def update_user(
        self,
        username: str,
        new_username: Optional[str] = None,
        new_user_name: Optional[str] = None,
        new_level_of_access: Optional[int] = None,
        new_organisation: Optional[str] = None,
    ) -> NoReturn:
        pass

    async def update_user_password(
        self,
        username: str,
        old_passwords: Optional[str] = None,
        new_password: Optional[str] = None,
    ) -> Dict[str, Union[str, int]]:
        pass

    async def update_user_email(
        self, username: str, new_email: str
    ) -> Dict[str, Union[str, uuid.UUID]]:
        pass

    async def delete_user(self, username: str) -> NoReturn:
        pass

    async def create_org(
        self, org: MinimalOrganisation, name: Optional[str] = None,
    ) -> Dict[str, Union[str, List[str]]]:
        # check if org with this id exists
        self.logger.debug("checking for %s organisation", org.organisation_id)
        select_orgs_with_same_id = self.organisations.select().where(
            self.organisations.c.organisation_id == org.organisation_id
        )
        orgs_with_same_id = await self.database.fetch_all(
            select_orgs_with_same_id
        )
        if len(orgs_with_same_id) > 0:
            self.logger.debug(
                "organisation with id %s already exists", org.organisation_id
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"organisation with given organisation_id ({org.organisation_id}) already exists",
            )
        else:
            self.logger.debug(
                "organisation with id %s doesn't exist", org.organisation_id
            )

        # create organisation
        self.logger.debug(
            "creating organisation with id %s", org.organisation_id
        )
        new_org = {
            "uuid": uuid.uuid4().bytes,
            "organisation_id": org.organisation_id,
            "name": org.organisation_name,
        }
        insert = self.organisations.insert().values(**new_org)

        try:
            await self.database.execute(insert)
            self.logger.debug(
                "created organisation with id %s", org.organisation_id
            )
        except Exception as exception:
            self.logger.debug(
                "can't created organisation with id %s", org.organisation_id
            )
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="""An error occurred when working with Auth DB.
                        Check logs for more information.""",
            )
        return new_org

    async def read_org(self, org_id: str) -> Organisation:
        pass

    async def read_orgs(
        self, columns: Optional[List[str]] = None
    ) -> List[MinimalOrganisation]:
        pass

    async def update_org(
        self,
        old_organisation_id: str,
        new_organisation_id: Optional[str] = None,
        new_name: Optional[str] = None,
    ):
        pass

    async def delete_org(self, org_name: str):
        pass

    async def create_invite_code(
        self, issuer: str, organisation_id: str
    ) -> str:
        pass

    async def read_invite_code(self, code: str) -> InviteCode:
        pass

    async def read_invite_codes(self) -> List[InviteCode]:
        pass

    async def delete_invite_codes(self, code: str):
        pass

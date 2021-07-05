import datetime
import logging
import re
import uuid
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

import ecdsa
import sqlalchemy as sa
from authlib.jose import jwt
from databases import Database
from email_validator import EmailNotValidError, validate_email
from fastapi import HTTPException, Request, status
from ipstack import GeoLookup
from paperback.abc import BaseAuth
from paperback.abc.models import custom_charset
from pydantic import EmailStr
from user_agents import parse

from .crypto import crypto_context


class AuthImplemented(BaseAuth):
    DEFAULTS: Mapping[str, Union[str, Mapping[str, Union[str, bool]]]] = {
        "IPstack_api_key": "",
        "root": {
            "username": "root",
            "password": "root",
        },
        "db": {
            "host": "127.0.0.1",
            "port": "5432",
            "username": "postgres",
            "password": "password",
            "db": "papertext",
        },
        "hash": {"algo": "pbkdf2_sha512"},
        "token": {"curve": "secp521r1", "generate_keys": False,},
    }

    requires_dir: bool = True

    def __init__(self, cfg: SimpleNamespace, storage_dir: Path):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.getLogger("paperback").level)
        self.logger.info("initializing papertext_auth module")

        self.logger.debug("using storage dir %s", storage_dir)
        self.logger.debug("using config %s", cfg)
        self.storage_dir: Path = storage_dir
        self.cfg: SimpleNamespace = cfg
        # TODO: add check for configuration,
        #  i.e. that hash.algo lib and token.curve lib are present

        self.logger.debug("updating crypto context")
        crypto_context.update(default=cfg.hash.algo)
        self.logger.info("updated crypto context")

        self.logger.debug("connecting to ipstack")
        self.ip2geo: GeoLookup = GeoLookup(cfg.IPstack_api_key)
        self.logger.info("connected to ipstack")

        self.logger.debug("getting JWT keys")

        self.private_key_file: Path = self.storage_dir / "private.pem"
        self.public_key_file: Path = self.storage_dir / "public.pem"
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

        self.logger.info("acquired JWT keys")

        self.logger.debug("setting up database")
        database_url: str = f"postgresql://{self.cfg.db.username}:{self.cfg.db.password}@" f"{self.cfg.db.host}:{self.cfg.db.port}/{self.cfg.db.db}"
        self.logger.debug("database url: %s", database_url)
        self.logger.debug("connecting to database")
        self.database: Database = Database(database_url)
        self.logger.debug("connected to database")
        self.engine: sa.engine.Engine = sa.create_engine(database_url)

        self.logger.debug("setting up tables")
        self.metadata: sa.MetaData = sa.MetaData(bind=self.engine)

        self.users: sa.Table = sa.Table(
            "users",
            self.metadata,
            sa.Column(
                "user_id", sa.String(256), unique=True, primary_key=True
            ),
            sa.Column("email", sa.String(256), unique=True, nullable=True),
            sa.Column("hashed_password", sa.Text()),
            sa.Column("user_name", sa.String(256)),
            sa.Column("level_of_access", sa.Integer()),
            sa.Column(
                "member_of",
                sa.String(256),
                sa.ForeignKey("organisations.organisation_id"),
            ),
            extend_existing=True,
        )
        self.organisations: sa.Table = sa.Table(
            "organisations",
            self.metadata,
            sa.Column(
                "organisation_id",
                sa.String(256),
                unique=True,
                primary_key=True,
            ),
            sa.Column("organisation_name", sa.Text()),
            extend_existing=True,
        )
        self.tokens = sa.Table(
            "tokens",
            self.metadata,
            sa.Column(
                "token_uuid", sa.LargeBinary(16), primary_key=True, unique=True
            ),
            sa.Column("location", sa.Text()),
            sa.Column("device", sa.Text()),
            sa.Column(
                "issued_by", sa.String(256), sa.ForeignKey("users.user_id"),
            ),
            sa.Column("issued_at", sa.Text()),
            extend_existing=True,
        )
        self.invitation_codes = sa.Table(
            "invitation_codes",
            self.metadata,
            sa.Column(
                "invitation_code_uuid",
                sa.LargeBinary(16),
                primary_key=True,
                unique=True,
            ),
            sa.Column("code", sa.Text(), unique=True,),
            sa.Column(
                "issuer_id", sa.String(256), sa.ForeignKey("users.user_id"),
            ),
            sa.Column(
                "add_to",
                sa.String(256),
                sa.ForeignKey("organisations.organisation_id"),
            ),
            sa.Column("used_times", sa.Integer,),
            extend_existing=True,
        )
        self.metadata.create_all(self.engine)

        self.logger.info("set up tables")

        self.logger.debug("creating publiv organisation")
        self.public_org: Dict[str, str] = self.create_public_org()
        self.logger.info("created publiv organisation")

    def create_public_org(self) -> Dict[str, str]:
        self.logger.debug("creating basic organisation")
        conn = self.engine.connect()
        select_org_with_same_id = self.organisations.select().where(
            self.organisations.c.organisation_id == self.public_org_id
        )
        org_with_same_id = conn.execute(select_org_with_same_id).fetchone()
        if org_with_same_id is not None:
            self.logger.debug(
                "public organisation %s already exists", dict(org_with_same_id)
            )
            conn.close()
            return dict(org_with_same_id)
        else:
            self.logger.debug("public organisation doesn't exist")
            org = {
                "organisation_id": self.public_org_id,
                "organisation_name": "Публичная организация",
            }
            insert = self.organisations.insert().values(**org)
            conn.execute(insert)
            self.logger.debug("created public organisation %s", org)
            conn.close()
            return org

    async def create_root_user(self, username: str, password: str, public_org_id: str) -> Dict[str, str]:
        self.logger.debug("creating root user")

        users_with_same_name = await self.database.fetch_all(
            self.users.select().where(self.users.c.user_id == username)
        )

        if len(users_with_same_name) > 1:
            self.logger.error("found multiple users with root user_id %s", username)
            raise Exception(f"found multiple users with root user_id {username}")
        elif len(users_with_same_name) == 1:
            root_user = users_with_same_name[0]
            self.logger.info("root user_id %s already exists", username)
            loa = root_user["level_of_access"]
            if loa < 3:
                self.logger.error("root user doesn't have correct level of access")
                raise Exception("root user doesn't have correct level of access")
        elif len(users_with_same_name) == 0:
            self.logger.info("creating root user with %s user_id", username)
            root_user = {
                "user_id": username,
                "email": "root@papertext.ru",
                "hashed_password": crypto_context.hash(password),
                "user_name": "root",
                "level_of_access": 3,
                "member_of": public_org_id,
            }
            insert = self.users.insert().values(**root_user)
            try:
                await self.database.execute(insert)
            except Exception as exception:
                self.logger.info("can't create root user")
                self.logger.error(exception)
                raise
            self.logger.debug("created new root user")
            return root_user

    async def __async__init__(self):
        self.logger.info("connected to Auth DB")
        await self.database.connect()
        self.logger.debug("connected to Auth DB")

        self.logger.debug("creating root user")
        self.root_user: Dict[str, str] = await self.create_root_user(**self.cfg.root, public_org_id=self.public_org_id)
        self.logger.info("created root user")

    def generate_keys(self, curve: str) -> Tuple[bytes, bytes]:
        def default():
            self.logger.error("can't find specified curve")
            raise KeyError("can't find specified curve")

        def secp521r1():
            self.logger.debug("creating secp521r1 keys")
            sk: ecdsa.SigningKey = ecdsa.SigningKey.generate(
                curve=ecdsa.NIST521p
            )
            vk: ecdsa.VerifyingKey = sk.verifying_key
            sk_bytes: bytes = bytes(sk.to_pem())
            vk_bytes: bytes = bytes(vk.to_pem())
            return sk_bytes, vk_bytes

        case: Dict[str, Callable[..., Tuple[bytes, bytes]]] = defaultdict(
            default
        )
        case["secp521r1"] = secp521r1
        return case[curve]()

    def read_keys(self, curve: str) -> Tuple[bytes, bytes]:
        def default():
            self.logger.error("can't find specified curve")
            raise KeyError("can't find specified curve")

        def secp521r1():
            self.logger.debug("creating secp521r1 keys")
            sk: ecdsa.SigningKey = ecdsa.SigningKey.from_pem(  # noqa
                self.private_key_file.read_text()
            )
            vk: ecdsa.VerifyingKey = sk.verifying_key
            sk_bytes: bytes = bytes(sk.to_pem())
            vk_bytes: bytes = bytes(vk.to_pem())
            return sk_bytes, vk_bytes

        case: Dict[str, Callable[..., Tuple[bytes, bytes]]] = defaultdict(
            default
        )
        case["secp521r1"] = secp521r1
        return case[curve]()

    def validate_token(self, token: str) -> Dict[str, Any]:
        claim_option: Dict[str, Dict[str, Any]] = {
            "iss": {"essential": True, "values": ["paperback"],},
            "sub": {"essential": True,},
            "exp": {"essential": True,},
            "jti": {"essential": True,},
        }
        try:
            claims = jwt.decode(
                token, self.public_key, claims_options=claim_option
            )
            claims.validate()
        except Exception as exception:
            self.logger.debug(token)
            self.logger.error("can't verify token")
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "end": "can't verify token",
                    "rus": "невозможно верефецировать токен",
                },
            )
        token_uuid = uuid.UUID(claims["jti"]).bytes

        conn = self.engine.connect()
        select = self.tokens.select().where(
            self.tokens.c.token_uuid == token_uuid
        )
        tokens = conn.execute(select).fetchall()
        if len(tokens) == 0:
            self.logger.debug(token)
            self.logger.error("can't verify token")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "end": "can't verify token",
                    "rus": "токен был удалён",
                },
            )
        return claims

    def token2user(self, token: str) -> Dict[str, Union[str, int]]:
        claims = self.validate_token(token)

        user_id: str = claims["sub"]

        conn = self.engine.connect()
        user = conn.execute(
            self.users.select().where(self.users.c.user_id == user_id)
        ).fetchone()
        conn.close()

        user_dict: Dict[str, Any] = {
            "user_id": user["user_id"],
            "user_name": user["user_name"],
            "email": user["email"],
            "level_of_access": user["level_of_access"],
            "member_of": user["member_of"],
        }

        self.logger.debug("decoded token %s for user %s", claims, user_dict)
        return user_dict

    def cleanup_tokens(self):
        self.logger.debug("removing expired tokens")
        conn = self.engine.connect()
        result = conn.execute(
            sa.sql.select([self.tokens.c.token_uuid, self.tokens.c.issued_at])
        )
        for row in result:
            issued_at = datetime.datetime.fromisoformat(row["issued_at"])
            delta = datetime.datetime.now() - issued_at
            self.logger.debug(
                f"selected token with {row['token_uuid']=}"
                f"{issued_at=} {delta=}"
            )
            # delete tokens older than 2 days and 2 hours
            if delta.total_seconds() >= (24 * 2 + 2) * 60 * 60:
                self.logger.debug(
                    f"removing token with uuid {row['token_uuid']}"
                )
                conn.execute(
                    self.tokens.delete().where(
                        self.tokens.c.token_uuid == row["token_uuid"]
                    )
                )
        conn.close()

    async def signin(
        self,
        request: Request,
        password: str,
        identifier: Union[str, EmailStr],
    ) -> str:
        location: str = "Unknown"
        if "x-real-ip" in request.headers:
            real_ip: str = request.headers["x-real-ip"]
            self.logger.debug("requesters IP address is %s", real_ip)
            try:
                ipstack_res: Dict = self.ip2geo.get_location(real_ip)
                location = (
                    f"{ipstack_res['location']['country_flag_emoji']} "
                    f"{ipstack_res['city']} / "
                    f"{ipstack_res['region_name']} / "
                    f"{ipstack_res['country_name']}"
                )
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
            except Exception as exception:
                self.logger.error(exception)
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "rus": "incorrect identifier",
                        "eng": "неправльный идентификатор",
                    },
                )

        try:
            if email:
                user = await self.database.fetch_one(
                    sa.sql.select(
                        [self.users.c.hashed_password, self.users.c.user_id]
                    ).where(self.users.c.email == email)
                )
                user_id = user["user_id"]
            else:
                user = await self.database.fetch_one(
                    sa.sql.select([self.users.c.hashed_password]).where(
                        self.users.c.user_id == user_id
                    )
                )
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )

        hashed_password = user["hashed_password"]

        if not crypto_context.verify(password, hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "end": "Incorrect password",
                    "rus": "Неправильный пароль",
                },
            )

        now: datetime.datetime = datetime.datetime.now()
        token_uuid: bytes = uuid.uuid4().bytes

        insert = self.tokens.insert().values(
            token_uuid=token_uuid,
            location=location,
            device=device,
            issued_by=user_id,
            issued_at=str(now),
        )

        try:
            await self.database.execute(insert)
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )

        header: Dict[str, str] = {"alg": "ES384", "typ": "JWT"}
        payload: Dict[str, Any] = {
            "iss": "paperback",
            "sub": str(user_id),
            "exp": int(
                round((now + datetime.timedelta(days=2)).timestamp(), 0)
            ),
            "iat": int(round(now.timestamp(), 0)),
            "jti": str(uuid.UUID(bytes=token_uuid)),
        }
        self.logger.debug("created token %s for user %s", payload, user_id)
        return jwt.encode(header, payload, self.private_key)

    async def signup(
        self,
        request: Request,
        user_id: str,
        email: EmailStr,
        password: str,
        invitation_code: str,
        user_name: Optional[str] = None,
    ) -> str:
        pass

    # async def signout(self, token: str): pass

    async def signout_everywhere(self, user_id: str):
        pass

    async def read_tokens(self, user_id: str):
        self.logger.debug("querying all tokens of user with id %s", user_id)
        select = self.tokens.select().where(self.tokens.c.issued_by == user_id)

        try:
            raw_tokens = await self.database.fetch_all(select)
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )
        tokens = [dict(raw_token) for raw_token in raw_tokens]
        return tokens

    async def delete_token(self, token_identifier: str):
        match = re.match(
            r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}"
            r"-[a-fA-F0-9]{12}$",
            token_identifier,
        )
        if match is None:
            claims = self.validate_token(token_identifier)
            token_uuid = claims["jti"]
            self.logger.debug("removing token by uuid %s", token_uuid)
        else:
            token_uuid = token_identifier
            self.logger.debug("removing token by uuid %s", token_uuid)
        token_uuid = uuid.UUID(token_uuid).bytes

        tokens = await self.database.fetch_all(
            self.tokens.select().where(self.tokens.c.token_uuid == token_uuid)
        )
        if len(tokens) == 0:
            self.logger.error("users with uuid %s doesn't exists", token_uuid)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": f"token with uuid {token_uuid} doesn't exists",
                    "rus": f"токен с uuid {token_uuid} не существует",
                },
            )

        try:
            await self.database.execute(
                self.tokens.delete().where(
                    self.tokens.c.token_uuid == token_uuid
                )
            )
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )

    async def create_user(
        self,
        user_id: str,
        password: str,
        level_of_access: int = 0,
        email: Optional[EmailStr] = None,
        member_of: Optional[str] = None,
        user_name: Optional[str] = None,
    ) -> Dict[str, Union[str, int, Any]]:
        self.logger.debug(
            "creating user: %s",
            {
                "user_id": user_id,
                "password": password,
                "level_of_access": level_of_access,
                "email": email,
                "member_of": member_of,
                "user_name": user_name,
            },
        )

        users = await self.database.fetch_all(
            self.users.select().where(self.users.c.user_id == user_id)
        )
        if len(users) > 0:
            self.logger.error("users with id %s already exists", user_id)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": f"users with id {user_id} already exists",
                    "rus": f"пользователь с id {user_id} уже существует",
                },
            )

        if not member_of:
            member_of = self.public_org_id
        else:
            org = await self.database.fetch_all(
                self.organisations.select().where(
                    self.organisations.c.organisation_id == member_of
                )
            )

            if len(org) == 0:
                self.logger.error(
                    "can't find organisation with id %s", member_of
                )
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "end": f"can't find organisation with id {member_of}",
                        "rus": f"организации с id {member_of} не существует",
                    },
                )
            else:
                member_of = org[0]["organisation_id"]

        new_user = {
            "user_id": user_id,
            "email": email,
            "hashed_password": crypto_context.hash(password),
            "user_name": user_name,
            "level_of_access": level_of_access,
            "member_of": member_of,
        }
        insert = self.users.insert().values(**new_user)

        self.logger.debug("creating users with this info: %s", new_user)
        try:
            await self.database.execute(insert)
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )
        return new_user

    async def read_user(self, user_id: str) -> Dict[str, Any]:
        self.logger.debug("querying user with id %s", user_id)
        select = self.users.select().where(self.users.c.user_id == user_id)

        try:
            user = await self.database.fetch_one(select)
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )
        return dict(user)

    async def read_users(self) -> List[Dict[str, Union[str, int]]]:
        self.logger.debug("querying all user")
        select = self.users.select()

        try:
            raw_users = await self.database.fetch_all(select)
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )
        users: List[Dict] = [dict(user) for user in raw_users]
        return users

    async def update_user(
        self,
        user_id: str,
        new_user_id: Optional[str] = None,
        new_user_name: Optional[str] = None,
        new_level_of_access: Optional[int] = None,
        new_organisation_id: Optional[str] = None,
    ) -> Dict[str, Union[str, int]]:
        if new_user_id is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "eng": f"can't update users id",
                    "rus": f"невозможно обновить id пользователя",
                },
            )

        values: Dict[str, Any] = {
            "user_id": new_user_id,
            "user_name": new_user_name,
            "level_of_access": new_level_of_access,
            "organisation_id": new_organisation_id,
        }
        new_values: Dict[str, Any] = {
            key: val for key, val in values.items() if val is not None
        }

        users = await self.database.fetch_all(
            self.users.select().where(self.users.c.user_id == user_id)
        )
        if len(users) == 0:
            self.logger.error("users with id %s doesn't exists", user_id)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": f"users with id {user_id} doesn't exists",
                    "rus": f"пользователь с id {user_id} не существует",
                },
            )

        self.logger.debug("updating user with id %s", user_id)
        update = (
            self.users.update()
            .where(self.users.c.user_id == user_id)
            .values(**new_values)
        )

        try:
            await self.database.execute(update)
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )

        try:
            user = await self.database.fetch_one(
                self.users.select().where(self.users.c.user_id == user_id)
            )
            if user is None:
                raise ValueError
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )
        user = dict(user)
        del user["hashed_password"]
        return user

    async def update_user_password(
        self,
        user_id: str,
        old_password: Optional[str] = None,
        new_password: Optional[str] = None,
    ) -> Dict[str, Union[str, int]]:
        current_hash: str = crypto_context.hash(old_password)
        new_hash: str = crypto_context.hash(new_password)

        users = await self.database.fetch_all(
            self.users.select().where(self.users.c.user_id == user_id)
        )
        if len(users) == 0:
            self.logger.error("users with id %s doesn't exists", user_id)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": f"users with id {user_id} doesn't exists",
                    "rus": f"пользователь с id {user_id} не существует",
                },
            )

        user = users[0]
        old_hash: str = user["hashed_password"]

        if current_hash != old_hash:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": f"incorrect password",
                    "rus": f"неправильный пароль",
                },
            )

        self.logger.debug(
            "updating password of user with id %s", user["user_id"]
        )
        update = (
            self.users.update()
            .where(self.users.c.user_id == user_id)
            .values(hashed_password=new_hash)
        )

        try:
            await self.database.execute(update)
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )

        try:
            user = await self.database.fetch_one(
                self.users.select().where(self.users.c.user_id == user_id)
            )
            if user is None:
                raise ValueError
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )
        user = dict(user)
        del user["hashed_password"]
        return user

    async def update_user_email(
        self, user_id: str, new_email: EmailStr
    ) -> Dict[str, Union[str, int]]:
        if new_email is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "eng": f"can't update users email",
                    "rus": f"невозможно обновить email пользователя",
                },
            )

    async def delete_user(self, user_id: str):
        users = await self.database.fetch_all(
            self.users.select().where(self.users.c.user_id == user_id)
        )
        if len(users) == 0:
            self.logger.error("users with id %s doesn't exists", user_id)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": f"users with id {user_id} doesn't exists",
                    "rus": f"пользователь с id {user_id} не существует",
                },
            )

        try:
            await self.database.execute(
                self.users.delete().where(self.users.c.user_id == user_id)
            )
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )

    async def create_org(
        self, organisation_id: str, organisation_name: Optional[str] = None,
    ) -> Dict[str, Union[str, List[str]]]:
        # check if org with given this id exists
        self.logger.debug(
            "checking for organisation with id %s", organisation_id
        )
        select_orgs_with_same_id = self.organisations.select().where(
            self.organisations.c.organisation_id == organisation_id
        )
        orgs_with_same_id = await self.database.fetch_all(
            select_orgs_with_same_id
        )
        if len(orgs_with_same_id) > 0:
            self.logger.debug(
                "organisation with id %s already exists", organisation_id
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": f"organisation with given organisation_id ({organisation_id}) already exists",
                    "rus": f"организация с данным идентификатором ({organisation_id}) уже существует",
                },
            )
        else:
            self.logger.debug(
                "organisation with id %s doesn't exist", organisation_id
            )

        # create organisation
        self.logger.debug("creating organisation with id %s", organisation_id)
        new_org = {
            "uuid": uuid.uuid4().bytes,
            "member_of": organisation_id,
            "name": organisation_name,
        }
        insert = self.organisations.insert().values(**new_org)

        try:
            await self.database.execute(insert)
            self.logger.debug(
                "created organisation with id %s", organisation_id
            )
        except Exception as exception:
            self.logger.debug(
                "can't created organisation with id %s", organisation_id
            )
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )
        return new_org

    async def read_org(
        self, organisation_id: str
    ) -> Dict[str, Union[str, List[str]]]:
        self.logger.debug("querying organisation with id %s", organisation_id)
        select = self.organisations.select().where(
            self.organisations.c.organisation_id == organisation_id
        )

        try:
            org = await self.database.fetch_one(select)
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )
        return dict(org)

    async def read_orgs(
        self, columns: Optional[List[str]] = None
    ) -> List[Dict[str, str]]:
        self.logger.debug("querying all organisations")
        try:
            raw_orgs = await self.database.fetch_all(
                self.organisations.select()
            )
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )
        orgs: List[Dict] = [dict(org) for org in raw_orgs]
        return orgs

    async def update_org(
        self,
        old_organisation_id: str,
        new_organisation_id: Optional[str] = None,
        new_organisation_name: Optional[str] = None,
    ) -> Dict[str, str]:
        if new_organisation_id is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "eng": f"can't update organisation id",
                    "rus": f"невозможно обновить id организации",
                },
            )

        values: Dict[str, Any] = {
            "new_organisation_name": new_organisation_name,
            "new_organisation_id": new_organisation_id,
        }
        new_values: Dict[str, Any] = {
            key: val for key, val in values.items() if val is not None
        }

        orgs = await self.database.fetch_all(
            self.organisations.select().where(
                self.organisations.c.organisation_id == old_organisation_id
            )
        )
        if len(orgs) == 0:
            self.logger.error(
                "users with id %s doesn't exists", old_organisation_id
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": f"organisation with id {old_organisation_id} doesn't exists",
                    "rus": f"организации с id {old_organisation_id} не существует",
                },
            )

        self.logger.debug(
            "updating organisation with id %s", old_organisation_id
        )
        update = (
            self.organisations.update()
            .where(self.organisations.c.organisation_id == old_organisation_id)
            .values(**new_values)
        )

        try:
            await self.database.execute(update)
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )

        try:
            org = await self.database.fetch_one(
                self.organisations.select().where(
                    self.organisations.c.organisation_id == old_organisation_id
                )
            )
            if org is None:
                raise ValueError
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )
        return dict(org)

    async def delete_org(self, organisation_id: str):
        orgs = await self.database.fetch_all(
            self.organisations.select().where(
                self.organisations.c.organisation_id == organisation_id
            )
        )
        if len(orgs) == 0:
            self.logger.error(
                "users with id %s doesn't exists", organisation_id
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": f"organisation with id {organisation_id} doesn't exists",
                    "rus": f"организации с id {organisation_id} не существует",
                },
            )

        self.logger.debug("updating organisation with id %s", organisation_id)
        delete = self.organisations.delete().where(
            self.organisations.c.organisation_id == organisation_id
        )

        try:
            await self.database.execute(delete)
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )

    async def create_invite_code(
        self, issuer: str, code: str, add_to: str
    ) -> Dict[str, Any]:
        codes = await self.database.fetch_all(
            self.invitation_codes.select().where(
                self.invitation_codes.c.code == code
            )
        )
        if len(codes) > 0:
            self.logger.error("code %s already exists", code)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": f"code {code} already exists",
                    "rus": f"код {code} уже существует",
                },
            )

        org = await self.database.fetch_all(
            self.organisations.select().where(
                self.organisations.c.organisation_id == add_to
            )
        )

        if len(org) < 0:
            self.logger.error("can't find organisation with id %s", add_to)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "end": f"can't find organisation with id {add_to}",
                    "rus": f"организации с id {add_to} не существует",
                },
            )

        new_code = {
            "invitation_code_uuid": uuid.uuid4(),
            "code": code,
            "issuer_id": issuer,
            "add_to": add_to,
        }
        insert = self.invitation_codes.insert().values(**new_code)

        self.logger.debug("creating users with this info: %s", new_code)
        try:
            await self.database.execute(insert)
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )
        return new_code

    async def read_invite_code(self, code: str) -> Dict[str, str]:
        self.logger.debug("querying invitatiom_code with code %s", code)
        select = self.invitation_codes.select().where(
            self.invitation_codes.c.code == code
        )

        try:
            code = await self.database.fetch_one(select)
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )
        return dict(code)

    async def read_invite_codes(self) -> List[Dict[str, str]]:
        self.logger.debug("querying all codes")
        select = self.invitation_codes.select()

        try:
            raw_codes = await self.database.fetch_all(select)
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )
        codes: List[Dict] = [dict(code) for code in raw_codes]
        return codes

    async def delete_invite_code(self, code: str):
        codes = await self.database.fetch_all(
            self.invitation_codes.select().where(
                self.invitation_codes.c.code == code
            )
        )
        if len(codes) == 0:
            self.logger.error(
                "invitation_code with code %s doesn't exists", code
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": f"invitation_code with code {code} doesn't exists",
                    "rus": f"кода приглашения с кодом {code} не существует",
                },
            )

        try:
            await self.database.execute(
                self.invitation_codes.delete().where(
                    self.invitation_codes.c.code == code
                )
            )
        except Exception as exception:
            self.logger.error(exception)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "eng": "An error occurred when working with Auth DB",
                    "rus": "Произошла ошибка при обращении к базе данных "
                    "модуля авторизации",
                },
            )

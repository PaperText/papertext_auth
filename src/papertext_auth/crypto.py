from passlib.context import CryptContext

crypt_context = CryptContext(
    schemes=["argon2", "pbkdf2_sha512", "bcrypt"],
    deprecated="auto",
    argon2__max_threads=-1,
    argon2__rounds=15,
    pbkdf2_sha512__rounds=30_000,
    pbkdf2_sha512__salt_size=32,
    bcrypt__rounds=15,
)

from authlib.jose import jwk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.config import Config

from .gino_app import load_entry_point


def load_private_key(payload):
    if not payload.startswith("-----BEGIN PRIVATE KEY-----"):
        try:
            with open(payload) as f:
                payload = f.read()
        except FileNotFoundError:
            with open(payload, "w") as f:
                assert JWT_KEY_ALGORITHM == "RSA"
                payload = (
                    rsa.generate_private_key(
                        public_exponent=65537, key_size=1024, backend=default_backend()
                    )
                    .private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                    .decode()
                )
                f.write(payload)
    return jwk.dumps(
        payload, kty=JWT_KEY_ALGORITHM, use="sig", kid=JWT_KEY_ID, alg=JWT_ALGORITHM
    )


def get_public_key(private_key):
    return jwk.dumps(
        jwk.loads(private_key)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode(),
        kty=JWT_KEY_ALGORITHM,
        use="sig",
        kid=JWT_KEY_ID,
        alg=JWT_ALGORITHM,
    )


config = load_entry_point("config", Config)

DEBUG = config("DEBUG", cast=bool, default=True)
USE_DEMO_LOGIN = config("USE_DEMO_LOGIN", cast=bool, default=True)

JWT_ISSUER = config("JWT_ISSUER", default="http://localhost:8000")
JWT_ALGORITHM = config("JWT_ALGORITHM", default="RS256")
JWT_KEY_ALGORITHM = config(
    "JWT_KEY_ALGORITHM", default=dict(RS="RSA", ES="EC").get(JWT_ALGORITHM[:2], "oct")
)
JWT_KEY_ID = config("JWT_KEY_ID", default="initial")
JWT_PRIVATE_KEY = config(
    "JWT_PRIVATE_KEY", cast=load_private_key, default=".jwt-private-key.pem",
)
JWT_PUBLIC_KEY = get_public_key(JWT_PRIVATE_KEY)
JWT_AUTH_CODE_TTL = config("JWT_AUTH_CODE_TTL", cast=int, default=300)  # 5 minutes
JWT_TOKEN_TTL = config("JWT_TOKEN_TTL", cast=int, default=1800)  # 30 minutes

SESSION_TTL = config("SESSION_TTL", cast=int, default=100)  # 100 days

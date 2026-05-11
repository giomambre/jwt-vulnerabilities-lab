from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


KEY_DIR = Path(__file__).resolve().parent / "keys"
TASK2_PRIVATE_KEY = KEY_DIR / "task2_private.pem"
TASK2_PUBLIC_KEY = KEY_DIR / "task2_public.pem"
TASK3_DEFAULT_KEY = KEY_DIR / "task3-default.key"


def ensure_key_material() -> None:
    KEY_DIR.mkdir(parents=True, exist_ok=True)

    if not TASK3_DEFAULT_KEY.exists():
        TASK3_DEFAULT_KEY.write_text("task3-default-teaching-secret\n", encoding="utf-8")

    if TASK2_PRIVATE_KEY.exists() and TASK2_PUBLIC_KEY.exists():
        return

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    TASK2_PRIVATE_KEY.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    TASK2_PUBLIC_KEY.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def read_task2_private_key() -> str:
    ensure_key_material()
    return TASK2_PRIVATE_KEY.read_text(encoding="utf-8")


def read_task2_public_key() -> str:
    ensure_key_material()
    return TASK2_PUBLIC_KEY.read_text(encoding="utf-8")

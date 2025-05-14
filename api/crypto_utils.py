import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from api.conf import PASSWORD_HASH_ITERATIONS, PASSWORD_HASH_LENGTH, AES_KEY
import base64
import binascii
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets


def hash_password(password):
    """
    Hashes a password using PBKDF2HMAC with SHA256 algorithm and random salt.

    Args:
        password (str): The password to hash.

    Returns:
        Dictionary containing the base64 encoded salt and hashed password
        strings.
    """
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PASSWORD_HASH_LENGTH,
        salt=salt,
        iterations=PASSWORD_HASH_ITERATIONS,
    )

    password_hash = kdf.derive(password.encode("utf-8"))

    return {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "hash": base64.b64encode(password_hash).decode("utf-8"),
    }


def verify_password(password, stored_salt, stored_hash):
    """
    Verify a password against stored salt and password hash.

    Args:
        password: String password to verify.
        stored_salt: Base64 encoded stored salt string.
        stored_hash: Base64 encoded stored password hash string.

    Returns:
        True if password matches stored salt and password hash, otherwise False.
    """

    # Decode the salt and password hash stored as string.
    salt = base64.b64decode(stored_salt)
    password_hash = base64.b64decode(stored_hash)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PASSWORD_HASH_LENGTH,
        salt=salt,
        iterations=PASSWORD_HASH_ITERATIONS,
    )

    try:
        kdf.verify(password.encode("utf-8"), password_hash)
        return True
    except InvalidKey:
        return False


def encrypt_personal_data(personal_data):
    """
    Encrypt personal data using AES-GCM.
    AES-GCM uses CTR mode (encryption) and Galois Mode (authentication)

    Args:
        personal_data: String data to encrypt
    Returns:
        Dictionary with nonce and encrypted data in base64 encoding
    """

    # 96-bits nonce
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(AES_KEY)

    encrypted_data = aesgcm.encrypt(
        nonce=nonce, data=personal_data.encode("utf-8"), associated_data=None,
    )

    return {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "encrypted_data": base64.b64encode(encrypted_data).decode("utf-8"),
    }


def decrypt_personal_data(encrypted_obj):
    """
    Decrypt personal data using AES-GCM.

    Args:
        encrypted_obj: Dictionary with nonce and encrypted data strings in
        base64 encoding

    Returns:
        Decrypted data as string
    """

    if (
            encoded_nonce := encrypted_obj.get("nonce")) and (
            encoded_data := encrypted_obj.get("encrypted_data")
    ):
        try:
            nonce = base64.b64decode(encoded_nonce, validate=True)
            encrypted_data = base64.b64decode(
                encoded_data, validate=True
            )

            aesgcm = AESGCM(AES_KEY)

            personal_data = aesgcm.decrypt(
                nonce=nonce,
                data=encrypted_data,
                associated_data=None,
            )

            return personal_data

        except (binascii.Error, ValueError) as error:
            raise ValueError(
                "Invalid base64 encoded data or failed "
                "decryption"
            ) from error
    return None

import os


def hash_password(password):
    """
    Hashes a password using PBKDF2HMAC with SHA256 algorithm and random salt.
    """
    salt = os.urandom(16)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PORT = 4000

MONGODB_HOST = {
    'host': 'localhost',
    'port': 27017
}

MONGODB_DBNAME = 'cyberStudents'

WORKERS = 32

# Cryptographic configuration
# In a production environment, these would be managed by a secrets management tool
PASSWORD_HASH_ITERATIONS = 700000
PASSWORD_HASH_LENGTH = 32  # Length of the hash value in bytes


# Generate AES-256 secret key (256-bit key)
AES_KEY = AESGCM.generate_key(bit_length=256)

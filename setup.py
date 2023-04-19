import hashlib
import secrets

# Generate a public-private key pair for each party using cryptography library
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate public-private key pair for administrator
admin_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
admin_public_key = admin_private_key.public_key()

# Generate public-private key pair for collectors
collector1_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
collector1_public_key = collector1_private_key.public_key()

collector2_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
collector2_public_key = collector2_private_key.public_key()

# Define the collector and administrator data structures
collector1 = {'host': 'localhost', 'port': 8000, 'public_key': collector1_public_key}
collector2 = {'host': 'localhost', 'port': 8001, 'public_key': collector2_public_key}
administrator = {'host': 'localhost', 'port': 8002, 'public_key': admin_public_key}

# Save the public keys in separate files
with open('collector1_public.pem', 'wb') as f:
    f.write(collector1_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

with open("collector1_private_key.pem", "wb") as f:
    f.write(collector1_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
 
with open('collector2_public.pem', 'wb') as f:
    f.write(collector2_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

with open("collector2_private_key.pem", "wb") as f:
    f.write(collector2_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open('administrator_public.pem', 'wb') as f:
    f.write(admin_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

with open("administrator_private_key.pem", "wb") as f:
    f.write(admin_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))


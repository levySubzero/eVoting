from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import struct
import os

ped_message = ''

def sign():
# Load the private key of the signer
    with open("administrator_private_key.pem", "rb") as f:
        pem_data = f.read()
        private_key = serialization.load_pem_private_key(
        pem_data,
        password=None
    )
    message = b"Hello, this is a test message."
        
    # Compute the BLAKE2b hash of the message and random bits
    hasher = hashes.Hash(hashes.BLAKE2b(64), backend=default_backend())
    hasher.update(message)
    # hasher.update(ass := os.urandom(32))
    digest = hasher.finalize()
    # print("public_key1: ", ass, "\n", "message: ", message)

    # Create a message to sign

    signature = private_key.sign(
        digest, 
        padding.PKCS1v15(), 
        hashes.SHA256()
    )

    # Pack the message
    payload_length = len(message).to_bytes(4, byteorder='big')
    payload = message
    random_bits = os.urandom(32)
    signature_length = len(signature).to_bytes(4, byteorder='big')
    packed_message = payload_length + payload + random_bits + signature_length + signature

    return packed_message



def verify(packed_message):
    # Extract the fields from the packed message
    payload_length = int.from_bytes(packed_message[:4], byteorder='big')
    payload = packed_message[4:4+payload_length]
    random_bits = packed_message[4+payload_length:4+payload_length+32]
    signature_length = int.from_bytes(packed_message[4+payload_length+32:4+payload_length+32+4], byteorder='big')
    signature = packed_message[4+payload_length+32+4:]

    # Compute the BLAKE2b hash of the payload and random bits
    hasher = hashes.Hash(hashes.BLAKE2b(64), backend=default_backend())
    hasher.update(payload)
    # hasher.update(random_bits)
    digest = hasher.finalize()
    # print("public_key1: ", random_bits, "\n", "message: ", payload)

    # Verify the signature using the public key of the signer
    with open("administrator_public.pem", "rb") as f:
        pem_data = f.read()
        public_key = serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )

        # try:
        public_key.verify(
            signature,
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        # Reconstruct the original message by concatenating the payload and random bits
        # message = payload + random_bits
        message = payload
        # Verify that the computed hash matches the hash in the packed message
        hasher = hashes.Hash(hashes.BLAKE2b(64), backend=default_backend())
        hasher.update(message)
        computed_digest = hasher.finalize()
        if computed_digest != digest:
            return False
        else:
            return True
        # except:
        #     return False

# packed_message = sign()
# print(verify(packed_message))
# receive(ped_message)

from phe import paillier
import pickle

# Generate a Paillier key pair
public_key, private_key = paillier.generate_paillier_keypair()

# Save the keys to a file
with open('paillier_keys.pkl', 'wb') as f:
    pickle.dump((public_key, private_key), f)

# Load the keys from the file
with open('paillier_keys.pkl', 'rb') as f:
    public_key, private_key = pickle.load(f)

# Encrypt a number using the public key
plaintext = 42
encrypted_number = public_key.encrypt(plaintext)

# Decrypt the encrypted number using the private key
decrypted_number = private_key.decrypt(encrypted_number)

# Print the results
print("Plaintext:", plaintext)
print("Encrypted number:", encrypted_number)
print("Decrypted number:", decrypted_number)

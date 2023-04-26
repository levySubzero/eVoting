# sign
import struct
import random
import hashlib
import hmac
from Crypto.PublicKey import RSA

def sign_message(message, private_key):
    # Generate a random 32-byte value for the random_bits field
    random_bits = bytes([random.randint(0, 255) for _ in range(32)])
    
    # Calculate the BLAKE2b hash of the message concatenated with random_bits
    hash_value = hashlib.blake2b(message + random_bits, digest_size=32).digest()
    
    # Convert the hash value to an integer
    m = int.from_bytes(hash_value, byteorder='big')
    
    # Sign the hash value using RSA
    signature = private_key.sign(m)
    
    # Pack the message into the format you described
    payload_length = len(message).to_bytes(4, byteorder='big')
    payload = message
    signature_length = len(signature).to_bytes(4, byteorder='big')
    
    # Combine the payload and random bits fields into a single byte string
    message_bytes = payload_length + payload + random_bits
    
    # Combine the signature length and signature fields into a single byte string
    signature_bytes = signature_length + signature
    
    # Return the packed message as a byte string
    return message_bytes + signature_bytes

# receive and unpack
def verify_message(packed_message, public_key):
    # Unpack the message and signature fields
    payload_length = struct.unpack('>I', packed_message[:4])[0]
    payload = packed_message[4:4+payload_length]
    random_bits = packed_message[4+payload_length:4+payload_length+32]
    signature_length = struct.unpack('>I', packed_message[4+payload_length+32:4+payload_length+32+4])[0]
    signature = packed_message[4+payload_length+32+4:]
    
    # Calculate the BLAKE2b hash of the message concatenated with random_bits
    hash_value = hashlib.blake2b(payload + random_bits, digest_size=32).digest()
    
    # Convert the hash value to an integer
    m = int.from_bytes(hash_value, byteorder='big')
    
    # Verify the signature using RSA
    n, e = public_key.n, public_key.e
    m_dash = pow(signature, e, n)
    
    # Check that the recomputed hash value matches the signed hash value
    if m == m_dash:
        return payload
    else:
        return None
    


# Encrypted send
import struct
import os
from Crypto.Cipher import Salsa20
from Crypto.PublicKey import RSA

def package_encrypt_message(message, public_key, private_key):
    # Generate a random 256-bit symmetric key
    symmetric_key = os.urandom(32)
    
    # Encrypt the message using Salsa20 with the symmetric key
    cipher = Salsa20.new(key=symmetric_key, nonce=b'\x00'*8)
    payload_encrypted = cipher.encrypt(message.encode('utf-8'))
    
    # Encrypt the symmetric key using RSA with the recipient's public key
    key_encrypted = public_key.encrypt(symmetric_key, None)[0]
    
    # Compute the BLAKE2b hash of the concatenated fields
    hash_value = hashlib.blake2b(struct.pack('>I', len(payload_encrypted)) + payload_encrypted + struct.pack('>I', len(key_encrypted)), digest_size=32).digest()
    
    # Sign the hash value using RSA with the sender's private key
    m = int.from_bytes(hash_value, byteorder='big')
    signature = pow(m, private_key.d, private_key.n)
    
    # Generate a knowledge proof by encrypting the symmetric key with the sender's public key
    knowledge_proof = private_key.encrypt(symmetric_key, None)[0]
    
    # Package the message according to the guidelines
    packed_message = struct.pack('>I', len(payload_encrypted)) + payload_encrypted + struct.pack('>I', len(key_encrypted)) + key_encrypted + struct.pack('>I', len(signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big'))) + signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big') + struct.pack('>I', len(knowledge_proof.to_bytes((knowledge_proof.bit_length() + 7) // 8, byteorder='big'))) + knowledge_proof.to_bytes((knowledge_proof.bit_length() + 7) // 8, byteorder='big')
    
    return packed_message


#receive and decrypt
import os
from Crypto.Cipher import Salsa20
from Crypto.PublicKey import RSA
from hashlib import blake2b

def receive_signed_encrypted_message(msg, private_key, sender_public_key):
    # Unpack the message into its components
    payload_length = int.from_bytes(msg[:4], byteorder='big')
    payload_encrypted = msg[4:4+payload_length]
    key_encrypted_length = int.from_bytes(msg[4+payload_length:8+payload_length], byteorder='big')
    key_encrypted = msg[8+payload_length:8+payload_length+key_encrypted_length]
    signature_length = int.from_bytes(msg[8+payload_length+key_encrypted_length:12+payload_length+key_encrypted_length], byteorder='big')
    signature = int.from_bytes(msg[12+payload_length+key_encrypted_length:12+payload_length+key_encrypted_length+signature_length], byteorder='big')
    knowledge_proof_length = int.from_bytes(msg[12+payload_length+key_encrypted_length+signature_length:16+payload_length+key_encrypted_length+signature_length], byteorder='big')
    knowledge_proof = int.from_bytes(msg[16+payload_length+key_encrypted_length+signature_length:16+payload_length+key_encrypted_length+signature_length+knowledge_proof_length], byteorder='big')

    # Verify the signature
    hash_value = blake2b(msg[:payload_length+4+key_encrypted_length], digest_size=32).digest()
    if pow(hash_value, sender_public_key.e, sender_public_key.n) != signature:
        raise ValueError('Invalid signature')

    # Decrypt the symmetric key
    key = pow(int.from_bytes(key_encrypted, byteorder='big'), private_key.d, private_key.n).to_bytes(32, byteorder='big')

    # Verify the knowledge proof
    if pow(int.from_bytes(key, byteorder='big'), sender_public_key.e, sender_public_key.n) != knowledge_proof:
        raise ValueError('Invalid knowledge proof')

    # Decrypt the payload
    nonce = os.urandom(8)
    cipher = Salsa20.new(key=key, nonce=nonce)
    payload = cipher.decrypt(payload_encrypted)

    return payload

#LAS response
def paillier_and_las_response(self, data):
    # Decrypt the payload using Salsa20
    symmetric_key_encrypted_length = int.from_bytes(data[8:12], byteorder='big')
    symmetric_key_encrypted = data[12:12+symmetric_key_encrypted_length]
    symmetric_key = self.private_key.decrypt(symmetric_key_encrypted)
    cipher = Salsa20.new(key=symmetric_key, nonce=b'\x00'*8)
    payload_encrypted_length = int.from_bytes(data[:4], byteorder='big')
    payload_encrypted = data[4:4+payload_encrypted_length]
    payload = cipher.decrypt(payload_encrypted)

    # Deserialize the message
    message = pickle.loads(payload)

    # Verify the signature using RSA
    signature_length = int.from_bytes(message[-3], byteorder='big')
    signature = message[-2]
    key_encrypted_length = int.from_bytes(message[-5], byteorder='big')
    key_encrypted = message[-4]
    payload_length = int.from_bytes(message[0], byteorder='big')
    payload_encrypted = message[1]
    h = hashlib.blake2b.new(payload_length.to_bytes(4, byteorder='big') + payload_encrypted + key_encrypted)
    sender_public_key = serialization.load_der_public_key(data[1:69], backend=default_backend())
    try:
        sender_public_key.verify(signature, h.digest())
    except InvalidSignature:
        print("Invalid signature")
        return

    # Decrypt the symmetric key using RSA
    symmetric_key = self.private_key.decrypt(key_encrypted)

    # Deserialize the LAS message
    key_hash = message[1]
    election_id = message[2]
    n_length = int.from_bytes(message[3], byteorder='big')
    n = int.from_bytes(message[4][:n_length], byteorder='big')
    encrypted_perm = []
    for i in range(5, len(message), 2):
        length_prefix = message[i]
        enc_v_bytes = message[i+1]
        bytes_needed = len(enc_v_bytes)
        enc_v = PaillierPublicKey(n).encrypt(int.from_bytes(enc_v_bytes, byteorder='big'))
        encrypted_perm.append(enc_v)

    # Apply a random permutation and generate the response
    N = len(encrypted_perm)
    pi2 = list(range(N))
    random.shuffle(pi2)
    encrypted_perm_inv = [encrypted_perm[pi2.index(i)].decrypt() for i in range(N)]
    r2 = [random.randint(0, n-1) for i in range(N)]
    response = [(encrypted_perm_inv[i] * pow(r2[i], n-2, n)) % n for i in range(N)]
    response_perm = [response[pi2.index(i)] for i in range(N)]

    # Encrypt the response using Paillier
    pub_key = PaillierPublicKey(n)
    encrypted_response = [pub_key.encrypt(r) for r in response_perm]

    # Convert the encrypted response values to bytes and calculate their length
    response_bytes = b''
    for v in encrypted_response:
        enc_v = v.ciphertext()
        bytes_needed = (enc_v.bit_length() + 7) // 8  # calculate number of bytes needed
        bytes_needed += bytes_needed % 2  # make sure there is an even number of bytes
        enc_v_bytes = enc_v.to_bytes(bytes_needed, byteorder='big', signed=True)  # encode as bytes in big-endian two's complement format
        length_prefix = struct.pack


##REspond with shares
def generate_message(voter_id, public_key, election_id, num_shares):
    key_hash = hash(public_key)
    Rj = generate_random_bytes(R_length)  // Generate random bytes for Rj field
    shares = []
    for i in range(num_shares):
        share = generate_share(voter_id, public_key, Rj)  // Generate encrypted share
        complementary_share = generate_complementary_share(voter_id, public_key)  // Generate encrypted complementary share
        shares.append(share)
        shares.append(complementary_share)
    N = num_shares * 2  // Calculate total number of shares sent
    message = build_message(key_hash, election_id, N, Rj, shares)
    return message

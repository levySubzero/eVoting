import hashlib
import os
import random
import socket
import pickle
import struct
import sys
import threading
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Util.number import getPrime, inverse
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

HOST = '127.0.0.1'

class Voter():
    election_id = ''
    collector1_pk = ''
    collector1_pk_length = ''
    collector1_key_hash = ''
    collector1_host = HOST
    collector1_host_length = ''
    collector1_port = ''
    collector2_pk = ''
    collector2_pk_length = ''
    collector2_key_hash = ''
    collector2_host = HOST
    collector2_host_length = ''
    collector2_port = ''
    M = 2
    name1_length = ''
    name1 = ''
    name2_length = ''
    name2 = ''

    def __init__(self, voter_id, admin_port):
        self.voter_id = int(voter_id)
        voter_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        with open(f"data/voter{voter_id}_private_key.pem", "wb") as f:
            f.write(voter_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        message_type = b'\x03'
        serialized_key = voter_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_hash = hashlib.sha256(serialized_key).digest()
        votr_id = self.voter_id.to_bytes(4, byteorder='big')

        payload = message_type + key_hash + votr_id

        random_bytes = os.urandom(32)

        # Sign the payload
        signature = voter_private_key.sign(
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        payload_length = struct.pack('>I', len(payload))
        signature_length = struct.pack('>I', len(signature))
        message = payload_length + payload + random_bytes + signature_length + signature
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((HOST, int(admin_port)))
        print("Connected to Admin Server")
        print("Registered Succefully")
        print("Election Data Received")
        server.sendall(message)
        payload_length = None
        payload = None
        random_bits = None
        signature_length = None
        signature = None

        # Receive payload length
        payload_data = server.recv(2000)
        # print(payload_length_data)

        payload_len = payload_data[:4]
        message_type = payload_data[4:4+1]
        election_ID = payload_data[4+1:4+1+16]
        print('Election ID_ADMIN: ', election_ID, int.from_bytes(election_ID, byteorder="big"))
        c1_host_length = payload_data[4+1+16:4+1+16+4]
        print('C1_host_length', c1_host_length, int.from_bytes(c1_host_length, byteorder="big"))
        c1_host = payload_data[4+1+16+4:4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")]
        print('C1_host', c1_host, c1_host.decode('utf-8'))
        c1_port = payload_data[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big"):4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2]
        print('C1_port', int.from_bytes(c1_port, byteorder="big"))
        c1_pk_length = payload_data[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2:4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4]
        print('C1_pk_length', int.from_bytes(c1_pk_length, byteorder="big"))
        c1_pk = payload_data[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4:4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")]
        print('C1_pk', c1_pk)
        c2_host_length = payload_data[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big"):4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4]
        print('C2_host_length', c2_host_length, int.from_bytes(c2_host_length, byteorder="big"))
        c2_host = payload_data[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4:4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")]
        print('C2_host', c2_host, c2_host.decode('utf-8'))
        c2_port = payload_data[24+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big"):4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2]
        print('C2_port', int.from_bytes(c2_port, byteorder="big"))
        c2_pk_length = payload_data[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2:4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4]
        print('C2_pk_length', int.from_bytes(c2_pk_length, byteorder="big"))

        c2_pk = payload[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4:4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")]
        print('C2_pk', c2_pk)
        M = payload[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big"):4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1]
        print('M: ', M, int.from_bytes(M, byteorder="big"))
        name1_length = payload[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1:4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4]
        print('name1_length: ', name1_length, int.from_bytes(name1_length, byteorder="big"))
        name1 = payload[21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big"):21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big")]
        print('name1: ', name1, name1.decode('utf-8'))
        name2_length = payload[21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big"):21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big")+4]
        print('name2_length: ', name2_length, int.from_bytes(name2_length, byteorder="big"))
        name2 = payload[21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big")+4:21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big")+4+int.from_bytes(name2_length, byteorder="big")]
        print('name2: ', name2, name2.decode('utf-8'))
        return
        # payload_length = struct.unpack('!I', payload_length_data)[0]
        # # print("size", int.from_bytes(payload_length, byteorder="big"))
        # print("size", payload_length)
        # # Receive payload
        payload_data = server.recv(payload_length)

        # # Receive random bits
        # random_bits_data = server.recv(32)

        # # Receive signature length
        # signature_length_data = server.recv(4)

        # Receive signature
        # signature_data = server.recv(signature_length)

        # Unpack payload
        message_type = payload_data[:1]
        election_ID = payload_data[1:17]
        print('Election ID_ADMIN: ', election_ID, int.from_bytes(election_ID, byteorder="big"))
        c1_host_length = payload_data[17:21]
        print('C1_host_length', c1_host_length, int.from_bytes(c1_host_length, byteorder="big"))
        c1_host = payload_data[21:21+int.from_bytes(c1_host_length, byteorder="big")]
        print('C1_host', c1_host, c1_host.decode('utf-8'))
        c1_port = payload_data[21+int.from_bytes(c1_host_length, byteorder="big"):21+int.from_bytes(c1_host_length, byteorder="big")+2]
        print('C1_port', int.from_bytes(c1_port, byteorder="big"))
        c1_pk_length = payload_data[21+int.from_bytes(c1_host_length, byteorder="big")+2:21+int.from_bytes(c1_host_length, byteorder="big")+2+4]
        print('C1_pk_length', int.from_bytes(c1_pk_length, byteorder="big"))
        c1_pk = payload_data[21+int.from_bytes(c1_host_length, byteorder="big")+2+4:21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")]
        print('C1_pk', c1_pk)
        c2_host_length = payload_data[21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big"):21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4]
        print('C2_host_length', c2_host_length, int.from_bytes(c2_host_length, byteorder="big"))
        c2_host = payload_data[21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4:21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")]
        print('C2_host', c2_host, c2_host.decode('utf-8'))
        c2_port = payload_data[21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big"):21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2]
        print('C2_port', int.from_bytes(c2_port, byteorder="big"))
        c2_pk_length = payload_data[21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2:21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4]
        print('C2_pk_length', int.from_bytes(c2_pk_length, byteorder="big"))

        # c2_pk = payload[21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4:21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")]
        # print('C2_pk', c2_pk)
        # M = payload[21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length,send and receive  byte string in tcp python byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big"):21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1]
        # name1_length = payload[21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1:21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4]
        # name1 = payload[21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big"):21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big")]
        # name2_length = payload[21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big"):21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big")+4]
        # name2 = payload[21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big")+4:21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big")+4++int.from_bytes(name2_length, byteorder="big")]
        

        # print('host: ',c1_host)
        # print('port: ', c1_port)
        # print('host: ',c2_host)
        # print('port: ', c2_port)
        # print('name1: ', name1) 
        # print('name2: ', name2)
        



    def voter_info_req():
        # send signed to admin
        # message_type TYPE_REGISTER = 0x03
        # public_key_hash
        # voter id

        admin_host = 'local_host'
        admin_port = 8000
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((admin_host, admin_port))

        voter_public_key, voter_private_key, admin_public_key, voter_id = '',
        serialized_key = voter_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_hash = hashlib.sha256(serialized_key).digest()

        # Create the message to sign
        message = b'\x03' + key_hash + voter_id.to_bytes(4, byteorder='big')
        # Sign the message
        signature = voter_private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # Create the final message to send
        final_message = b'\x03' + key_hash + voter_id.to_bytes(4, byteorder='big') + signature

        # Encrypt the message for the admin
        encrypted_message = admin_public_key.encrypt(
            final_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Send the message to the admin
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('admin_hostname', admin_port))
            s.sendall(encrypted_message)  

    # receive metadata
    def voter_register():
        voter_private_key, = ''
        message = 'receive_message(s)'
        # Verify the signature
        signature = message[-256:]
        signed_data = message[:-256]
        try:
            voter_public_key = voter_private_key.public_key()
            voter_public_key.verify(
                signature,
                signed_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return None

        # Extract the data
        metadata_bytes = message
        metadata_type = int.from_bytes(metadata_bytes[0:1], byteorder='big')
        election_id = metadata_bytes[1:17]
        c1_host_length = int.from_bytes(metadata_bytes[17:21], byteorder='big')
        c1_host = metadata_bytes[21:21+c1_host_length].decode('utf-8')
        c1_port = int.from_bytes(metadata_bytes[21+c1_host_length:23+c1_host_length], byteorder='big')
        c1_pk_length = int.from_bytes(metadata_bytes[23+c1_host_length:27+c1_host_length], byteorder='big')
        c1_pk = metadata_bytes[27+c1_host_length:27+c1_host_length+c1_pk_length]
        c2_host_length = int.from_bytes(metadata_bytes[27+c1_host_length:31+c1_host_length], byteorder='big')
        c2_host = metadata_bytes[31+c1_host_length:31+c1_host_length+c2_host_length].decode('utf-8')
        c2_port = int.from_bytes(metadata_bytes[31+c1_host_length+c2_host_length:33+c1_host_length+c2_host_length], byteorder='big')
        c2_pk_length = int.from_bytes(metadata_bytes[33+c1_host_length+c2_host_length:37+c1_host_length+c2_host_length], byteorder='big')
        c2_pk = metadata_bytes[37+c1_host_length+c2_host_length:37+c1_host_length+c2_host_length+c2_pk_length]
        num_candidates = int.from_bytes(metadata_bytes[-15:-14], byteorder='big')
        name1_length = int.from_bytes(metadata_bytes[-14:-10], byteorder='big')
        name1 = metadata_bytes[-10-name1_length:-10].decode('utf-8')
        name2_length = int.from_bytes(metadata_bytes[-10:-6], byteorder='big')
        name2 = metadata_bytes[-6-name2_length:-6].decode('utf-8')

    def vote(admin_host,admin_port):
        # voter sends to collector 2
        # message_type TYPE_SHARES_REQUEST=0x08
        # voter ID
        # election ID

        voter_private_key, collector_public_key, collector_address, election_id, voter_id, collector_port = ''
        voter_public_key = voter_private_key.public_key()
        serialized_key = voter_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_hash = hashlib.sha256(serialized_key).digest()
        # Create the message to sign
        message = b'\x03' + key_hash + election_id + voter_id.to_bytes(4, byteorder='big')

        # Sign the message
        signature = voter_private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

         # Create the final message to send
        final_message = b'\x08' + key_hash + election_id + voter_id.to_bytes(4, byteorder='big') + signature

        # Encrypt the message for the collector
        encrypted_message = collector_public_key.encrypt(
            final_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Send the message to the collector
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((collector_address, collector_port))
            s.sendall(encrypted_message)


class Administrator():
    election_id = ''
    collector1_pk = ''
    collector1_pk_length = ''
    collector1_key_hash = ''
    collector1_host = ''
    collector1_host_length = ''
    collector1_port = ''
    collector2_pk = ''
    collector2_pk_length = ''
    collector2_key_hash = ''
    collector2_host = ''
    collector2_host_length = ''
    collector2_port = ''
    admin_port = ''
    admin_pk = ''
    M = 2
    N = 0
    admin_private_key = ''

    def __init__(self):
        # Generate a election
        election_id = os.urandom(16)

        Administrator.election_id = election_id
        print("***INITIALISING***")

        admin_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        Administrator.admin_private_key = admin_private_key
        with open("data/admin_private_key.pem", "wb") as f:
            f.write(admin_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        # Generate public-private key pair for collectors
        collector1_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        with open("data/collector1_private_key.pem", "wb") as f:
            f.write(collector1_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        collector2_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        with open("data/collector2_private_key.pem", "wb") as f:
            f.write(collector2_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        collector1_pk = collector1_private_key.public_key()
        collector2_pk = collector2_private_key.public_key()
        admin_pk = admin_private_key.public_key()
        # collector1_pk_length = len(collector1_pk)
        # collector2_pk_length = len(collector2_pk)
        col1_hash = collector1_pk.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        col2_hash = collector2_pk.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        collector1_key_hash = hashlib.sha256(col1_hash)
        collector1_key_hash = collector1_key_hash.digest()
        collector2_key_hash = hashlib.sha256(col2_hash)
        collector2_key_hash = collector2_key_hash.digest()

        collector1_pk_bytes = collector1_pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )  
        collector2_pk_bytes = collector2_pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )        

        Administrator.collector1_pk = collector1_pk_bytes
        Administrator.collector2_pk = collector2_pk_bytes
        Administrator.admin_pk = admin_pk
        # Administrator.collector1_pk_length = collector1_pk_length
        # Administrator.collector2_pk_length = collector2_pk_length
        Administrator.collector1_key_hash = collector1_key_hash
        Administrator.collector2_key_hash = collector2_key_hash

        collector_host = HOST
        Administrator.collector1_host_length = len(collector_host)
        Administrator.collector2_host_length = len(collector_host)

        print("Now Enter the Ports for Admin and the collectors e.g 8000, 8001, 8002")
        Administrator.admin_port = int(input("Enter port number for Admin: "))
        Administrator.collector1_port = int(input("Enter port number for collector 1: "))
        Administrator.collector2_port = int(input("Enter port number for collector 2: "))

        voter_ids = [1, 2, 3, 4, 5]            

        server_thread = threading.Thread(target=self.admin_server)
        server_thread.start()

        
    def admin_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, int(Administrator.admin_port)))
        server.listen(1)
        voters = []
        while True:    
            client, address = server.accept()
            print(f"Connection Established with - PORT : {address[1]}")
            data = client.recv(1024)
            if data.find(b'\x03') != -1:
                # extract the payload length
                payload_length = int.from_bytes(data[:4], byteorder='big')

                # extract the payload
                payload = data[4:4+payload_length]

                # extract the random bits
                random_bits = data[4+payload_length:4+payload_length+32]

                # extract the signature length
                signature_length_start = 4+payload_length+32
                signature_length_end = signature_length_start + 4
                signature_length = int.from_bytes(data[signature_length_start:signature_length_end], byteorder='big')

                # extract the signature
                signature_start = signature_length_end
                signature_end = signature_start + signature_length
                signature = data[signature_start:signature_end]

                # extract the payload contents
                message_type = int.from_bytes(payload[:4], byteorder='big')
                key_hash = payload[4:68]
                voter_id = payload[33:38]
                print(f'Election Data Sent to {voter_id}')
                
                message_type = b'\x04'
                election_ID = Administrator.election_id
                print('Election ID_ADMIN: ', election_ID, int.from_bytes(election_ID, byteorder="big"))
                C1_host_length = len(HOST.encode('utf-8')).to_bytes(4, byteorder='big')
                print('C1_host_length', C1_host_length, int.from_bytes(election_ID, byteorder="big"))
                C1_host = HOST.encode('utf-8')
                print('C1_host', C1_host, HOST.encode('utf-8'))
                C1_port = Administrator.collector1_port.to_bytes(2, byteorder='big')
                print('C1_port', C1_port, Administrator.collector1_port)
                C1_pk_length = len(Administrator.collector1_pk).to_bytes(4, byteorder='big')
                print('C1_pk_length', C1_pk_length , len(Administrator.collector1_pk))
                C1_pk = Administrator.collector1_pk
                print('C1_pk ', C1_pk, )
                C2_host_length = len(HOST.encode('utf-8')).to_bytes(4, byteorder='big')
                print('C2_host_length', C2_host_length, len(HOST.encode('utf-8')))
                C2_host = HOST.encode('utf-8')
                print('C2_host', C2_host, HOST)
                C2_port = Administrator.collector2_port.to_bytes(2, byteorder='big')
                print('C2_port', C2_port, Administrator.collector2_port)
                C2_pk_length = len(Administrator.collector2_pk).to_bytes(4, byteorder='big')
                print('C2_pk_length ', C2_pk_length, len(Administrator.collector2_pk))
                C2_pk = Administrator.collector2_pk
                print('C2_pk', C2_pk, )
                M = (2).to_bytes(1, byteorder='big')
                print('M', M, 2)
                name1 = 'Competitor 1'.encode('utf-8')
                print('name1 ', name1, 'Competitor 1')
                name1_length = len(name1).to_bytes(4, byteorder='big')
                print('name1_length ', name1_length, len(name1))
                name2 = 'Competitor 2'.encode('utf-8')
                print('name2', name2, 'Competitor 2')
                name2_length = len(name2).to_bytes(4, byteorder='big')
                print('name1_length ', name1_length, len(name1))
                respond = [message_type , election_ID , C1_host_length , C1_host , C1_port , C1_pk_length , C1_pk , C2_host_length , C2_host , C2_port , C2_pk_length , C2_pk , M , name1_length , name1 , name2_length , name2]
                response = b''
                for i in respond:
                    print(i)
                    response += i
                print(response)
                # hash_value = hashes.Hash(hashes.BLAKE2b(64), backend=default_backend())
                # hash_value.update(response + b'\x00' * 32)
                # digest = hash_value.finalize()
                # signature = Administrator.admin_private_key.sign(
                #     digest,
                #     padding.PKCS1v15(),
                #     hashes.SHA256()
                # )
                
                # send the signed response message
                response_length = len(response).to_bytes(4, byteorder='big')
                signature_length = len(signature).to_bytes(4, byteorder='big')
                client.sendall(k := response_length + response + os.urandom(32) + signature_length + signature)
                payload_data = response_length + response
                payload_len = payload_data[:4]
                message_type = payload_data[4:4+1]
                election_ID = payload_data[4+1:4+1+16]
                print('Election ID_ADMIN: ', election_ID, int.from_bytes(election_ID, byteorder="big"))
                c1_host_length = payload_data[4+1+16:4+1+16+4]
                print('C1_host_length', c1_host_length, int.from_bytes(c1_host_length, byteorder="big"))
                c1_host = payload_data[4+1+16+4:4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")]
                print('C1_host', c1_host, c1_host.decode('utf-8'))
                c1_port = payload_data[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big"):4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2]
                print('C1_port', int.from_bytes(c1_port, byteorder="big"))
                c1_pk_length = payload_data[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2:4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4]
                print('C1_pk_length', int.from_bytes(c1_pk_length, byteorder="big"))
                c1_pk = payload_data[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4:4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")]
                print('C1_pk', c1_pk)
                c2_host_length = payload_data[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big"):4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4]
                print('C2_host_length', c2_host_length, int.from_bytes(c2_host_length, byteorder="big"))
                c2_host = payload_data[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4:4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")]
                print('C2_host', c2_host, c2_host.decode('utf-8'))
                c2_port = payload_data[24+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big"):4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2]
                print('C2_port', int.from_bytes(c2_port, byteorder="big"))
                c2_pk_length = payload_data[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2:4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4]
                print('C2_pk_length', int.from_bytes(c2_pk_length, byteorder="big"))

                c2_pk = payload[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4:4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")]
                print('C2_pk', c2_pk)
                M = payload[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big"):4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1]
                print('M: ', M, int.from_bytes(M, byteorder="big"))
                name1_length = payload[4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1:4+1+16+4+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4]
                print('name1_length: ', name1_length, int.from_bytes(name1_length, byteorder="big"))
                name1 = payload[21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big"):21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big")]
                print('name1: ', name1, name1.decode('utf-8'))
                name2_length = payload[21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big"):21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big")+4]
                print('name2_length: ', name2_length, int.from_bytes(name2_length, byteorder="big"))
                name2 = payload[21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big")+4:21+int.from_bytes(c1_host_length, byteorder="big")+2+4+int.from_bytes(c1_pk_length, byteorder="big")+4+int.from_bytes(c2_host_length, byteorder="big")+2+4+int.from_bytes(c2_pk_length, byteorder="big")+1+4+int.from_bytes(name1_length, byteorder="big")+4+int.from_bytes(name2_length, byteorder="big")]
                print('name2: ', name2, name2.decode('utf-8'))
                if len(voters) == 5:
                    print('**REGISTRATION PERIOD ENDED**')
                    print('**SENDING LIST OF VOTERS TO COLLECTORS**')
                    print('**COLLECTOR 1 TO INITIALISE PAILIER**')
                    ...
                    break

            else:
                print('election', int.from_bytes(Administrator.election_id, byteorder='big'))
                client.send(Administrator.election_id)

            
    def admin_client(self, port, message):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((HOST, port))
        print("sending voters list to collector")
        server.send(message)

        # Define the collector and administrator data structures
        # collector1 = {'host': 'localhost', 'port': 8000, 'public_key': collector1_public_key}
        # collector2 = {'host': 'localhost', 'port': 8001, 'public_key': collector2_public_key}
        # administrator = {'host': 'localhost', 'port': 8002, 'public_key': admin_public_key}

    def receive_voter_register():
        admin_private_key, message = ''
        # Decrypt the message
        decrypted_message = admin_private_key.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Parse the message
        key_hash = decrypted_message[0:64]
        voter_id = int.from_bytes(decrypted_message[64:68], byteorder='big')

        # Verify the signature
        signature = decrypted_message[68:]
        message_to_verify = key_hash + voter_id.to_bytes(4, byteorder='big')
        admin_public_key = admin_private_key.public_key()
        try:
            admin_public_key.verify(
                signature,
                message_to_verify,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except:
            print("Invalid signature.")

        key_hash = key_hash.decode('utf-8')
        voter_id = str(voter_id)

        return key_hash, voter_id

    def voter_info_response(voter_id, key_hash):
        # response func
        # send signed to voter.
        # message_type TYPE_METADATA_VOTER=0x04
        # Election ID
        # collectors info
        # list of candidates

        # Serialize the public keys
        serialized_c1_pk = c1_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        serialized_c2_pk = c2_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Serialize the candidate names
        serialized_names = b''
        for name in candidate_names:
            name_length = len(name).to_bytes(4, byteorder='big')
            serialized_names += name_length + name.encode()

        c1_public_key, c2_public_key, candidate_names, election_id, c1_host, c1_port, c2_host, c2_port, num_candidates, admin_private_key = ''

        # Create the message to sign
        message = b'\x04' + election_id + \
            len(c1_host).to_bytes(4, byteorder='big') + c1_host.encode() + \
            c1_port.to_bytes(2, byteorder='big') + \
            len(serialized_c1_pk).to_bytes(4, byteorder='big') + serialized_c1_pk + \
            len(c2_host).to_bytes(4, byteorder='big') + c2_host.encode() + \
            c2_port.to_bytes(2, byteorder='big') + \
            len(serialized_c2_pk).to_bytes(4, byteorder='big') + serialized_c2_pk + \
            num_candidates.to_bytes(1, byteorder='big') + serialized_names
        
        # Sign the message
        signature = admin_private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Create the final message to send
        final_message = b'\x04' + election_id + \
                len(c1_host).to_bytes(4, byteorder='big') + c1_host.encode() + \
                c1_port.to_bytes(2, byteorder='big') + \
                len(serialized_c1_pk).to_bytes(4, byteorder='big') + serialized_c1_pk + \
                len(c2_host).to_bytes(4, byteorder='big') + c2_host.encode() + \
                c2_port.to_bytes(2, byteorder='big') + \
                len(serialized_c2_pk).to_bytes(4, byteorder='big') + serialized_c2_pk + \
                num_candidates.to_bytes(1, byteorder='big') + serialized_names + \
                signature

        return final_message
        
    def voters_list_to_collectors():
        # send signed to both collectors
        # message_type TYPE_VOTERS = 0x05
        # Election ID
        # voters info(ID, pk & pk hash)
        election_id, collector_public_key, admin_private_key, collector_address, voter_list, s = 'to be', '', 'voter_list'
        # Serialize the voter list
        serialized_voter_list = []
        for voter in voter_list:
            voter_id = voter['id'].to_bytes(4, byteorder='big')
            voter_pk_length = len(voter['pk']).to_bytes(4, byteorder='big')
            serialized_voter = voter_id + voter_pk_length + voter['pk']
            serialized_voter_list.append(serialized_voter)

        # Concatenate the serialized voters
        serialized_voters = b''.join(serialized_voter_list)
        # Create the message to sign
        message = b'\x05' + election_id + len(voter_list).to_bytes(4, byteorder='big') + serialized_voters
        # Sign the message
        signature = admin_private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # Create the final message to send
        final_message = b'\x02' + election_id + len(voter_list).to_bytes(4, byteorder='big') + serialized_voters + signature

        # Encrypt the message for the collector
        encrypted_message = collector_public_key.encrypt(
            final_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        s.connect(collector_address)
        # Send the encrypted message
        s.sendall(encrypted_message)

        # Close the socket
        # s.close()


class Collector():
    election_id = ''
    M = 2
    N = 0
    voters_info = []
    paillier_public_key = ''

    def __init__(self, admin_port, collector_index):
        self.collector_index = collector_index
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((HOST, admin_port))
        print("Connected to Admin")
        election_id = server.recv(1024)
        try:
            election_id = election_id.decode('utf-8')
            print(f"utf: {election_id}")
        except UnicodeDecodeError:
            print('id_int',int.from_bytes(election_id, byteorder='big'))
            election_id = election_id.hex()
            print(f"hex: {election_id}")
        Collector.election_id = election_id

        with open("data/collector1_private_key.pem", "rb") as f:
            pem_data = f.read()
            collector1_private_key = serialization.load_pem_private_key(
            pem_data,
            password=None
        )
        with open("data/collector2_private_key.pem", "rb") as f:
            pem_data = f.read()
            collector2_private_key = serialization.load_pem_private_key(
            pem_data,
            password=None
        )
        if collector_index == 1:
            self.pk = collector1_private_key.public_key()
            # self.pk_length = len(self.pk)
            # key_hash = hashlib.sha256(self.pk)
            # key_hash = key_hash.digest()
            # self.key_hash = key_hash
            self.other_C_host_length = len(HOST)
            self.other_C_host = HOST
            self.other_C_port = input("Enter Port that you Entered for Collector2 in Admin server")
            self.other_C_pk = collector2_private_key.public_key()
            # self.other_C_pk_length = len(self.other_C_pk)
        else:
            self.pk = collector2_private_key.public_key()
            # self.pk_length = len(self.pk)
            # key_hash = hashlib.sha256(self.pk)
            # key_hash = key_hash.digest()
            # self.key_hash = key_hash
            self.other_C_host_length = len(HOST)
            self.other_C_host = HOST
            self.other_C_port = input("Enter Port that you Entered for Collector1 in Admin server")
            self.other_C_pk = collector1_private_key.public_key()
            # self.other_C_pk_length = len(self.other_C_pk)


    def send_shares():
        # send signed to both collectors
        # message_type TYPE_SHARES
        # key hash
        # election ID
        # N
        ...

    def receive_type_voters(self):
        encrypted_message, collector_private_key, admin_public_key = '', '' 
        # Decrypt the message using the collector's private key
        decrypted_message = collector_private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Unparse the message
        message_type = decrypted_message[0:1]
        election_id = decrypted_message[1:17]
        num_voters = int.from_bytes(decrypted_message[17:21], byteorder='big')
        serialized_voters = decrypted_message[21:-256]
        signature = decrypted_message[-256:]
        self.N = num_voters

        # Verify the signature using the admin's public key
        admin_public_key.verify(
            signature,
            b'\x02' + election_id + num_voters.to_bytes(4, byteorder='big') + serialized_voters,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Parse the serialized voters
        voters = []
        i = 0
        while i < len(serialized_voters):
            voter_id = int.from_bytes(serialized_voters[i:i+4], byteorder='big')
            voter_pk_length = int.from_bytes(serialized_voters[i+4:i+8], byteorder='big')
            voter_pk = serialized_voters[i+8:i+8+voter_pk_length]
            voters.append({'id': voter_id, 'pk': voter_pk})
            i += 8 + voter_pk_length

        # # Close the socket
        # conn.close()
        # s.close()

    def paillier_init(self):
        # Choose two large prime numbers p and q of equal length and 2048 bits
        p = getPrime(2048)
        q = getPrime(2048)

        n = p * q
        lamda = (p - 1) * (q - 1)
        mu = inverse(lamda, n)

        # Let g = n + 1, which will be used as the public key
        public_key = n + 1
        private_key = (lamda, mu)
        public_key_bytes = public_key.to_bytes((public_key.bit_length() + 7) // 8, byteorder='big')
        #send(public_key_bytes)

    def las_c1_initiate(self):
        message_type = b'0x06'
        election_id = Collector.election_id.encode()
        N = len(Collector.voters_info) # num_of_voters

        # Generate random permutation of {0, 1, ..., N-1}
        pi = random.sample(range(N), N)

        # Encrypt each permuted value using Paillier cryptosystem
        encrypted_values = []
        # for i in range(N):
            # encrypted_value = paillier_encrypt(pi[i], self.paillier_key.public_key)
            # encrypted_values.append(encrypted_value)

        # Serialize and pack message fields
        # key_hash = hashlib.sha256(rsa_key.publickey().export_key()).digest()
        # n_bytes = long_to_bytes(N)
        # value1_bytes = b"".join([long_to_bytes(value) for value in encrypted_values])

        # packed_message = message_type + self.key_hash + election_id + n_bytes + value1_bytes
        # Sign the message with RSA digital signature
        # signature = rsa_key.sign(packed_message, "")
        # signed_message = packed_message + signature

        # Encrypt the signed message with AES
        iv = b"1234567890123456"
        cipher = AES.new(self.key_hash[:16], AES.MODE_CBC, iv)
        # encrypted_message = cipher.encrypt(pad(signed_message, 16))

        # Connect to c2 over TCP and send the encrypted message
        TCP_IP = 'c2_ip_address'
        TCP_PORT = 1234
        BUFFER_SIZE = 1024

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TCP_IP, TCP_PORT))

        # s.send(encrypted_message)
        data = s.recv(BUFFER_SIZE)

        s.close()

    def las_c2_response(self):
        # TYPE_LAS2 0x07
        ...

    # -- Sub-protocal 1----
    def initiate_verification(admin_host, admin_port, election_id):
        # send signed to the other collector
        # message_type TYPE_VERIFY1
        # key hash
        # election ID
        # voter ID
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((admin_host, admin_port))

        message_type = b'TYPE_VERIFY1'
        key_hash = b'64_byte_key_hash'
        voter_id = b'4_byte_voter_id'
        message = (message_type, key_hash, election_id, voter_id)

        with open("collector1_private_key.pem", "rb") as f:
            pem_data = f.read()
            collector1_private_key = serialization.load_pem_private_key(
            pem_data,
            password=None
        )

        signature = collector1_private_key.sign(pickle.dumps(message), padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ), hashes.SHA256())

        ...

    def init_response1(i):
        # send signed and Encrypted to initiating collector
        # message_type TYPE_VERIFY2
        # election ID
        # STPM_index
        # value_length
        # value

        # message_type = b'TYPE_VERIFY2'
        # key_hash = b'64_byte_key_hash'
        # election_id = b'4_byte_voter_id'
        # STPM_index = i
        # value_length
        # value
        # message = (message_type, key_hash, election_id, STPM_index, value_length, value)

        # with open("collector1_private_key.pem", "rb") as f:
        #     pem_data = f.read()
        #     collector1_private_key = serialization.load_pem_private_key(
        #     pem_data,
        #     password=None
        # )

        # signature = collector1_private_key.sign(pickle.dumps(message), padding.PSS(
        #     mgf=padding.MGF1(hashes.SHA256()),
        #     salt_length=padding.PSS.MAX_LENGTH
        # ), hashes.SHA256())

        ...

    def init_response2(i):
        # send signed and Encrypted to initres1 initiating collector
        # message_type TYPE_VERIFY3
        # election ID
        # STPM_index
        # value_length
        # value
        # message_type = b'TYPE_VERIFY3'
        # key_hash = b'64_byte_key_hash'
        # election_id = b'4_byte_voter_id'
        # STPM_index = i
        # value_length
        # value
        # message = (message_type, key_hash, election_id, STPM_index, value_length, value)

        # with open("collector1_private_key.pem", "rb") as f:
        #     pem_data = f.read()
        #     collector1_private_key = serialization.load_pem_private_key(
        #     pem_data,
        #     password=None
        # )

        # signature = collector1_private_key.sign(pickle.dumps(message), padding.PSS(
        #     mgf=padding.MGF1(hashes.SHA256()),
        #     salt_length=padding.PSS.MAX_LENGTH
        # ), hashes.SHA256())
        ...

    # collectors exchange product
    def product_send():
        # send signed and Encrypted to other collector
        # message_type TYPE_VERIFY4
        # election ID
        # product_length
        # product
        ...

# ------- Sub Protocal 2 --------
    def send_gsi():   
        # each collector send signed and Encrypted to other collector
        # message_type TYPE_VERIFY5
        # key_hash 64 bytes
        # election ID
        ...

    def send_to_admin():
        ...


class Communication():
    
    # Define constants for IP addresses and ports
    ADMIN_IP = 'localhost'
    ADMIN_PORT = 5000
    COLLECTOR1_IP = 'localhost'
    COLLECTOR1_PORT = 5001
    COLLECTOR2_IP = 'localhost'
    COLLECTOR2_PORT = 5002
    VOTER1_IP = 'localhost'
    VOTER1_PORT = 5003
    VOTER2_IP = 'localhost'
    VOTER2_PORT = 5004

    # Define the admin server thread
    def admin_server():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as admin_sock:
            # admin_sock.bind((ADMIN_IP, ADMIN_PORT))
            admin_sock.listen()
            # print(f"Admin server running on {ADMIN_IP}:{ADMIN_PORT}")
            while True:
                conn, addr = admin_sock.accept()
                print(f"Admin connected from {addr}")
                # Handle admin requests here

    # Define the collector1 server thread
    def collector1_server():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as collector1_sock:
            # collector1_sock.bind((COLLECTOR1_IP, COLLECTOR1_PORT))
            collector1_sock.listen()
            # print(f"Collector 1 server running on {COLLECTOR1_IP}:{COLLECTOR1_PORT}")
            while True:
                conn, addr = collector1_sock.accept()
                print(f"Collector 1 connected from {addr}")
                # Handle collector1 requests here

    # Define the collector2 server thread
    def collector2_server():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as collector2_sock:
            # collector2_sock.bind((COLLECTOR2_IP, COLLECTOR2_PORT))
            collector2_sock.listen()
            # print(f"Collector 2 server running on {COLLECTOR2_IP}:{COLLECTOR2_PORT}")
            while True:
                conn, addr = collector2_sock.accept()
                print(f"Collector 2 connected from {addr}")
                # Handle collector2 requests here

    # Define the voter1 client thread
    def voter1_client():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as voter1_sock:
            # voter1_sock.connect((ADMIN_IP, ADMIN_PORT))
            # print(f"Voter 1 connected to admin server at {ADMIN_IP}:{ADMIN_PORT}")
            # Send voter1 requests to admin here
            # Receive responses from admin here
            ...

    # Define the voter2 client thread
    def voter2_client():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as voter2_sock:
            # voter2_sock.connect((ADMIN_IP, ADMIN_PORT))
            # print(f"Voter 2 connected to admin server at {ADMIN_IP}:{ADMIN_PORT}")
            # Send voter2 requests to admin here
            # Receive responses from admin here
            ...

    # Define the admin client thread
    def admin_client():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as admin_sock:
            # admin_sock.connect((COLLECTOR1_IP, COLLECTOR1_PORT))
            # print(f"Admin connected to collector1 server at {COLLECTOR1_IP}:{COLLECTOR1_PORT}")
            # Send requests to collector1 here
            # Receive responses from collector1 here
            # Send responses to voters through admin server here

            # admin_sock.connect((COLLECTOR2_IP, COLLECTOR2_PORT))
            # print(f"Admin connected to collector2 server at {COLLECTOR2_IP}:{COLLECTOR2_PORT}")
            # Send requests to collector2 here
            # Receive responses from collector2 here
            # Send responses to voters through admin server here
            ...


if __name__ == '__main__':
    # get the service name from the command line arguments
    service_name = sys.argv[1]

    # start the service based on the service name
    if service_name == 'admin':
        admin = Administrator()
    elif service_name == 'collector1':
        collector1 = Collector(int(sys.argv[2]), 1)
    elif service_name == 'collector2':
        collector2 = Collector(int(sys.argv[2]), 2)
    elif service_name == 'voter':
        vote = Voter(sys.argv[2], sys.argv[3])
    else:
        print('Invalid service name')
import hashlib
import os
import random
import secrets
import socket
import pickle
import struct
import sys
import threading
import time
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

    def __init__(self, voter_id):
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
        try:
            server.connect((HOST, 8000))
        except OSError:
            Administrator.admin_port = int(input("ENTER ADMIN PORT FROM ADMIN SERVER"))
            server.connect((HOST, Administrator.admin_port))
        print("Connected to Admin Server")
        print("Registered Succefully")
        server.sendall(message)
        payload_length = None
        payload = None
        random_bits = None
        signature_length = None
        signature = None

        # Receive payload length
        payload_data = server.recv(2000)
        # print(payload_length_data)
        payload_data = pickle.loads(payload_data)
                
        payload_len = payload_data[0]
        message_type = payload_data[1]
        Voter.election_id = payload_data[2]
        print('Election ID_ADMIN: ',int.from_bytes(Voter.election_id, byteorder="big"))
        Voter.collector1_host_length = payload_data[3]
        print('C1_host_length', int.from_bytes(Voter.collector1_host_length, byteorder="big"))
        Voter.collector1_host = payload_data[4]
        print('C1_host', Voter.collector1_host.decode('utf-8'))
        Voter.collector1_port = payload_data[5]
        print('C1_port', int.from_bytes(Voter.collector1_port, byteorder="big"))
        Voter.collector1_pk_length = payload_data[6]
        print('C1_pk_length', int.from_bytes(Voter.collector1_pk_length, byteorder="big"))
        Voter.collector1_pk = payload_data[7]
        print('C1_pk')
        Voter.collector2_host_length = payload_data[8]
        print('C2_host_length', int.from_bytes(Voter.collector2_host_length, byteorder="big"))
        Voter.collector2_host = payload_data[9]
        print('C2_host', Voter.collector2_host.decode('utf-8'))
        Voter.collector2_port = payload_data[10]
        print('C2_port', int.from_bytes(Voter.collector2_port, byteorder="big"))
        Voter.collector2_pk_length = payload_data[11]
        print('C2_pk_length', int.from_bytes(Voter.collector2_pk_length, byteorder="big"))
        Voter.collector1_pk = payload_data[12]
        print('C2_pk')
        Voter.M = payload_data[13]
        print('M: ', int.from_bytes(Voter.M, byteorder="big"))
        Voter.name1_length = payload_data[14]
        print('name1_length: ', int.from_bytes(Voter.name1_length, byteorder="big"))
        Voter.name1 = payload_data[15]
        print('name1: ', Voter.name1.decode('utf-8'))
        Voter.name2_length = payload_data[16]
        print('name2_length: ', int.from_bytes(Voter.name2_length, byteorder="big"))
        Voter.name2 = payload_data[17]
        print('name2: ', Voter.name2.decode('utf-8'))
        print("random 32bytes")
        print("signature length")
        print("signature")

        print("Election Data Received")
        # payload_length = struct.unpack('!I', payload_length_data)[0]
        # # print("size", int.from_bytes(payload_length, byteorder="big"))
        # print("size", payload_length)
        # # Receive payload
        # payload_data = server.recv(payload_length)

        # # Receive random bits
        # random_bits_data = server.recv(32)

        # # Receive signature length
        # signature_length_data = server.recv(4)

        # Receive signature
        # signature_data = server.recv(signature_length)

        
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

        server_thread = threading.Thread(target=self.admin_server)
        server_thread.start()

        
    def admin_server(self):
        Administrator.admin_port = 8000
        Administrator.collector1_port = 8001
        Administrator.collector2_port = 8002
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind((HOST, int(Administrator.admin_port)))
        except OSError:
            Administrator.admin_port = int(input("ENTER ADMIN PORT"))
            Administrator.collector1_port = int(input("ENTER CONTROLLER 1 PORT"))
            Administrator.collector2_port = int(input("ENTER CONTROLLER 2 PORT"))
            server.bind((HOST, int(Administrator.admin_port)))

        print(f"Admin Server running at 127.0.0.1 : {Administrator.admin_port}")
        print(f"Admin Server running at 127.0.0.1 : {Administrator.collector1_port}")
        print(f"Admin Server running at 127.0.0.1 : {Administrator.collector2_port}")
        server.listen(10)
        voters = []
        while True:    
            client, address = server.accept()
            t = threading.Thread(target=self.print_numbers, args=(client, address, voters))
            t.start()
     
    def admin_client(self, port, message):
        print(type(message))
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((HOST, port))
        print("SENDING VOTER LIST TO COLLECTOR")
        server.send(message)
        # pickle.dumps

    def print_numbers(self, client, x, voters):
        print(f"Connection Established with - PORT : {x[1]}")
        data = client.recv(1024)

        if data.find(b'\x03') != -1:
            # extract the payload length & payload
            payload_length = int.from_bytes(data[:4], byteorder='big')
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
            print(f'Sending Election Data {int.from_bytes(voter_id, byteorder="big")}')

            #Generate message to send to voter
            message_type = b'\x04'
            election_ID = Administrator.election_id
            C1_host_length = len(HOST.encode('utf-8')).to_bytes(4, byteorder='big')
            C1_host = HOST.encode('utf-8')
            C1_port = Administrator.collector1_port.to_bytes(2, byteorder='big')
            C1_pk_length = len(Administrator.collector1_pk).to_bytes(4, byteorder='big')
            C1_pk = Administrator.collector1_pk
            C2_host_length = len(HOST.encode('utf-8')).to_bytes(4, byteorder='big')
            C2_host = HOST.encode('utf-8')
            C2_port = Administrator.collector2_port.to_bytes(2, byteorder='big')
            C2_pk_length = len(Administrator.collector2_pk).to_bytes(4, byteorder='big')
            C2_pk = Administrator.collector2_pk
            M = (2).to_bytes(1, byteorder='big')
            name1 = 'Competitor 1'.encode('utf-8')
            name1_length = len(name1).to_bytes(4, byteorder='big')
            name2 = 'Competitor 2'.encode('utf-8')
            name2_length = len(name2).to_bytes(4, byteorder='big')
            response = b''
            random_bits = secrets.token_bytes(32)
            hash_value = hashes.Hash(hashes.BLAKE2b(64), backend=default_backend())
            hash_value.update(response + random_bits)
            digest = hash_value.finalize()
            signature = Administrator.admin_private_key.sign(
                digest,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            # send the signed response message
            response_length = len(response).to_bytes(4, byteorder='big')
            signature_length = len(signature).to_bytes(4, byteorder='big')
            
            client.sendall(pickle.dumps([response_length, message_type , election_ID , 
                                            C1_host_length , C1_host , C1_port , C1_pk_length , C1_pk,
                                            C2_host_length , C2_host , C2_port , C2_pk_length , C2_pk,
                                            M , name1_length , name1 , name2_length, name2, random_bits,
                                            signature_length, signature]))
            with open(f'data/voter{int.from_bytes(voter_id, byteorder="big")}_private_key.pem', "rb") as f:
                pem_data = f.read()
                voter_private_key = serialization.load_pem_private_key(
                pem_data,
                password=None
            )
            public_key = voter_private_key.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            public_key_len = len(voter_private_key.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)).to_bytes(4, byteorder="big")
            voters.extend([voter_id, public_key_len, public_key])
            # voter_pk = voter_private_key.public_key()
            if len(voters) == 15:
                print('**REGISTRATION PERIOD ENDED**')
                print('**GENERATING LIST OF VOTERS FOR COLLECTORS**')
                #Generate message for collectors
                message = [b'\x05', Administrator.election_id]
                for i in range(len(voters)):
                    message.append(voters[i])
                
                signature = Administrator.admin_private_key.sign(
                    pickle.dumps(message),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                signature_len = len(bytes.fromhex(signature.hex())).to_bytes(4, byteorder="big")
                x = [secrets.token_bytes(32), signature_len, bytes.fromhex(signature.hex())]
                # message = message.extend()
                print('**SENDING LIST OF VOTERS FOR COLLECTOR1**')
                for i in x:
                    message.append(i)
                for i in message:
                    print(type(i))
                self.admin_client(Administrator.collector1_port, pickle.dumps(message))
                time.sleep(1)
                print('**SENDING LIST OF VOTERS FOR COLLECTOR2**')
                self.admin_client(Administrator.collector2_port, pickle.dumps(message))
                time.sleep(1)
                print('**COLLECTOR 1 TO INITIALISE PAILIER ONCE ALL COLLECTORS RECEIVE DATA**')
            client.close()

        else:
            client.send(Administrator.election_id)
            client.close()

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

    def __init__(self, collector_index):
        self.collector_index = collector_index
       
        with open(f"data/collector{collector_index}_private_key.pem", "rb") as f:
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
            self.other_C_port = Administrator.collector2_port
            self.other_C_pk = collector2_private_key.public_key()
            # self.other_C_pk_length = len(self.other_C_pk)
            client_thread = threading.Thread(target=self.collector_client)
            server_thread = threading.Thread(target=self.collector_server, args=(self.collector_index, ))
            client_thread.start()
            server_thread.start()
        else:
            self.pk = collector2_private_key.public_key()
            # self.pk_length = len(self.pk)
            # key_hash = hashlib.sha256(self.pk)
            # key_hash = key_hash.digest()
            # self.key_hash = key_hash
            self.other_C_host_length = len(HOST)
            self.other_C_host = HOST
            self.other_C_port = Administrator.collector1_port
            self.other_C_pk = collector1_private_key.public_key()
            # self.other_C_pk_length = len(self.other_C_pk)
            client_thread = threading.Thread(target=self.collector_client)
            server_thread = threading.Thread(target=self.collector_server, args=(self.collector_index, ))
            client_thread.start()
            server_thread.start()
        

    def collector_server(self, collector_index):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        collector_port = 0000
        if int(collector_index) == 1:
            collector_port = 8001
        else:
            collector_port = 8002
        try:
            server.bind((HOST, collector_port))
        except OSError:
            if int(collector_index) == 1:
                Administrator.collector1_port = int(input(f"ENTER PORT FOR COLLECTOR{collector_index} SERVER"))
                collector_port = Administrator.collector1_port
            else:
                Administrator.collector2_port = int(input(f"ENTER PORT FOR COLLECTOR{collector_index} SERVER"))
                collector_port = Administrator.collector2_port
            
            server.bind((HOST, collector_port))
        server.listen(5)
        print(f"COLLECTOR{collector_index} SERVER STARTED at PORT: {collector_port}")
        while True:    
            client, address = server.accept()
            print(f"Connection Established with - PORT : {address[1]}")
            data = client.recv(2024)
            data = pickle.loads(data)
            for i in range(len(data)):
                print(data[i])
            if int(collector_index) == 2:
                print("COLLECTOR 2 RECEIVED VOTER INFO")
            else:
                print("COLLECTOR 1 RECEIVED VOTER INFO, PREPARING TO INITIALIZE PAILLIER CRYPTO")
                # INITIALIZE PAILLIER CRYPTO
                import random

                
    def collector_client(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((HOST, 8000))
        server.sendall(b'R')
        election_id = server.recv(1024)
        Collector.election_id = election_id
        print("Connected to Admin")
        print(f'Election ID: {int.from_bytes(election_id, byteorder="big")}')
        server.close()

    def send_shares():
        # send signed to both collectors
        # message_type TYPE_SHARES
        # key hash
        # election ID
        # N
        ...
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

# Function to generate large primes
def generate_prime(bits):
    p = random.getrandbits(bits)
    while not is_prime(p):
        p = random.getrandbits(bits)
    return p

# Function to check if a number is prime
def is_prime(n):
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i*i <= n:
        print("O")
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

# Function to compute greatest common divisor
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Function to generate a random coprime to n
def random_coprime(n):
    while True:
        r = random.randrange(2, n)
        if gcd(r, n) == 1:
            return r

# Function to compute the modular inverse
def modinv(a, m):
    g, x, _ = gcdextended(a, m)
    if g != 1:
        raise ValueError('Modular inverse does not exist')
    return x % m

# Function to compute the extended Euclidean algorithm
def gcdextended(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = gcdextended(b % a, a)
        return (g, x - (b // a) * y, y)

# Function to generate public and private keys for the Paillier cryptosystem
def generate_paillier_keys():
    # Generate two large primes of equal length
    p = generate_prime(2048)
    q = generate_prime(2048)
    # Compute n = pq and λ = lcm(p-1, q-1)
    n = p * q
    lambda_n = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
    # Compute µ = (L(g^λ mod n^2)^-1) mod n where g=n+1
    g = n + 1
    L = lambda x: (x - 1) // n
    mu = modinv(L(pow(g, lambda_n, n*n)), n)
    # Return public key (n, g) and private key (lambda_n, mu)
    return (n, g), (lambda_n, mu)

# Function to encrypt a message using the Paillier cryptosystem
def paillier_encrypt(m, public_key):
    n, g = public_key
    r = random_coprime(n)
    return (pow(g, m, n*n) * pow(r, n, n*n)) % (n*n)

# Function to decrypt a ciphertext using the Paillier cryptosystem
def paillier_decrypt(c, private_key):
    lambda_n, mu = private_key
    u = (pow(c, lambda_n, mu*mu) - 1) // mu
    return L(u) * modinv(L(pow(n+1, lambda_n, n*n)), n) % n









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


if __name__ == '__main__':
    # get the service name from the command line arguments
    # service_name = sys.argv[1]

    # # start the service based on the service name
    # if service_name == 'admin':
    #     admin = Administrator()
    # elif service_name == 'collector1':
    #     collector1 = Collector(1)
    # elif service_name == 'collector2':
    #     collector2 = Collector(2)
    # elif service_name.startswith('voter'):
    #     print(sys.argv[1][-1])
    #     vote = Voter(sys.argv[1][-1])
    # else:
    #     print('Invalid service name')
    # Example usage
    public_key, private_key = generate_paillier_keys()
    m = 42
    c = paillier_encrypt(m, public_key)
    print(paillier_decrypt(c, private_key)) # Output: 42

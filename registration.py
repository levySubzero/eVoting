import os
import socket
import pickle
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, serialization


def authorized_voter():
    # Generate a 4-byte ID for each voter
    # voter_ids = [os.urandom(4) for _ in range(num_voters)]

    # Generate a public-private key pair for each voter
    # key_pairs = []
    # for _ in range(num_voters):
    voter_id = os.urandom(4)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Serialize the public key and store it along with the voter ID
    # voter_data = []
    # for i in range(num_voters):
        # voter_id = voter_ids[i]
        # public_key = key_pairs[i][1]

    # Save the public keys in separate files
    with open('voter_public.pem', 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    with open("voter_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    serialized_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return (voter_id, private_key, public_key, serialized_public_key)


def generate_metadata(election_id, collector_info, candidate_names):
    metadata = [b'TYPE_METADATA_VOTER', election_id]
    for collector_pk, (host, port, pk) in collector_info.items():
        host_len_bytes = len(host).to_bytes(4, byteorder='big')
        pk_len_bytes = len(pk).to_bytes(4, byteorder='big')
        metadata.append(host_len_bytes)
        metadata.append(host.encode())
        metadata.append(port.to_bytes(2, byteorder='big'))
        metadata.append(pk_len_bytes)
        metadata.append(pk)
    metadata.append(b'\x01')
    for name in candidate_names:
        name_len_bytes = len(name).to_bytes(4, byteorder='big')
        metadata.append(name_len_bytes)
        metadata.append(name.encode())
    return metadata


def handle_voter_request(admin_host, admin_port, voter_public_key_hash, voter_id, candidates):
    # Load the voter's public key from the database
    with open('voter_public_key.pem', 'rb') as f:
        voter_public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    # Generate the voter's message
    message = (b'TYPE_REGISTER', voter_public_key_hash, voter_id)
    message_bytes = pickle.dumps(message)

    with open("voter_private_key.pem", "rb") as f:
        pem_data = f.read()
        voter_private_key = serialization.load_pem_private_key(
        pem_data,
        password=None
    )

    # Sign the message with the voter's private key
    signature = voter_private_key.sign(message_bytes, padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ), hashes.SHA256())

    # Send the message and signature to the administrator
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((admin_host, admin_port))
    message_with_signature = (message, signature)
    sock.send(pickle.dumps(message_with_signature))

    # Receive the metadata and signature from the administrator
    metadata_with_signature = pickle.loads(sock.recv(4096))
    metadata, signature = metadata_with_signature

    with open('administrator_public.pem', "rb") as f:
        pem_data = f.read()

    # Deserialize the PEM data into a public key object
    admin_public_key = serialization.load_pem_public_key(pem_data)

    # Verify the metadata signature
    if not utils.verify(admin_public_key, signature, pickle.dumps(metadata), padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
    ), hashes.SHA256()):
        raise Exception('Invalid signature')

    # Parse the metadata
    election_id = metadata[1]
    collector_info = {}
    i = 2
    while i < len(metadata):
        host_len = int.from_bytes(metadata[i], byteorder='big')
        host = metadata[i + 1][:host_len].decode()
        port = int.from_bytes(metadata[i + 2], byteorder='big')
        pk_len = int.from_bytes(metadata[i + 3], byteorder='big')
        pk = metadata[i + 4]
        collector_info[pk] = (host, port, pk)
        i += 5
    candidate_names = [metadata[-1][1].decode()]

    return election_id, collector_info, candidate_names


#########


def send_voter_list(admin_private_key, collector_public_keys, election_id, voter_list):
    # Serialize voter list
    voter_list_bytes = pickle.dumps(voter_list)

    # Sign message
    message = b'TYPE_VOTERS' + election_id + len(voter_list_bytes).to_bytes(4, 'big') + voter_list_bytes
    signature = admin_private_key.sign(message, padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ), hashes.SHA256())

    # Encrypt message for each collector
    encrypted_messages = {}
    for collector_public_key in collector_public_keys:
        encrypted_message = collector_public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_messages[collector_public_key] = encrypted_message

    return encrypted_messages, signature

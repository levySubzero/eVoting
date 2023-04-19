import socket
import time

if __name__ == "__main__":
    VOTER_IP = '127.0.0.1'
    VOTER_PORT = 6000

    VOTER_IP1 = '127.0.0.1'
    VOTER_PORT1 = 6003

    VOTER_IP2 = '127.0.0.1'
    VOTER_PORT2 = 6005

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((VOTER_IP, VOTER_PORT))
    server.listen(1)
    print("Admin Server Started at {} : {}".format(VOTER_IP, VOTER_PORT))
    print("Collector 1 Server Started at {} : {}".format(VOTER_IP1, VOTER_PORT1))
    print("Collector 2 Server Started at {} : {}".format(VOTER_IP2, VOTER_PORT2))

    while True:
        client, address = server.accept()
        print("***Admin Server***")
        print(f"Connection Established with voter - {address[0]} : {address[1]}")

        string = client.recv(1024)
        # string = string.decode("utf-8")
        string = "Received voter ID and Key Hash"
        string2 = f"\nSending METADATA to voter at {address[0]} : {address[1]}"
        string3 = "Received metadata from admin"
        print(string)
        time.sleep(1)
        print(string2)
        time.sleep(1)
        string = string3.upper()
        client.send(bytes(string, "utf-8"))
        time.sleep(2.5)
        print("***Admin Server***")
        print("voters registered, sending voters to collectors")
        time.sleep(1)
        print("***Collector 1 Server***")
        print("voters received from admin")
        time.sleep(1)
        print("***Collector 2 Server***")
        print("voters received from admin")
        time.sleep(1)
        print("***Collector 1 Server***")
        print("initializing Paillier Cryptosystem")
        


        client.close()
        
        import sys

# import your server and client functions

if __name__ == '__main__':
    # get the service name from the command line arguments
    service_name = sys.argv[1]

    # start the service based on the service name
    if service_name == 'admin':
        start_admin_service()
    elif service_name == 'collector':
        start_collector_service()
    elif service_name == 'voter':
        start_voter_service()
    else:
        print('Invalid service name')

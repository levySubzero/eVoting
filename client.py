import socket

if __name__ == "__main__":
    VOTER_IP = '127.0.0.1'
    VOTER_PORT = 6000

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect((VOTER_IP, VOTER_PORT))
    string = input("Enter Voter ID")
    print("sending voter id and key hash to admin")
    server.send(bytes(string, "utf-8"))
    buffer = server.recv(1024)
    buffer = buffer.decode("utf-8")
    print(f"{buffer}")

    # 
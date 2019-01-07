from socket import*
HOST = '58.87.70.179'
# The remote host
PORT = 8500
# The same port as used by the server
s = None


def startClient():
    BUFSIZE = 1024
    ADDR = (HOST, PORT)
    while True:
        data = input('> ')
        if not data:
            break
        tcpCliSock = socket(AF_INET, SOCK_STREAM)
        tcpCliSock.connect(ADDR)
        tcpCliSock.send(data.encode())
        data = tcpCliSock.recv(BUFSIZE)
        print(data)
        tcpCliSock.close()


if __name__ == "__main__":
    root = startClient()
    root.mainloop()


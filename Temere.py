import os
import time
import ctypes
import ctypes.wintypes
import math
import psutil
from collections import deque
from colorama import init, Fore, Style
init(autoreset=True)
FILE_LIST_DIRECTORY = 0x0001
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
FILE_NOTIFY_CHANGE_SIZE = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
FILE_NOTIFY_CHANGE_SECURITY = 0x00000100
ENTROPY_THRESHOLD = 0.8
MAX_CHECK_SIZE = 1024
RANSOMWARE_THRESHOLD = 5
RANSOMWARE_TIME_WINDOW = 2
kernel32 = ctypes.windll.kernel32
ReadDirectoryChangesW = kernel32.ReadDirectoryChangesW

class FILE_NOTIFY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("NextEntryOffset", ctypes.wintypes.DWORD),
        ("Action", ctypes.wintypes.DWORD),
        ("FileNameLength", ctypes.wintypes.DWORD),
        ("FileName", ctypes.wintypes.WCHAR * 1024)
    ]

def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy / 8.0

def get_process_by_file(file_path):
    try:
        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
            try:
                for file in proc.open_files():
                    if file.path == file_path:
                        return proc
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    except Exception as e:
        print(Fore.RED + f"Error while getting process for file {file_path}: {str(e)}")
    return None

def process_event(fni, folder_path, high_entropy_events):
    action = fni.Action
    filename = fni.FileName[:fni.FileNameLength // 2]
    file_path = os.path.join(folder_path, filename)
    if action in [1, 3]:
        try:
            with open(file_path, "rb") as file:
                data = file.read(MAX_CHECK_SIZE)
                entropy = calculate_entropy(data)
                if entropy > ENTROPY_THRESHOLD:
                    timestamp = time.time()
                    high_entropy_events.append(timestamp)
                    high_entropy_events = deque(
                        [t for t in high_entropy_events if t > time.time() - RANSOMWARE_TIME_WINDOW]
                    )
                    if len(high_entropy_events) > RANSOMWARE_THRESHOLD:
                        print(Fore.RED + Style.BRIGHT + "Ransomware Detected!!!")
                        process = get_process_by_file(file_path)
                        if process:
                            try:
                                process.terminate()
                                print(Fore.RED + f"Process {process.name()} (PID: {process.pid}) was terminated.")
                            except Exception as e:
                                print(Fore.RED + f"Failed to terminate process {process.name()} (PID: {process.pid}): {str(e)}")
                        else:
                            print(Fore.RED + "Process responsible for ransomware activity could not be identified.")
                    else:
                        print(Fore.YELLOW + f"[{time.strftime('%X')}] {filename} High Entropy Modification: {entropy:.4f}")
        except Exception as e:
            pass

def monitor_folder(folder_path, high_entropy_events):
    hDir = kernel32.CreateFileW(
        folder_path,
        FILE_LIST_DIRECTORY,
        0x00000007,
        None,
        0x00000003,
        0x02000000,
        None
    )
    if hDir == -1:
        raise ctypes.WinError()
    buffer = ctypes.create_string_buffer(8192)
    bytes_returned = ctypes.wintypes.DWORD()
    while True:
        result = ReadDirectoryChangesW(
            hDir,
            ctypes.byref(buffer),
            ctypes.sizeof(buffer),
            True,
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_ATTRIBUTES |
            FILE_NOTIFY_CHANGE_SIZE |
            FILE_NOTIFY_CHANGE_LAST_WRITE |
            FILE_NOTIFY_CHANGE_SECURITY,
            ctypes.byref(bytes_returned),
            None,
            None
        )
        if result:
            offset = 0
            while offset < bytes_returned.value:
                fni = ctypes.cast(ctypes.byref(buffer, offset), ctypes.POINTER(FILE_NOTIFY_INFORMATION)).contents
                process_event(fni, folder_path, high_entropy_events)
                if not fni.NextEntryOffset:
                    break
                offset += fni.NextEntryOffset

def main():
    print(Fore.WHITE + "Temere Ransomware Monitor v1.0")
    print(Fore.WHITE + "==============================")
    print(Fore.WHITE + "Currently Monitoring System..")
    common_folders = [
        os.path.join(os.path.expanduser("~"), "Desktop"),
        os.path.join(os.path.expanduser("~"), "Documents"),
        os.path.join(os.path.expanduser("~"), "Downloads"),
        os.path.join(os.path.expanduser("~"), "Pictures"),
        os.path.join(os.path.expanduser("~"), "Videos"),
        os.path.join(os.path.expanduser("~"), "Music")
    ]
    high_entropy_events = deque()
    for folder in common_folders:
        monitor_folder(folder, high_entropy_events)
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "Monitoring stopped.")

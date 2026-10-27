import time
import ctypes
from ctypes import wintypes

user32 = ctypes.windll.user32

hwnds = []
def enum_cb(hwnd, lparam):
    if user32.IsWindowVisible(hwnd):
        buff = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, buff, 512)
        if "Aegis-Lab-Android" in buff.value:
            hwnds.append(hwnd)
    return True

WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, ctypes.c_void_p)
user32.EnumWindows(WNDENUMPROC(enum_cb), None)

if not hwnds:
    print("VM window not found")
    exit(1)

hwnd = hwnds[0]
user32.ShowWindow(hwnd, 9)
user32.SetForegroundWindow(hwnd)
time.sleep(0.3)

# Key constants
VK_MENU = 0x12 # Alt
VK_F1 = 0x70
VK_F7 = 0x76
KEYEVENTF_KEYUP = 0x0002

def press_alt_f1():
    user32.keybd_event(VK_MENU, 0, 0, 0)
    time.sleep(0.05)
    user32.keybd_event(VK_F1, 0, 0, 0)
    time.sleep(0.05)
    user32.keybd_event(VK_F1, 0, KEYEVENTF_KEYUP, 0)
    user32.keybd_event(VK_MENU, 0, KEYEVENTF_KEYUP, 0)
    time.sleep(1.0)

print("Sending Alt+F1 to switch to console...")
press_alt_f1()

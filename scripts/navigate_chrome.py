import time
import ctypes

user32 = ctypes.windll.user32

hwnd = 4001024
user32.ShowWindow(hwnd, 9)
user32.SetForegroundWindow(hwnd)
time.sleep(0.5)

# Focus omnibar with Ctrl+L
VK_CONTROL = 0x11
VK_L = 0x4C
user32.keybd_event(VK_CONTROL, 0, 0, 0)
time.sleep(0.05)
user32.keybd_event(VK_L, 0, 0, 0)
time.sleep(0.05)
user32.keybd_event(VK_L, 0, 2, 0)
user32.keybd_event(VK_CONTROL, 0, 2, 0)
time.sleep(0.5)

# Type URL: http://172.17.240.1:8000/Aegis-Security.apk
url = "http://172.17.240.1:8000/Aegis-Security.apk"

for ch in url:
    # Send char as unicode key event
    code = ord(ch)
    # KEYEVENTF_UNICODE = 0x0004
    user32.keybd_event(0, code, 4, 0)
    time.sleep(0.02)
    user32.keybd_event(0, code, 4 | 2, 0)
    time.sleep(0.02)

time.sleep(0.5)
# Press Enter (VK_RETURN = 0x0D)
user32.keybd_event(0x0D, 0, 0, 0)
time.sleep(0.05)
user32.keybd_event(0x0D, 0, 2, 0)
print("Typed URL and pressed Enter")
time.sleep(2.0)

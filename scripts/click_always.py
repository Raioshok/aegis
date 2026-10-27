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

rect = wintypes.RECT()
user32.GetWindowRect(hwnd, ctypes.byref(rect))
width = rect.right - rect.left
height = rect.bottom - rect.top

always_x = rect.left + int(width * 0.60)
always_y = rect.top + int(height * 0.53)

print(f"Clicking ALWAYS at ({always_x}, {always_y})")
user32.SetCursorPos(always_x, always_y)
time.sleep(0.05)
user32.mouse_event(2, 0, 0, 0, 0) # LEFTDOWN
time.sleep(0.05)
user32.mouse_event(4, 0, 0, 0, 0) # LEFTUP
time.sleep(1.0)

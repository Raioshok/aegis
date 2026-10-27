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

# 1. Click Home button
home_x = rect.left + int(width * 0.50)
home_y = rect.top + int(height * 0.97)

print(f"Clicking Home button at ({home_x}, {home_y})")
user32.SetCursorPos(home_x, home_y)
time.sleep(0.05)
user32.mouse_event(2, 0, 0, 0, 0) # LEFTDOWN
time.sleep(0.05)
user32.mouse_event(4, 0, 0, 0, 0) # LEFTUP
time.sleep(1.0)

# 2. Swipe up from bottom
start_y = rect.top + int(height * 0.85)
end_y = rect.top + int(height * 0.25)
center_x = rect.left + int(width * 0.50)

print(f"Swiping up from ({center_x}, {start_y}) to ({center_x}, {end_y})")
user32.SetCursorPos(center_x, start_y)
time.sleep(0.1)
user32.mouse_event(2, 0, 0, 0, 0) # LEFTDOWN
time.sleep(0.05)

# Drag in steps
steps = 20
for i in range(steps):
    curr_y = start_y - int((start_y - end_y) * (i / float(steps)))
    user32.SetCursorPos(center_x, curr_y)
    time.sleep(0.02)

user32.SetCursorPos(center_x, end_y)
time.sleep(0.05)
user32.mouse_event(4, 0, 0, 0, 0) # LEFTUP
time.sleep(1.5)

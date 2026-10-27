import time
import ctypes
from ctypes import wintypes

user32 = ctypes.windll.user32

hwnd = 4001024
user32.ShowWindow(hwnd, 9)
user32.SetForegroundWindow(hwnd)
time.sleep(0.3)

rect = wintypes.RECT()
user32.GetWindowRect(hwnd, ctypes.byref(rect))
width = rect.right - rect.left
height = rect.bottom - rect.top

print(f"VM Window bounds: {width}x{height} at ({rect.left}, {rect.top})")

# Calculate START button position (~58% X, ~58% Y)
btn_x = rect.left + int(width * 0.58)
btn_y = rect.top + int(height * 0.58)

print(f"Clicking START at ({btn_x}, {btn_y})")
user32.SetCursorPos(btn_x, btn_y)
time.sleep(0.1)
user32.mouse_event(2, 0, 0, 0, 0) # LEFTDOWN
time.sleep(0.05)
user32.mouse_event(4, 0, 0, 0, 0) # LEFTUP
time.sleep(2.0)

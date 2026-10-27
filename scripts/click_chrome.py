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

chrome_x = rect.left + int(width * 0.44)
chrome_y = rect.top + int(height * 0.90)

print(f"Clicking Chrome icon directly at ({chrome_x}, {chrome_y})")
user32.SetCursorPos(chrome_x, chrome_y)
time.sleep(0.1)
user32.mouse_event(2, 0, 0, 0, 0) # LEFTDOWN
time.sleep(0.08)
user32.mouse_event(4, 0, 0, 0, 0) # LEFTUP
time.sleep(2.5)

import os
import time
import ctypes
from ctypes import wintypes
from PIL import Image

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32

hwnds = []
def enum_cb(hwnd, lparam):
    if user32.IsWindowVisible(hwnd):
        buff = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, buff, 512)
        if "Aegis-Lab-Android" in buff.value:
            hwnds.append((hwnd, buff.value))
    return True

WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, ctypes.c_void_p)
user32.EnumWindows(WNDENUMPROC(enum_cb), None)

print("Found vmconnect HWNDs:", hwnds)

if not hwnds:
    exit(1)

hwnd, title = hwnds[0]

# Bring to top
HWND_TOPMOST = -1
HWND_NOTOPMOST = -2
SWP_NOSIZE = 0x0001
SWP_NOMOVE = 0x0002
SWP_SHOWWINDOW = 0x0040

user32.ShowWindow(hwnd, 9)
user32.SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW)
user32.SetForegroundWindow(hwnd)
time.sleep(0.5)

rect = wintypes.RECT()
user32.GetWindowRect(hwnd, ctypes.byref(rect))
width = rect.right - rect.left
height = rect.bottom - rect.top

hwndDC = user32.GetWindowDC(hwnd)
mfcDC = gdi32.CreateCompatibleDC(hwndDC)
saveBitMap = gdi32.CreateCompatibleBitmap(hwndDC, width, height)
gdi32.SelectObject(mfcDC, saveBitMap)

user32.PrintWindow(hwnd, mfcDC, 2)

class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ('biSize', wintypes.DWORD),
        ('biWidth', wintypes.LONG),
        ('biHeight', wintypes.LONG),
        ('biPlanes', wintypes.WORD),
        ('biBitCount', wintypes.WORD),
        ('biCompression', wintypes.DWORD),
        ('biSizeImage', wintypes.DWORD),
        ('biXPelsPerMeter', wintypes.LONG),
        ('biYPelsPerMeter', wintypes.LONG),
        ('biClrUsed', wintypes.DWORD),
        ('biClrImportant', wintypes.DWORD)
    ]

bmi = BITMAPINFOHEADER()
bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
bmi.biWidth = width
bmi.biHeight = -height
bmi.biPlanes = 1
bmi.biBitCount = 32
bmi.biCompression = 0

buf = (ctypes.c_char * (width * height * 4))()
gdi32.GetDIBits(mfcDC, saveBitMap, 0, height, buf, ctypes.byref(bmi), 0)

img = Image.frombytes('RGBA', (width, height), buf, 'raw', 'BGRA')
out_path = r"docs\assets\screenshots\android_vm_screen.png"
img.convert('RGB').save(out_path)
print(f"Captured Android VM: {out_path} ({os.path.getsize(out_path)} bytes)")

user32.SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE)
gdi32.DeleteObject(saveBitMap)
gdi32.DeleteDC(mfcDC)
user32.ReleaseDC(hwnd, hwndDC)

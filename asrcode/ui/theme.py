"""System caption typography and screen-bounded window placement."""
import sys
from PyQt5.QtCore import QRect
from PyQt5.QtGui import QFont, QFontDatabase

def title_font():
    fallback=QFontDatabase.systemFont(QFontDatabase.TitleFont)
    if sys.platform=='win32':
        try:
            import ctypes as c
            from ctypes import wintypes as w
            class LOGFONT(c.Structure):
                _fields_=[('height',w.LONG),('width',w.LONG),('escape',w.LONG),
                          ('orientation',w.LONG),('weight',w.LONG),
                          ('italic',w.BYTE),('underline',w.BYTE),('strike',w.BYTE),
                          ('charset',w.BYTE),('out',w.BYTE),('clip',w.BYTE),
                          ('quality',w.BYTE),('pitch',w.BYTE),('face',w.WCHAR*32)]
            class Metrics(c.Structure):
                _fields_=[('size',w.UINT),('border',c.c_int),('scrollw',c.c_int),('scrollh',c.c_int),
                          ('captionw',c.c_int),('captionh',c.c_int),('caption',LOGFONT),
                          ('smallw',c.c_int),('smallh',c.c_int),('small',LOGFONT),
                          ('menuw',c.c_int),('menuh',c.c_int),('menu',LOGFONT),
                          ('status',LOGFONT),('message',LOGFONT),('padded',c.c_int)]
            m=Metrics();m.size=c.sizeof(m);user=c.windll.user32
            if hasattr(user,'SystemParametersInfoForDpi'):
                ok=user.SystemParametersInfoForDpi(0x29,m.size,c.byref(m),0,96)
                dpi=96
            else:
                ok=user.SystemParametersInfoW(0x29,m.size,c.byref(m),0)
                dpi=user.GetDpiForSystem() if hasattr(user,'GetDpiForSystem') else 96
            if ok and m.caption.height:
                font=QFont(m.caption.face or fallback.family())
                font.setPointSizeF(abs(m.caption.height)*72.0/max(1,dpi))
                return font
        except (AttributeError,OSError,ValueError):
            pass
    if fallback.pointSizeF()<=0:fallback.setPointSizeF(9)
    return fallback

def default_window_rect(area):
    """Work in Qt logical coordinates; never multiply OS scaling twice."""
    rect=QRect(0,0,max(1,min(1180,int(area.width()*.88))),max(1,min(780,int(area.height()*.90))))
    rect.moveCenter(area.center())
    return rect

def bounded_frame(area,frame):
    rect=QRect(frame)
    rect.setWidth(min(max(1,rect.width()),area.width()))
    rect.setHeight(min(max(1,rect.height()),area.height()))
    rect.moveLeft(max(area.left(),min(rect.left(),area.right()-rect.width()+1)))
    rect.moveTop(max(area.top(),min(rect.top(),area.bottom()-rect.height()+1)))
    return rect

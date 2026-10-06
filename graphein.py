import webview
import os
import re
import io
import sys
import base64
import time
import json
import logging
import webbrowser
import hashlib
import mimetypes
import urllib.parse
import urllib.request
import subprocess
import tempfile
import shutil
import threading
import winsound
from pathlib import Path
from ctypes import wintypes
import struct
import ctypes
import ipaddress
import random
import socket
import urllib.error
import gzip
import zlib


logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)
if getattr(sys, 'frozen', False):
    BUNDLE_DIR = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
    EXE_DIR = os.path.dirname(sys.executable)
else:
    BUNDLE_DIR = os.path.dirname(os.path.abspath(__file__))
    EXE_DIR = BUNDLE_DIR
    
    
try:
    os.chdir(EXE_DIR)
except Exception:
    pass

                                                                        
if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w')

HTML_FILE = os.path.join(BUNDLE_DIR, 'index.html')
if not os.path.exists(HTML_FILE):
    HTML_FILE = os.path.join(EXE_DIR, 'index.html')

ICON_FILE = os.path.abspath(os.path.join(BUNDLE_DIR, 'assets', 'app_icon.ico'))
if not os.path.exists(ICON_FILE):
    ICON_FILE = os.path.abspath(os.path.join(EXE_DIR, 'assets', 'app_icon.ico'))


                                                                             
                                                      
                                                    
                                                                             
appdata_base = os.environ.get('APPDATA') or str(Path.home() / 'AppData' / 'Roaming')
USER_DATA_DIR = os.path.join(appdata_base, 'Graphein')

                                                                    
os.makedirs(USER_DATA_DIR, exist_ok=True)

SETTINGS_FILE = os.path.join(USER_DATA_DIR, 'settings.json')
PERMISSIONS_FILE = os.path.join(USER_DATA_DIR, 'image_permissions.json')
BACKUP_DIR = os.path.join(USER_DATA_DIR, 'backups')
os.makedirs(BACKUP_DIR, exist_ok=True)


logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[logging.NullHandler()],
    force=True
)

def _excepthook(exc_type, exc, tb):
    logging.getLogger('crash').critical('Uncaught exception', exc_info=(exc_type, exc, tb))
sys.excepthook = _excepthook

BACKUP_MAX_AGE_DAYS = 21
ALLOWED_IMG_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp', '.ico'}
MAX_IMAGE_PERMISSIONS = 1000

DEFAULT_SETTINGS = {
    "fontSizeLeft": 18,
    "fontSizeRight": 16,
    "pad_l_v": 1.5, "pad_l_h": 2.5,
    "pad_r_v": 2.5, "pad_r_h": 3.5,
    "themeEditor": "default",
    "themeGlobal": "theme-neo",
    "sidebarOpen": False,
    "leftPaneWidth": 50, 
    "sidebarWidth": 250,   
    "adaptiveImageColoring": False,
    "a4Preview": True,
    "spellLanguages": [],
    "editorHighlighting": True,
    "tabs": [],
    "activeTabPath": None
}



logger = logging.getLogger(__name__)


class SecurityException(Exception):
    pass


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):

    def __init__(self, validator_fn, max_redirects=3):
        self.validator_fn = validator_fn
        self.max_redirects = max_redirects
        self.redirect_count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirect_count += 1
        if self.redirect_count > self.max_redirects:
            raise SecurityException("Too many redirects.")

                                                                                       
        full_newurl = urllib.parse.urljoin(req.full_url, newurl)

        is_safe, error_msg = self.validator_fn(full_newurl)
        if not is_safe:
            raise SecurityException(f"Unsafe redirect blocked: {error_msg}")

        return super().redirect_request(req, fp, code, msg, headers, full_newurl)


class SafeImageFetcher:
    ALLOWED_PORTS = {80, 443}
    MAX_IMAGE_SIZE = 15 * 1024 * 1024               
    CHUNK_SIZE = 64 * 1024

    @classmethod
    def get_image_headers(cls) -> dict:
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Sec-Fetch-Dest': 'image',
            'Sec-Fetch-Mode': 'no-cors',
            'Sec-Fetch-Site': 'cross-site'
        }

    @classmethod
    def validate_url(cls, url: str) -> tuple[bool, str]:
        try:
            parsed = urllib.parse.urlsplit(url)

            if parsed.scheme not in ('http', 'https'):
                return False, "Only HTTP and HTTPS protocols are allowed."

            if parsed.username or parsed.password:
                return False, "Embedded credentials in URL are not allowed."

            port = parsed.port
            if port is not None and port not in cls.ALLOWED_PORTS:
                return False, f"Port {port} is not allowed."

            domain = parsed.hostname
            if not domain:
                return False, "Invalid or missing hostname."

            try:
                domain = domain.encode('idna').decode('ascii').lower()
            except Exception:
                return False, "Invalid domain encoding."

            banned_exact_hosts = {'localhost', '0.0.0.0', '127.0.0.1', '::1', '::'}
            if domain in banned_exact_hosts or domain.endswith(('.local', '.lan', '.internal', '.home')):
                return False, "Local and internal network domains are forbidden."

            try:
                ipaddress.ip_address(domain.strip('[]'))
                return False, "Direct IP addresses are not allowed."
            except ValueError:
                pass

            parts = domain.split('.')
            if len(parts) < 2 or not parts[-1].isalpha():
                return False, "Invalid domain name structure."

                                                                                    
            resolved_port = port or (443 if parsed.scheme == 'https' else 80)
            addr_info = socket.getaddrinfo(domain, resolved_port)
            for _, _, _, _, sockaddr in addr_info:
                ip = ipaddress.ip_address(sockaddr[0])
                if (ip.is_private or ip.is_loopback or ip.is_link_local or
                        ip.is_reserved or ip.is_multicast):
                    return False, "Domain resolves to a protected or private IP address."

            return True, ""
        except Exception as e:
            return False, f"Validation error: {e}"

    @staticmethod
    def decompress(data: bytes, encoding: str = "") -> bytes:
        encoding = encoding.lower()
        if 'gzip' in encoding or data.startswith(b'\x1f\x8b'):
            try:
                return gzip.decompress(data)
            except Exception:
                pass
        elif 'deflate' in encoding:
            try:
                return zlib.decompress(data)
            except Exception:
                try:
                    return zlib.decompress(data, -zlib.MAX_WBITS)
                except Exception:
                    pass
        return data

    @staticmethod
    def detect_real_mime(data: bytes) -> str | None:
        """Inspects magic bytes to determine the actual image format."""
        if data.startswith(b'\x89PNG\r\n\x1a\n'):
            return 'image/png'
        if data.startswith(b'\xff\xd8\xff'):
            return 'image/jpeg'
        if data.startswith((b'GIF87a', b'GIF89a')):
            return 'image/gif'
        if data.startswith(b'RIFF') and len(data) >= 12 and data[8:12] == b'WEBP':
            return 'image/webp'
        if data.startswith(b'BM'):
            return 'image/bmp'
        if data.startswith(b'\x00\x00\x01\x00'):
            return 'image/x-icon'

                                                      
        if len(data) >= 12 and data[4:8] == b'ftyp':
            major_brand = data[8:12]
            if major_brand in (b'avif', b'avis'):
                return 'image/avif'
            if major_brand in (b'heic', b'heix', b'mif1', b'msf1'):
                return 'image/heic'
            if b'avif' in data[8:64]:
                return 'image/avif'

                                                                             
        sample = data[:8192].lower()
        if b'<svg' in sample or (b'<?xml' in sample and b'<svg' in data[:65536].lower()):
            return 'image/svg+xml'

        return None


                                                                             
                                                                   
                                                                       
                                                                             
class _GUID(ctypes.Structure):
    _fields_ = [("d1", wintypes.DWORD), ("d2", wintypes.WORD),
                ("d3", wintypes.WORD), ("d4", ctypes.c_ubyte * 8)]


_PPV = ctypes.POINTER(ctypes.c_void_p)
_PULONG = ctypes.POINTER(wintypes.ULONG)
_ole32 = None


def _get_ole32():
    global _ole32
    if _ole32 is None:
        o = ctypes.WinDLL('ole32')
        o.CoInitializeEx.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        o.CoInitializeEx.restype = ctypes.c_long
        o.CoUninitialize.argtypes = []
        o.CoUninitialize.restype = None
        o.CoTaskMemFree.argtypes = [ctypes.c_void_p]
        o.CoTaskMemFree.restype = None
        for fn in (o.CLSIDFromString, o.IIDFromString):
            fn.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(_GUID)]
            fn.restype = ctypes.c_long
        o.CoCreateInstance.argtypes = [ctypes.POINTER(_GUID), ctypes.c_void_p, wintypes.DWORD,
                                       ctypes.POINTER(_GUID), _PPV]
        o.CoCreateInstance.restype = ctypes.c_long
        _ole32 = o
    return _ole32


def _vcall(ptr, index, argtypes, *args):
    vtbl = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_void_p))[0]
    fn = ctypes.cast(vtbl, ctypes.POINTER(ctypes.c_void_p))[index]
    proto = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, *argtypes)
    return proto(fn)(ptr, *args)


def _release(ptr):
    if ptr:
        _vcall(ptr, 2, ())


def _take_string(addr):
    if not addr:
        return ""
    try:
        return ctypes.wstring_at(addr)
    finally:
        _get_ole32().CoTaskMemFree(addr)


def _enum_strings(enum_ptr, limit=500):
    out = []
    while len(out) < limit:
        s, fetched = ctypes.c_void_p(), wintypes.ULONG(0)
        hr = _vcall(enum_ptr, 3, (wintypes.ULONG, _PPV, _PULONG), 1, ctypes.byref(s), ctypes.byref(fetched))
        if hr != 0 or fetched.value == 0 or not s.value:
            break
        out.append(_take_string(s.value))
    return out


class _ComApartment:
    def __enter__(self):
        self._ok = _get_ole32().CoInitializeEx(None, 2) >= 0                            
        return self

    def __exit__(self, *exc):
        if self._ok:
            _get_ole32().CoUninitialize()


class WinSpell:
    CLSID_FACTORY = "{7AB36653-1796-484B-BDFA-E74F1DB7C1DC}"
    IID_FACTORY = "{8E018A9D-2415-4677-BF08-794EA61F94BB}"

                                                                                                       
    _MASK = [re.compile(p, re.S) for p in (
        r'```.*?```', r'~~~.*?~~~', r'`[^`\n]+`', r'\$\$.*?\$\$', r'(?<!\\)\$[^$\n]+\$',
        r'<[^>\n]+>', r'(?<=\])\([^)\n]*\)', r'https?://\S+|www\.\S+', r'\S+@\S+\.\S+', r'&#?\w+;',
    )]

    @classmethod
    def _mask_markup(cls, text):
        def blank(m):
            return ''.join('\n' if c == '\n' else ' ' * (len(c.encode('utf-16-le', 'surrogatepass')) // 2)
                           for c in m.group(0))
        for rx in cls._MASK:
            text = rx.sub(blank, text)
        return text

    @classmethod
    def _create_factory(cls):
        ole = _get_ole32()
        clsid, iid, ppv = _GUID(), _GUID(), ctypes.c_void_p()
        ole.CLSIDFromString(cls.CLSID_FACTORY, ctypes.byref(clsid))
        ole.IIDFromString(cls.IID_FACTORY, ctypes.byref(iid))
        hr = ole.CoCreateInstance(ctypes.byref(clsid), None, 1, ctypes.byref(iid), ctypes.byref(ppv))                 
        if hr < 0 or not ppv.value:
            raise OSError(f"Windows spellchecker unavailable (HRESULT 0x{hr & 0xFFFFFFFF:08X})")
        return ppv.value

    @staticmethod
    def _supported_tags(factory):
        pe = ctypes.c_void_p()
        if _vcall(factory, 3, (_PPV,), ctypes.byref(pe)) < 0 or not pe.value:                          
            return []
        try:
            return _enum_strings(pe.value)
        finally:
            _release(pe.value)

    @staticmethod
    def _display_name(tag):
        try:
            k32 = ctypes.WinDLL('kernel32')
            k32.GetLocaleInfoEx.argtypes = [ctypes.c_wchar_p, wintypes.DWORD, ctypes.c_wchar_p, ctypes.c_int]
            k32.GetLocaleInfoEx.restype = ctypes.c_int
            buf = ctypes.create_unicode_buffer(160)
            if k32.GetLocaleInfoEx(tag, 0x2, buf, 160):                                
                return buf.value
        except Exception:
            pass
        return tag

    @classmethod
    def languages(cls):
        with _ComApartment():
            factory = cls._create_factory()
            try:
                tags = cls._supported_tags(factory)
            finally:
                _release(factory)
        langs = [{'tag': t, 'name': cls._display_name(t)} for t in tags]
        return sorted(langs, key=lambda l: l['name'].lower())

    @staticmethod
    def _check(chk, text):
        out = []
        pe = ctypes.c_void_p()
        if _vcall(chk, 4, (ctypes.c_wchar_p, _PPV), text, ctypes.byref(pe)) < 0 or not pe.value:
            return out
        try:
            while True:
                err = ctypes.c_void_p()
                if _vcall(pe.value, 3, (_PPV,), ctypes.byref(err)) != 0 or not err.value:
                    break
                try:
                    st, ln, act, rep = wintypes.ULONG(), wintypes.ULONG(), ctypes.c_int(), ctypes.c_void_p()
                    _vcall(err.value, 3, (_PULONG,), ctypes.byref(st))
                    _vcall(err.value, 4, (_PULONG,), ctypes.byref(ln))
                    _vcall(err.value, 5, (ctypes.POINTER(ctypes.c_int),), ctypes.byref(act))
                    replacement = ""
                    if act.value == 2 and _vcall(err.value, 6, (_PPV,), ctypes.byref(rep)) >= 0:
                        replacement = _take_string(rep.value)
                    out.append({'s': st.value, 'l': ln.value, 'a': act.value, 'r': replacement})
                finally:
                    _release(err.value)
        finally:
            _release(pe.value)
        return out

    @staticmethod
    def _suggest(chk, word, limit):
        pe = ctypes.c_void_p()
        if _vcall(chk, 5, (ctypes.c_wchar_p, _PPV), word, ctypes.byref(pe)) < 0 or not pe.value:
            return []
        try:
            return _enum_strings(pe.value, limit)
        finally:
            _release(pe.value)

    MAX_CHARS = 30000

    @classmethod
    def check(cls, text, tags, only=None, max_errors=300, per_lang=4, max_total=8):
        tags = list(dict.fromkeys(tags))[:3]
        if len(text) > cls.MAX_CHARS:
            return {'success': False, 'error': f'Selection too long (max {cls.MAX_CHARS} characters).'}
        text = text.replace('\x00', ' ')
        if not text.strip():
            return {'success': True, 'errors': [], 'skipped': [], 'truncated': False}
        masked = cls._mask_markup(text)
        u16 = text.encode('utf-16-le', 'surrogatepass')
        with _ComApartment():
            factory = cls._create_factory()
            checkers, skipped = [], []
            try:
                supported = {t.lower() for t in cls._supported_tags(factory)}
                for tag in tags:
                    chk = ctypes.c_void_p()
                    if tag.lower() in supported and \
                            _vcall(factory, 5, (ctypes.c_wchar_p, _PPV), tag, ctypes.byref(chk)) >= 0 and chk.value:
                        checkers.append((tag, chk.value))
                    else:
                        skipped.append(tag)
                if not checkers:
                    return {'success': False, 'error': 'None of the selected languages is available in Windows. '
                            'Add the language in Windows Settings > Time & language.'}

                chk_by_tag = dict(checkers)
                if only not in chk_by_tag:
                    only = None
                found = {tag: cls._check(chk, masked) for tag, chk in checkers}
                base_tag = only or checkers[0][0]

                def overlap(a, b):
                    return a['s'] < b['s'] + b['l'] and b['s'] < a['s'] + a['l']

                                                                     
                cands = []
                for base in found[base_tag]:
                    ms, foreign = {base_tag: base}, []
                    for tag, _ in checkers:
                        if tag == base_tag:
                            continue
                        m = next((o for o in found[tag] if overlap(base, o)), None)
                        if m:
                            ms[tag] = m
                        else:
                            foreign.append(tag)
                    if foreign and only is None:
                        continue                                                              
                    word = u16[base['s'] * 2:(base['s'] + base['l']) * 2].decode('utf-16-le', 'surrogatepass')
                    if word.strip():
                        cands.append((base, ms, foreign, word))

                                                                                      
                cands.sort(key=lambda c: (bool(c[2]), c[0]['s']))
                truncated = len(cands) > max_errors
                cands = cands[:max_errors]

                                                                                              
                sugg_tags = [t for t, _ in checkers] if only is None else [only]
                n_each = per_lang if only is None else max_total
                errors = []
                for base, ms, foreign, word in cands:
                    per = []
                    for tag in sugg_tags:
                        m, lst = ms[tag], []
                        if m['a'] == 2 and m['r']:
                            lst.append(m['r'])
                        elif m['a'] == 3:
                            lst.append("")
                        lst += cls._suggest(chk_by_tag[tag], word, n_each)
                        per.append([(s, tag) for s in lst[:n_each]])
                    sugg, seen = [], set()
                    for i in range(n_each):
                        for lst in per:
                            if i < len(lst) and lst[i][0].lower() not in seen and len(sugg) < max_total:
                                seen.add(lst[i][0].lower())
                                sugg.append({'text': lst[i][0], 'lang': lst[i][1]})
                    errors.append({'start': base['s'], 'length': base['l'], 'word': word,
                                   'suggestions': sugg, 'foreign': foreign})
                return {'success': True, 'errors': errors, 'skipped': skipped, 'truncated': truncated}
            finally:
                for _, chk in checkers:
                    _release(chk)
                _release(factory)


class Api:
    def __init__(self):
        self._window = None
        self.is_closing = False
        self._watched_files = {} 
        self._pending_open = []
        self._open_lock = threading.Lock()
        self._watcher_lock = threading.Lock()
        threading.Thread(target=self._cleanup_old_backups, daemon=True).start()
        threading.Thread(target=self._file_watcher_loop, daemon=True).start()

    def set_window(self, window):
        self._window = window

    def _cleanup_old_backups(self):
        if not os.path.exists(BACKUP_DIR):
            return

        now = time.time()
        max_age_sec = BACKUP_MAX_AGE_DAYS * 24 * 60 * 60

        for filename in os.listdir(BACKUP_DIR):
            file_path = os.path.join(BACKUP_DIR, filename)
            if os.path.isfile(file_path):
                if os.path.getmtime(file_path) < (now - max_age_sec):
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        logger.warning(f"Couldn't delete backup '{file_path}': {e}")


    def load_settings(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return {**DEFAULT_SETTINGS, **data}
            except Exception as e:
                logger.warning(f"Couldn't load settings, started with default settings: {e}")
        return DEFAULT_SETTINGS.copy()

    def save_settings(self, settings_dict):
        try:
            with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
                json.dump(settings_dict, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Couldn't save settings: {e}")
            return False
            
    def _get_file_signature(self, filepath):
        try:
            if not filepath or not os.path.exists(filepath):
                return None
            stat = os.stat(filepath)
                                                                                       
            return f"{stat.st_ctime:.6f}_{getattr(stat, 'st_ino', 0)}"
        except Exception as e:
            logger.warning(f"Couldn't verify file signature for '{filepath}': {e}")
            return None

    def get_image_permission(self, filepath):
        if not filepath or not os.path.exists(filepath) or not os.path.exists(PERMISSIONS_FILE):
            return None
        try:
            real_path = os.path.realpath(filepath)
            current_sig = self._get_file_signature(real_path)
            if not current_sig:
                return None

            with open(PERMISSIONS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)

            entry = data.get(real_path)
            if entry is None:
                return None

            saved_sig = entry.get("sig") if isinstance(entry, dict) else entry
            is_allowed = entry.get("allowed", True) if isinstance(entry, dict) else True

            if saved_sig == current_sig:
                return is_allowed

                                                                
            data.pop(real_path, None)
            with open(PERMISSIONS_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
            return None
        except Exception as e:
            logger.warning(f"Couldn't read image permission: {e}")
            return None
            
    def get_spellcheck_languages(self):
        if sys.platform != 'win32':
            return {'success': False, 'error': 'The Windows spellchecker is only available on Windows.'}
        try:
            return {'success': True, 'languages': WinSpell.languages()}
        except Exception as e:
            logger.error(f"Couldn't list spellcheck languages: {e}")
            return {'success': False, 'error': str(e)}

    def spellcheck_text(self, text, languages, only=None):
        if sys.platform != 'win32':
            return {'success': False, 'error': 'The Windows spellchecker is only available on Windows.'}
        try:
            tags = [t for t in (languages or []) if isinstance(t, str) and re.fullmatch(r'[A-Za-z0-9-]{2,35}', t)]
            if not tags or not isinstance(text, str):
                return {'success': False, 'error': 'No spellcheck language selected.'}
            if not (isinstance(only, str) and only in tags[:3]):
                only = None
            return WinSpell.check(text, tags[:3], only)
        except Exception as e:
            logger.error(f"Spellcheck failed: {e}")
            return {'success': False, 'error': str(e)}

    def open_about(self):
        try:
            content = self._get_about_markdown()
            return {
                'success': True,
                'filepath': None,          
                'filename': 'about_graphein.md',
                'content': content,
                'isAbout': True
            }
        except Exception as e:
            logger.error(f"Error generating about file: {e}")
            return {'success': False, 'error': str(e)}

    def save_image_permission(self, filepath, allowed: bool, explicit_block: bool = False):
        if not filepath:
            return False
        try:
            real_path = os.path.realpath(filepath)
            data = {}
            if os.path.exists(PERMISSIONS_FILE):
                try:
                    with open(PERMISSIONS_FILE, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                except Exception:
                    data = {}

            sig = self._get_file_signature(real_path)
            if not sig:
                return False

            now = time.time()

            if allowed is True:
                data[real_path] = {"sig": sig, "allowed": True, "timestamp": now}
            elif allowed is False and explicit_block:
                data[real_path] = {"sig": sig, "allowed": False, "timestamp": now}
            else:
                data.pop(real_path, None)

                                                                              
            if len(data) > MAX_IMAGE_PERMISSIONS:
                                                                                                
                sorted_keys = sorted(
                    data.keys(),
                    key=lambda k: data[k].get("timestamp", 0) if isinstance(data[k], dict) else 0
                )
                excess = len(data) - MAX_IMAGE_PERMISSIONS
                for old_key in sorted_keys[:excess]:
                    data.pop(old_key, None)

            os.makedirs(os.path.dirname(PERMISSIONS_FILE), exist_ok=True)
            with open(PERMISSIONS_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Couldn't save image permission: {e}")
            return False


    def export_to_pdf(self, html_content, default_filename="document.pdf"):
        if sys.platform != 'win32':
            return {'success': False, 'error': 'PDF-export only supported on windows'}

        result = self._window.create_file_dialog(
            webview.FileDialog.SAVE,
            file_types=('PDF Files (*.pdf)',),
            save_filename=default_filename
        )
        if not result:
            return {'success': False, 'error': 'Cancelled'}

        target_path = result[0]
        if not target_path.lower().endswith('.pdf'):
            target_path += '.pdf'

        local_app = os.environ.get('LOCALAPPDATA', '')
        program_files = os.environ.get('ProgramFiles', r'C:\Program Files')
        program_files_x86 = os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')

        browsers = [
            os.path.join(program_files, r"Microsoft\Edge\Application\msedge.exe"),
            os.path.join(program_files_x86, r"Microsoft\Edge\Application\msedge.exe"),
            
            os.path.join(program_files, r"Google\Chrome\Application\chrome.exe"),
            os.path.join(program_files_x86, r"Google\Chrome\Application\chrome.exe"),
            os.path.join(local_app, r"Google\Chrome\Application\chrome.exe"),
            
            os.path.join(program_files, r"BraveSoftware\Brave-Browser\Application\brave.exe"),
            os.path.join(program_files_x86, r"BraveSoftware\Brave-Browser\Application\brave.exe"),
            os.path.join(local_app, r"BraveSoftware\Brave-Browser\Application\brave.exe"),

            os.path.join(local_app, r"Vivaldi\Application\vivaldi.exe"),
            os.path.join(program_files, r"Vivaldi\Application\vivaldi.exe"),

            shutil.which("msedge"),
            shutil.which("chrome"),
            shutil.which("brave"),
            shutil.which("vivaldi"),
            shutil.which("chromium")
        ]
        browser = next((b for b in browsers if b and os.path.exists(b)), None)
        if not browser:
            return {'success': False, 'error': 'No chrome or edge installation found to render pdf'}

        temp_html = os.path.join(tempfile.gettempdir(), f"graphein_export_{int(time.time() * 1000)}.html")
        try:
            with open(temp_html, 'w', encoding='utf-8') as f:
                f.write(html_content)

            cmd = [
                browser,
                '--headless=new',
                '--disable-gpu',
                '--no-pdf-header-footer',
                '--run-all-compositor-stages-before-draw',
                '--virtual-time-budget=2000',
                f'--print-to-pdf={target_path}',
                temp_html
            ]
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return {'success': True, 'filepath': target_path}
        except Exception as e:
            logger.error(f"PDF-export failed: {e}")
            return {'success': False, 'error': str(e)}
        finally:
            if os.path.exists(temp_html):
                try:
                    os.remove(temp_html)
                except Exception as e:
                    logger.warning(f"Couldn't remove temporary html file: {e}")
                    
    def export_to_html(self, html_content, default_filename="document.html"):
        result = self._window.create_file_dialog(
            webview.FileDialog.SAVE,
            file_types=('HTML Files (*.html;*.htm)',),
            save_filename=default_filename
        )
        if not result:
            return {'success': False, 'error': 'Cancelled'}

        target_path = result[0]
        if not target_path.lower().endswith(('.html', '.htm')):
            target_path += '.html'

        try:
            with open(target_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return {'success': True, 'filepath': target_path}
        except Exception as e:
            logger.error(f"HTML-export failed: {e}")
            return {'success': False, 'error': str(e)}


    def read_local_file(self, filepath):
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    return f.read()
        except Exception as e:
            logger.warning(f"Could not read file '{filepath}': {e}")
        return None
        
        
    def get_remote_image(self, url):
        try:
                                                                                                        
            safe_url = urllib.parse.quote(url.strip(), safe=':/?#[]@!$&\'()*+,;=%')

            is_safe, err = SafeImageFetcher.validate_url(safe_url)
            if not is_safe:
                logger.warning(f"Blocked remote image URL '{safe_url}': {err}")
                return {'success': False, 'error': err}

            redirect_handler = SafeRedirectHandler(validator_fn=SafeImageFetcher.validate_url)
            opener = urllib.request.build_opener(redirect_handler)

            req = urllib.request.Request(
                safe_url,
                headers=SafeImageFetcher.get_image_headers()
            )

            with opener.open(req, timeout=10) as response:
                content_type = response.headers.get_content_type().lower()

                allowed_generic = {
                    'application/octet-stream',
                    'binary/octet-stream',
                    'application/xml',
                    'text/xml',
                    'text/plain'
                }
                if not (content_type.startswith('image/') or content_type in allowed_generic):
                    return {'success': False, 'error': f'Invalid content type: {content_type}'}

                chunks = []
                total_bytes = 0

                while True:
                    chunk = response.read(SafeImageFetcher.CHUNK_SIZE)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > SafeImageFetcher.MAX_IMAGE_SIZE:
                        return {'success': False, 'error': 'Image exceeds maximum allowed size (15 MB).'}
                    chunks.append(chunk)

                raw_data = b"".join(chunks)
                content_encoding = response.headers.get('Content-Encoding', '')

            decompressed_data = SafeImageFetcher.decompress(raw_data, content_encoding)

            detected_mime = SafeImageFetcher.detect_real_mime(decompressed_data)
            
                                                                                            
            if not detected_mime and content_type.startswith('image/'):
                detected_mime = content_type

            if not detected_mime:
                return {'success': False, 'error': 'File content does not match a verified image format.'}

            encoded = base64.b64encode(decompressed_data).decode('utf-8')
            return {'success': True, 'base64': f'data:{detected_mime};base64,{encoded}'}

        except SecurityException as se:
            logger.warning(f"Security exception while retrieving image: {se}")
            return {'success': False, 'error': str(se)}
        except urllib.error.HTTPError as he:
            return {'success': False, 'error': f'HTTP Error {he.code}'}
        except Exception as e:
            logger.warning(f"Error fetching remote image '{url}': {e}")
            return {'success': False, 'error': 'Failed to load remote image.'}

    def queue_open_files(self, paths):
        valid_paths = [os.path.abspath(p) for p in paths if p and os.path.isfile(p)]
        if not valid_paths:
            return

        def run():
            for _ in range(100):
                try:
                    if self._window and self._window.evaluate_js("typeof app !== 'undefined' && app.editorInstance !== null"):
                        break
                except Exception:
                    pass
                time.sleep(0.1)

            time.sleep(0.3)
            for p in valid_paths:
                try:
                    with open(p, 'r', encoding='utf-8') as f:
                        content = f.read()
                    filename = os.path.basename(p)
                    p_json = json.dumps(p)
                    fn_json = json.dumps(filename)
                    c_json = json.dumps(content)
                    self._window.evaluate_js(f"app.openDirectFile({p_json}, {fn_json}, {c_json});")
                except Exception as e:
                    logger.error(f"Fout bij openen van '{p}': {e}")
                time.sleep(0.2)

        threading.Thread(target=run, daemon=True).start()

    def open_file_dialog(self):
        with self._open_lock:
            pending = self._pending_open.pop(0) if self._pending_open else None
        if pending:
            try:
                with open(pending, 'r', encoding='utf-8') as f:
                    content = f.read()
                return {'success': True, 'filepath': pending,
                        'filename': os.path.basename(pending), 'content': content}
            except Exception as e:
                return {'success': False, 'error': str(e)}
        result = self._window.create_file_dialog(
            webview.FileDialog.OPEN, allow_multiple=False,
            file_types=('Markdown Files (*.md)', 'All Files (*.*)')
        )
        if result:
            filepath = result[0]
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                return {
                    'success': True,
                    'filepath': filepath,
                    'filename': os.path.basename(filepath),
                    'content': content
                }
            except Exception as e:
                return {'success': False, 'error': str(e)}
        return {'success': False, 'error': 'Cancelled'}

    def save_file_dialog(self, content):
        result = self._window.create_file_dialog(
            webview.FileDialog.SAVE,
            file_types=('Markdown Files (*.md)', 'All Files (*.*)'),
            save_filename='untitled.md'
        )
        if result:
            filepath = result[0]
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                return {'success': True, 'filepath': filepath, 'filename': os.path.basename(filepath)}
            except Exception as e:
                return {'success': False, 'error': str(e)}
        return {'success': False, 'error': 'Cancelled'}
        
    def _get_clipboard_text(self):
        if sys.platform != 'win32':
            return None

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        CF_UNICODETEXT = 13

        user32.OpenClipboard.argtypes = [wintypes.HWND]
        user32.OpenClipboard.restype = wintypes.BOOL
        user32.CloseClipboard.argtypes = []
        user32.CloseClipboard.restype = wintypes.BOOL
        user32.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
        user32.IsClipboardFormatAvailable.restype = wintypes.BOOL
        user32.GetClipboardData.argtypes = [wintypes.UINT]
        user32.GetClipboardData.restype = wintypes.HANDLE

        kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalLock.restype = wintypes.LPVOID
        kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalUnlock.restype = wintypes.BOOL

                                                                           
        for _ in range(5):
            if user32.OpenClipboard(None):
                break
            time.sleep(0.01)
        else:
            return None

        try:
            if user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
                h_mem = user32.GetClipboardData(CF_UNICODETEXT)
                if h_mem:
                    p_text = kernel32.GlobalLock(h_mem)
                    if p_text:
                        try:
                            return ctypes.c_wchar_p(p_text).value
                        finally:
                            kernel32.GlobalUnlock(h_mem)
        finally:
            user32.CloseClipboard()
        return None

    @staticmethod
    def _dib_to_png(dib):
        try:
            hdr, w, h, _planes, bpp, comp = struct.unpack_from('<IiiHHI', dib, 0)
            if bpp not in (24, 32) or comp not in (0, 3) or w <= 0 or h == 0:
                return None
            top_down = h < 0
            h = abs(h)
            off = hdr + (12 if (comp == 3 and hdr == 40) else 0)
            bpp_b = bpp // 8
            stride = ((w * bpp + 31) // 32) * 4
            if len(dib) < off + stride * h:
                return None
            raw = bytearray()
            for y in range(h):
                sy = y if top_down else h - 1 - y
                row = dib[off + sy * stride: off + sy * stride + w * bpp_b]
                rgb = bytearray(w * 3)
                rgb[0::3] = row[2::bpp_b]
                rgb[1::3] = row[1::bpp_b]
                rgb[2::3] = row[0::bpp_b]
                raw.append(0)
                raw += rgb

            def chunk(tag, data):
                c = struct.pack('>I', len(data)) + tag + data
                return c + struct.pack('>I', zlib.crc32(tag + data) & 0xFFFFFFFF)

            return (b'\x89PNG\r\n\x1a\n'
                    + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
                    + chunk(b'IDAT', zlib.compress(bytes(raw), 6))
                    + chunk(b'IEND', b''))
        except Exception as e:
            logger.warning(f"DIB conversion failed: {e}")
            return None

    def _read_clipboard_image(self):
        if sys.platform != 'win32':
            return None

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        user32.OpenClipboard.argtypes = [wintypes.HWND]
        user32.OpenClipboard.restype = wintypes.BOOL
        user32.CloseClipboard.argtypes = []
        user32.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
        user32.IsClipboardFormatAvailable.restype = wintypes.BOOL
        user32.GetClipboardData.argtypes = [wintypes.UINT]
        user32.GetClipboardData.restype = wintypes.HANDLE
        user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
        user32.RegisterClipboardFormatW.restype = wintypes.UINT
        kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalLock.restype = wintypes.LPVOID
        kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalSize.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalSize.restype = ctypes.c_size_t

        def grab(fmt):
            h_mem = user32.GetClipboardData(fmt)
            if not h_mem:
                return None
            size = kernel32.GlobalSize(h_mem)
            ptr = kernel32.GlobalLock(h_mem)
            if not ptr:
                return None
            try:
                return ctypes.string_at(ptr, size)
            finally:
                kernel32.GlobalUnlock(h_mem)

        for _ in range(5):
            if user32.OpenClipboard(None):
                break
            time.sleep(0.01)
        else:
            return None

        png = None
        try:
            png_fmt = user32.RegisterClipboardFormatW("PNG")
            if png_fmt and user32.IsClipboardFormatAvailable(png_fmt):
                data = grab(png_fmt)
                if data and data.startswith(b'\x89PNG'):
                    png = data
            if png is None and user32.IsClipboardFormatAvailable(8):          
                data = grab(8)
                if data:
                    png = self._dib_to_png(data)
            if png is None and user32.IsClipboardFormatAvailable(15):            
                data = grab(15)
                if data and len(data) > 20:
                    offset = struct.unpack_from('<I', data, 0)[0]
                    wide = struct.unpack_from('<I', data, 16)[0]
                    if wide:
                        names = data[offset:].decode('utf-16-le', 'ignore').split('\0')
                        for item in names:
                            if not item:
                                break
                            ext = os.path.splitext(item)[1].lower()
                            if ext in ALLOWED_IMG_EXTENSIONS and os.path.isfile(item):
                                with open(item, 'rb') as f:
                                    raw = f.read()
                                mime = SafeImageFetcher.detect_real_mime(raw) or 'image/png'
                                return "data:%s;base64,%s" % (mime, base64.b64encode(raw).decode('utf-8'))
        finally:
            user32.CloseClipboard()

        if png:
            return "data:image/png;base64," + base64.b64encode(png).decode('utf-8')
        return None

    def get_clipboard_data(self):
        try:
            img = self._read_clipboard_image()
            if img:
                return {"type": "image", "data": img}
        except Exception as e:
            logger.warning(f"Kon afbeelding uit klembord niet verwerken: {e}")

        try:
            text = self._get_clipboard_text()
            if text:
                return {"type": "text", "data": text}
        except Exception as e:
            logger.warning(f"Kon tekst uit klembord niet lezen: {e}")

        return None

    def _cleanup_unused_assets(self, md_filepath, content):
        try:
            if not md_filepath:
                return
            md_dir = os.path.dirname(md_filepath)
            md_filename = os.path.splitext(os.path.basename(md_filepath))[0]
            assets_dir_path = os.path.join(md_dir, f"assets_{md_filename}")

            if not os.path.isdir(assets_dir_path):
                return

            decoded_content = urllib.parse.unquote(content)

            IMG_PATTERN = re.compile(r"^img_[0-9a-f]{12}\.png$")

            for filename in os.listdir(assets_dir_path):
                file_path = os.path.join(assets_dir_path, filename)
                if os.path.isfile(file_path) and IMG_PATTERN.match(filename):
                    if filename not in content and filename not in decoded_content:
                        try:
                            os.remove(file_path)
                        except Exception as e:
                            logger.warning(f"Couldn't remove unused asset '{file_path}': {e}")

            if not os.listdir(assets_dir_path):
                os.rmdir(assets_dir_path)
        except Exception as e:
            logger.error(f"Asset-cleanup failed: {e}")


    def _content_hash(self, content: str) -> str:
        return hashlib.md5(content.encode('utf-8')).hexdigest()

    def _file_hash(self, filepath: str) -> str | None:
        try:
            with open(filepath, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return None

    def backup_file(self, original_filepath, filename, content):
        try:
            os.makedirs(BACKUP_DIR, exist_ok=True)
            safe_name = filename if filename else "untitled.md"
            base_name = os.path.splitext(safe_name)[0]

            existing_backups = [
                f for f in os.listdir(BACKUP_DIR)
                if f.startswith(f"{base_name} - ") and f.endswith(".md")
            ]

            if existing_backups:
                existing_backups.sort(
                    key=lambda x: os.path.getmtime(os.path.join(BACKUP_DIR, x)),
                    reverse=True
                )
                latest_backup = os.path.join(BACKUP_DIR, existing_backups[0])
                                                                                               
                if self._file_hash(latest_backup) == self._content_hash(content):
                    return True  

            timestamp = time.strftime("%Y%m%d_%H%M%S")
            backup_name = f"{base_name} - {timestamp}.md"
            backup_path = os.path.join(BACKUP_DIR, backup_name)

                                                                                                      
            counter = 1
            while os.path.exists(backup_path):
                backup_name = f"{base_name} - {timestamp}_{counter}.md"
                backup_path = os.path.join(BACKUP_DIR, backup_name)
                counter += 1

            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return False
            
    def watch_file(self, filepath):
        if not filepath:
            return False
        try:
            real_path = os.path.realpath(filepath)
            stat = os.stat(real_path)
            with self._watcher_lock:
                                                                                           
                self._watched_files[real_path] = (stat.st_mtime_ns, stat.st_size)
            return True
        except (OSError, ValueError) as e:
            logger.debug(f"Bestand kon niet worden gevolgd '{filepath}': {e}")
            return False

    def unwatch_file(self, filepath):
        if not filepath:
            return False
        try:
            real_path = os.path.realpath(filepath)
            with self._watcher_lock:
                self._watched_files.pop(real_path, None)
            return True
        except Exception:
            return False

    def _file_watcher_loop(self):
        while True:
            time.sleep(1.0)
            if self.is_closing or not self._window:
                continue

            with self._watcher_lock:
                                                          
                items = list(self._watched_files.items())

            for real_path, (last_mtime_ns, last_size) in items:
                try:
                                                                           
                    stat = os.stat(real_path)
                    
                    if stat.st_mtime_ns != last_mtime_ns or stat.st_size != last_size:
                                                                                              
                        time.sleep(0.05)
                        fresh_stat = os.stat(real_path)

                        with self._watcher_lock:
                                                                                              
                            if real_path in self._watched_files:
                                self._watched_files[real_path] = (fresh_stat.st_mtime_ns, fresh_stat.st_size)
                            else:
                                continue

                                                                             
                        path_json = json.dumps(real_path)
                        self._window.evaluate_js(f"setTimeout(() => app.onExternalFileChange({path_json}), 0);")

                except FileNotFoundError:
                                                                                              
                    pass
                except PermissionError:
                                                                                                                   
                    pass
                except Exception as e:
                    logger.debug(f"Fout bij monitoren van '{real_path}': {e}")
            
    def reset_to_default(self):
        try:
            if os.path.exists(SETTINGS_FILE):
                os.remove(SETTINGS_FILE)
            if os.path.exists(PERMISSIONS_FILE):
                os.remove(PERMISSIONS_FILE)
                
            return {'success': True}
        except Exception as e:
            logger.error(f"Error resetting to default: {e}")
            return {'success': False, 'error': str(e)}

    def overwrite_file(self, filepath, content):
        if not filepath:
            return False

        had_permission = self.get_image_permission(filepath)

        tmp_path = filepath + '.tmp'
        try:
            with open(tmp_path, 'w', encoding='utf-8') as f:
                f.write(content)
            os.replace(tmp_path, filepath) 
            self._cleanup_unused_assets(filepath, content)

                                                                                                
            real_path = os.path.realpath(filepath)
            with self._watcher_lock:
                if real_path in self._watched_files:
                    st = os.stat(filepath)
                    self._watched_files[real_path] = (st.st_mtime_ns, st.st_size)

                                                                                       
            if had_permission is not None:
                self.save_image_permission(filepath, had_permission, explicit_block=(had_permission is False))

            return True
        except Exception as e:
            logger.error(f"Couldn't save file: '{filepath}': {e}")
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
            return False

    def save_pasted_image(self, base64_data, md_filepath):
        if not md_filepath:
            return {'success': False, 'error': 'File not yet saved, save your .md file first (CTRL+S)'}
        try:
            header, encoded = base64_data.split(",", 1)
            data = base64.b64decode(encoded)
            md_dir = os.path.dirname(md_filepath)
            md_filename = os.path.splitext(os.path.basename(md_filepath))[0]

            assets_dir_name = f"assets_{md_filename}"
            assets_dir_path = os.path.join(md_dir, assets_dir_name)
            os.makedirs(assets_dir_path, exist_ok=True)

            img_hash = hashlib.sha256(data).hexdigest()[:12]
            img_name = f"img_{img_hash}.png"
            img_path = os.path.join(assets_dir_path, img_name)

            if not os.path.exists(img_path):
                with open(img_path, "wb") as f:
                    f.write(data)

            rel_path = f"{assets_dir_name}/{img_name}"
            safe_rel_path = urllib.parse.quote(rel_path)
            return {'success': True, 'image_path': safe_rel_path}
        except Exception as e:
            logger.error(f"Couldn't save pasted image: {e}")
            return {'success': False, 'error': str(e)}

    def confirm_dialog(self, title, message):
        return self._window.create_confirmation_dialog(title, message)


    def alert(self, title, message):
        self._window.create_confirmation_dialog(title, message)
        return True

    def open_external_link(self, url):
        try:
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme in ("http", "https", "mailto"):
                webbrowser.open(url)
                return True
            logger.warning(f"Link blocked: {url}")
            return False
        except Exception as e:
            logger.error(f"Error opening link: {e}")
            return False

    def get_local_image(self, md_filepath, img_rel_path):
        try:
            img_rel_path = urllib.parse.unquote(img_rel_path)

                                                                                 
            if img_rel_path.startswith('\\\\') or img_rel_path.startswith('//'):
                logger.warning(f"UNC path blocked: '{img_rel_path}'")
                return {'success': False, 'error': 'Network paths are not allowed'}

            base_dir = os.path.abspath(os.path.dirname(md_filepath))
            img_path = os.path.normpath(os.path.join(base_dir, img_rel_path))

                                                                                                   
            if img_path.startswith('\\\\') or img_path.startswith('//'):
                return {'success': False, 'error': 'Network paths are not allowed'}

            safe_base = base_dir + os.sep
            if not img_path.startswith(safe_base) and img_path != base_dir:
                logger.warning(
                    f"Path-traversal blocked: '{img_path}' outside '{base_dir}'"
                )
                return {'success': False, 'error': 'Request denied, outside allowed folder'}
            ext = os.path.splitext(img_path)[1].lower()
            if ext not in ALLOWED_IMG_EXTENSIONS:
                return {'success': False, 'error': 'Invalid file extension for image'}

            if os.path.exists(img_path):
                mime_type, _ = mimetypes.guess_type(img_path)
                if not mime_type:
                    mime_type = 'image/png'
                with open(img_path, 'rb') as f:
                    encoded = base64.b64encode(f.read()).decode('utf-8')
                return {'success': True, 'base64': f'data:{mime_type};base64,{encoded}'}
            return {'success': False, 'error': f'File not found: {img_path}'}
        except Exception as e:
            logger.error(f"Couldn't load image: {e}")
            return {'success': False, 'error': str(e)}
            
    def play_alert_sound(self):
        if sys.platform == 'win32':
            try:
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            except Exception:
                pass
        return True

    def force_close(self):
        self.is_closing = True
        if self._window:
            self._window.destroy()
        return True
        
        
    def _get_about_markdown(self) -> str:
        user_home = Path.home()
        
        return f"""# About Graphein.

> **Graphein** is a compact, offline Markdown and $\\LaTeX$ editor featuring a distraction-free, dual-panel live preview.

***

## 1. Key Features

* **Live Markdown, Math & Code Support**: Write standard Markdown with support for KaTeX math formulas, syntax-highlighted code blocks, and custom HTML/CSS.

* **Bi-Directional Double-Click Sync**: Double-click any element in the preview pane to jump to its source line in the editor, or double-click in the editor to scroll to and focus the element in the preview.

* **Adaptive Image Coloring**: Automatically adjusts embedded images and diagrams to match the active light or dark theme without modifying the source files (especially useful for screenshots of text).

* **Notation Reference Sheet**: A built-in side panel offering a quick reference for common Markdown syntax and LaTeX math commands.

* **Multi-Language Spell Check:** Check selected text across up to 3 languages simultaneously via right-click, keeping your document clean and free of distracting red squiggles.

***

## 2. Storage Architecture & File Locations

Everything created and managed by Graphein is transparently structured on your local filesystem:

| Component | Storage Path / Location | Purpose |
| :--- | :--- | :--- |
| **Main app** | `{EXE_DIR}` | Main folder with the app components |
| **Settings** | `{SETTINGS_FILE}` | Stores all the user settings like font sizes, paddings, window pane widths, active theme, A4 mode, and open tabs. |
| **Image Permissions** | `{PERMISSIONS_FILE}` | Stores your trust decisions (allow/block) for allowing external image loading per file. |
| **Automatic Backups** | `{BACKUP_DIR}/<filename> - <timestamp>.md` | Rolling safety copies created automatically every 5 minutes while working. Backups older than 21 days are purged automatically. |
| **Pasted Assets** | `<document_folder>/assets_<docname>/` | Stores local PNG images generated via clipboard paste. Unused images are cleaned up when saving. |
| **PDF Temporary Cache** | Operating System `%TEMP%` | Headless Chrome/Edge rendering intermediate files; purged immediately after export. |



***
## 3. Keyboard Shortcuts

| Shortcut | Action |
| :--- | :--- |
| `Ctrl + N` | Create a new untitled document |
| `Ctrl + O` | Open an existing Markdown document (`.md`) |
| `Ctrl + S` | Save current document (or Save As if untitled) |
| `Ctrl + P` | Toggle A4 Page Preview mode |
| `Ctrl + Shift + N` | Toggle the Markdown & $\\LaTeX$ Notation Sidebar |
| `Ctrl + F` | Open / Close Search & Replace panel |
| `Ctrl + B` | Bold selected text (`**bold**`) |
| `Ctrl + I` | Italicize selected text (`*italic*`) |
| `Ctrl + U` | Underline selected text (`<ins>underlined</ins>`) |
| `Tab` / `Shift + Tab` | Indent / Unindent selected lines by 4 spaces |
| `Double-Click` | Synchronize position between Editor and Preview |

***

## 4. Maintenance & Reset

If you ever need to reset Graphein to its original state:
- Select **File > Reset to Default**.
- Confirm the dialog to remove `settings.json` and `image_permissions.json`.
- Graphein will reload with clean factory defaults without touching your personal `.md` documents.
"""



def load_html() -> str:
    try:
        with open(HTML_FILE, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        logger.critical(f"HTML-file not found: {HTML_FILE}")
        raise SystemExit(
            f"Error: '{HTML_FILE}' not found. "
            "Make sure index.html is next to script"
        )
    except Exception as e:
        logger.critical(f"Couldn't load html file: {e}")
        raise SystemExit(f"Couldn't load html file: {e}")


SINGLE_INSTANCE_PORT = 47615


def _md_args():
    out = []
    for a in sys.argv[1:]:
        a = a.strip().strip('"')
        if a and not a.startswith('-') and os.path.isfile(a):
            out.append(os.path.abspath(a))
    return out


def _start_single_instance(api):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        srv.bind(('127.0.0.1', SINGLE_INSTANCE_PORT))
    except OSError:
        try:
            with socket.create_connection(('127.0.0.1', SINGLE_INSTANCE_PORT), timeout=2) as c:
                c.sendall(json.dumps(_md_args()).encode('utf-8'))
        except Exception:
            pass
        return False
    srv.listen(5)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
                with conn:
                    conn.settimeout(2)
                    buf = b''
                    while True:
                        part = conn.recv(65536)
                        if not part:
                            break
                        buf += part
                paths = json.loads(buf.decode('utf-8') or '[]')
                if isinstance(paths, list):
                    api.queue_open_files([p for p in paths if isinstance(p, str)])
            except Exception as e:
                logger.debug(f"Single-instance listener: {e}")
    threading.Thread(target=serve, daemon=True).start()
    return True


def main():
    if sys.platform == 'win32':
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('graphein.')
        except Exception:
            pass

    html_content = load_html()
    api = Api()
    if not _start_single_instance(api):
        return
    window = webview.create_window(
        'Graphein.',
        url=HTML_FILE,
        js_api=api,
        maximized=True,
        zoomable=True
    )
    api.set_window(window)

    def set_icon():
        if sys.platform == 'win32' and os.path.exists(ICON_FILE):
            try:
                hwnd = ctypes.windll.user32.FindWindowW(None, 'Graphein.')
                if not hwnd:
                    logger.warning("HWND not found for icon")
                    return
                WM_SETICON      = 0x0080
                ICON_SMALL      = 0
                ICON_BIG        = 1
                IMAGE_ICON      = 1
                LR_LOADFROMFILE = 0x00000010
                LR_DEFAULTSIZE  = 0x00000040
                hicon = ctypes.windll.user32.LoadImageW(
                    None, ICON_FILE, IMAGE_ICON, 0, 0,
                    LR_LOADFROMFILE | LR_DEFAULTSIZE
                )
                ctypes.windll.user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG,   hicon)
                ctypes.windll.user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, hicon)
            except Exception as e:
                logger.warning(f"Couldn't set icon: {e}")

    window.events.loaded += set_icon

    startup_files = _md_args()
    started = {'done': False}

    def on_loaded_open():
        if not started['done']:
            started['done'] = True
            api.queue_open_files(startup_files)

    if startup_files:
        window.events.loaded += on_loaded_open

    def on_closing():
        if api.is_closing:
            return True                                                   

                                                                                         
        def trigger_close():
            try:
                                                                                                                
                window.evaluate_js('setTimeout(() => app.requestAppClose(), 0);')
            except Exception as e:
                logger.error(f"Fout bij afsluitcontrole: {e}")
                api.force_close()

        threading.Thread(target=trigger_close, daemon=True).start()
        return False                                                             

    window.events.closing += on_closing
    webview.start(debug=False)


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        logging.getLogger('crash').critical('Fatal error in main', exc_info=True)
        raise



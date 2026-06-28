"""
真・三國無双7 Empires カメラ設定エディタ
Dynasty Warriors 8 Empires Camera Settings Editor

メモリスキャンでカメラ設定アドレスを特定し、
目線・目線の高さ・目線傾き・距離（通常/ガード）を自由に書き換えるツール。

作者: overmase
※ 管理者権限で実行してください。
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
import json
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox

# ============================================================
# Windows API 定数
# ============================================================
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
MAX_PATH = 260
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
READABLE_PROTECTIONS = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}

# ============================================================
# Windows API 構造体
# ============================================================
class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * MAX_PATH),
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * MAX_PATH),
    ]

# ============================================================
# Windows API 関数
# ============================================================
kernel32 = ctypes.windll.kernel32
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wintypes.BOOL
kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32FirstW.restype = wintypes.BOOL
kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = wintypes.BOOL
QueryFullProcessImageNameW = kernel32.QueryFullProcessImageNameW
QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
QueryFullProcessImageNameW.restype = wintypes.BOOL


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


# ============================================================
# メモリ操作クラス
# ============================================================
class MemoryEditor:
    def __init__(self):
        self.handle = None
        self.pid = None
        self.base = None  # メインモジュール(exe本体)のベースアドレス

    @staticmethod
    def get_module_base(pid):
        """対象プロセスのメインモジュール(exe本体)のベースアドレスを取得する。

        ASLR(アドレス空間配置のランダム化)により、PCやゲームを再起動すると
        絶対アドレスはそのたびに変わってしまう。しかし「ベースアドレスからの
        オフセット(相対距離)」はゲーム本体が同じバージョンであれば基本的に
        変化しない。そのためアドレスを直接保存せず、このベースアドレスとの
        差分(オフセット)を保存することで再起動や言語変更後もアドレスを
        使い続けられるようにする。
        """
        snap = kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        if snap == INVALID_HANDLE_VALUE:
            return None
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
        base = None
        if kernel32.Module32FirstW(snap, ctypes.byref(entry)):
            # 最初に列挙されるモジュールが常にプロセス本体(exe)
            base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value
        kernel32.CloseHandle(snap)
        return base

    @staticmethod
    def find_game_process():
        results = []
        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap == INVALID_HANDLE_VALUE:
            return results
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            while True:
                name = entry.szExeFile
                if name.lower() == "launch.exe":
                    pid = entry.th32ProcessID
                    path = MemoryEditor._get_process_path(pid)
                    if path and "dynasty warriors 8" in path.lower():
                        results.append((pid, name, path))
                    elif path is None:
                        results.append((pid, name, "(path unknown)"))
                if not kernel32.Process32NextW(snap, ctypes.byref(entry)):
                    break
        kernel32.CloseHandle(snap)
        return results

    @staticmethod
    def _get_process_path(pid):
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return None
        buf = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(1024)
        ok = QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size))
        kernel32.CloseHandle(h)
        return buf.value if ok else None

    def attach(self, pid):
        access = (PROCESS_VM_READ | PROCESS_VM_WRITE |
                  PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION)
        self.handle = kernel32.OpenProcess(access, False, pid)
        if self.handle:
            self.pid = pid
            self.base = self.get_module_base(pid)
            return True
        return False

    def detach(self):
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None
            self.pid = None
            self.base = None

    def is_attached(self):
        return self.handle is not None and self.handle != 0

    def read_int32(self, addr):
        buf = ctypes.create_string_buffer(4)
        n = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            self.handle, ctypes.c_void_p(addr), buf, 4, ctypes.byref(n))
        return struct.unpack('<i', buf.raw)[0] if ok and n.value == 4 else None

    def write_int32(self, addr, val):
        data = struct.pack('<i', int(val))
        buf = ctypes.create_string_buffer(data)
        n = ctypes.c_size_t(0)
        return bool(kernel32.WriteProcessMemory(
            self.handle, ctypes.c_void_p(addr), buf, 4, ctypes.byref(n)))

    def read_float(self, addr):
        buf = ctypes.create_string_buffer(4)
        n = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            self.handle, ctypes.c_void_p(addr), buf, 4, ctypes.byref(n))
        return struct.unpack('<f', buf.raw)[0] if ok and n.value == 4 else None

    def write_float(self, addr, val):
        data = struct.pack('<f', float(val))
        buf = ctypes.create_string_buffer(data)
        n = ctypes.c_size_t(0)
        return bool(kernel32.WriteProcessMemory(
            self.handle, ctypes.c_void_p(addr), buf, 4, ctypes.byref(n)))

    def scan_initial(self, value, vtype='int32', progress_cb=None):
        search = struct.pack('<i', int(value)) if vtype == 'int32' \
            else struct.pack('<f', float(value))
        results = []
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0
        max_addr = 0x7FFFFFFF
        total_scanned = 0
        while addr < max_addr:
            ret = kernel32.VirtualQueryEx(
                self.handle, ctypes.c_void_p(addr),
                ctypes.byref(mbi), ctypes.sizeof(mbi))
            if ret == 0:
                addr += 0x1000
                continue
            region_size = mbi.RegionSize
            if region_size == 0:
                addr += 0x1000
                continue
            if (mbi.State == MEM_COMMIT and
                    mbi.Protect in READABLE_PROTECTIONS and
                    not (mbi.Protect & PAGE_GUARD)):
                chunk = min(region_size, 64 * 1024 * 1024)
                off = 0
                while off < region_size:
                    rsz = min(chunk, region_size - off)
                    buf = ctypes.create_string_buffer(rsz)
                    n = ctypes.c_size_t(0)
                    ok = kernel32.ReadProcessMemory(
                        self.handle, ctypes.c_void_p(addr + off),
                        buf, rsz, ctypes.byref(n))
                    if ok and n.value > 0:
                        data = buf.raw[:n.value]
                        pos = 0
                        while pos <= len(data) - 4:
                            idx = data.find(search, pos)
                            if idx == -1:
                                break
                            if idx % 4 == 0:
                                results.append(addr + off + idx)
                            pos = idx + 1
                    off += rsz
                    total_scanned += rsz
                    if progress_cb:
                        progress_cb(total_scanned, max_addr)
            addr += region_size
        return results

    def scan_narrow(self, addresses, value, vtype='int32'):
        search = struct.pack('<i', int(value)) if vtype == 'int32' \
            else struct.pack('<f', float(value))
        results = []
        for a in addresses:
            buf = ctypes.create_string_buffer(4)
            n = ctypes.c_size_t(0)
            ok = kernel32.ReadProcessMemory(
                self.handle, ctypes.c_void_p(a), buf, 4, ctypes.byref(n))
            if ok and n.value == 4 and buf.raw == search:
                results.append(a)
        return results


# ============================================================
# 設定定義・デフォルト値
# ============================================================
SETTING_KEYS = [
    "normal_distance", "normal_eye", "normal_eye_height", "normal_eye_tilt",
    "guard_distance", "guard_eye", "guard_eye_height", "guard_eye_tilt",
]

NORMAL_KEYS = SETTING_KEYS[:4]
GUARD_KEYS = SETTING_KEYS[4:]

# カメラ設定とは別枠の項目。基本的に4byte整数を使う(値タイプの切替に関わらず固定)。
BUGFIX_KEYS = ["bugfix1", "bugfix2", "bugfix3"]

DEFAULT_VALUES = {
    "normal_eye":        "650",
    "normal_eye_height": "145",
    "normal_eye_tilt":   "-0.25",
    "normal_distance":   "700",
    "guard_eye":         "650",
    "guard_distance":    "700",
    "guard_eye_height":  "145",
    "guard_eye_tilt":    "-0.25",
    "bugfix1":           "0",
    "bugfix2":           "0",
    "bugfix3":           "0",
}

# FOVプリセット: ボタン一発でカメラ設定のVal欄にまとめて値を入力するための定義。
# キーの順番はSETTING_KEYS(距離→目線→目線の高さ→目線傾き)に対応。
FOV_PRESETS = {
    "FOV65 (Def)": {
        "normal_distance": "450", "normal_eye": "500",
        "normal_eye_height": "130", "normal_eye_tilt": "-0.2443",
        "guard_distance": "450", "guard_eye": "500",
        "guard_eye_height": "130", "guard_eye_tilt": "0",
    },
    "FOV80": {
        "normal_distance": "600", "normal_eye": "650",
        "normal_eye_height": "135", "normal_eye_tilt": "-0.2443",
        "guard_distance": "600", "guard_eye": "650",
        "guard_eye_height": "135", "guard_eye_tilt": "-0.2631",
    },
    "FOV95": {
        "normal_distance": "700", "normal_eye": "750",
        "normal_eye_height": "145", "normal_eye_tilt": "-0.2743",
        "guard_distance": "700", "guard_eye": "750",
        "guard_eye_height": "145", "guard_eye_tilt": "-0.2943",
    },
    "FOV285": {
        "normal_distance": "2000", "normal_eye": "2100",
        "normal_eye_height": "175", "normal_eye_tilt": "-0.3943",
        "guard_distance": "1900", "guard_eye": "2000",
        "guard_eye_height": "175", "guard_eye_tilt": "-0.4143",
    },
}

# ============================================================
# 多言語テキスト
# ============================================================
TEXTS = {
    "ja": {
        "window_title":  "真・三國無双7 Empires カメラ設定エディタ",
        "author":        "作者: overmase",
        "frm_process":   "プロセス接続",
        "status_off":    "状態: 未接続",
        "status_on":     "状態: 接続中 (PID {pid})",
        "btn_attach":    "接続",
        "btn_detach":    "切断",
        "frm_camera":    "カメラ設定",
        "frm_bugfix":    "Bug Fix",
        "vtype_label":   "値タイプ:",
        "vtype_int":     "4byte 整数",
        "vtype_float":   "float 小数",
        "lbl_preset":    "FOVプリセット:",
        "section_normal":"── 通常カメラ ──",
        "section_guard": "── ガードカメラ ──",
        "btn_read_all":  "全て読込",
        "btn_write_all": "全て適用",
        "btn_save":      "プロファイル保存",
        "btn_apply_blue": "全て適応(バトルスタートしたら押す)",
        "frm_scanner":   "メモリスキャナー",
        "lbl_target":    "対象:",
        "lbl_search":    "検索値:",
        "lbl_result":    "結果: ---",
        "result_fmt":    "結果: {n} 件",
        "btn_first":     "初回スキャン",
        "btn_narrow":    "絞込スキャン",
        "btn_confirm":   "アドレス確定",
        "frm_help":      "使い方",
        "help": (
            "1. ゲームを起動し、「接続」ボタンでプロセス接続をする\n"
            "2. プロセス接続の状態が「接続中」になっていたら、Valの値を変えても変えなくてもいい\n"
            "3. 青色の「全て適応(バトルスタートしたら押す)」ボタンを押す。FOVが即座に変わります\n"
            "\n"
            "プロファイル保存 : 現在の設定値を保存します\n"
            "全て読込 : プロファイル保存した設定を反映します\n"
            "Rボタン : その設定の値だけプロファイル保存から読み込みます\n"
            "Wボタン : その設定だけゲーム内に反映します\n"
            "\n"
            "※ Offsetは使い方が特に分からない限り値を変更しないでください\n"
            "\n"
            "メモリスキャナーは開発のために個人で実装した機能で、通常使うことはありません。"
        ),
        "settings": {
            "normal_eye": "目線", "normal_eye_height": "目線の高さ",
            "normal_eye_tilt": "目線傾き", "normal_distance": "距離",
            "guard_eye": "目線", "guard_distance": "距離",
            "guard_eye_height": "目線の高さ", "guard_eye_tilt": "目線傾き",
            "bugfix1": "Bug Fix address", "bugfix2": "Bug Fix address2",
            "bugfix3": "Bug Fix address3",
        },
        "full_settings": {
            "normal_eye": "通常 目線", "normal_eye_height": "通常 目線の高さ",
            "normal_eye_tilt": "通常 目線傾き", "normal_distance": "通常 距離",
            "guard_eye": "ガード 目線", "guard_distance": "ガード 距離",
            "guard_eye_height": "ガード 目線の高さ",
            "guard_eye_tilt": "ガード 目線傾き",
            "bugfix1": "Bug Fix address", "bugfix2": "Bug Fix address2",
            "bugfix3": "Bug Fix address3",
        },
        "msg_ready":       "準備完了。ゲームを起動してから「接続」を押してください。",
        "msg_preset_applied": "プリセット「{n}」をVal欄に入力しました。青色ボタンで反映してください。",
        "msg_attached":    "既に接続されています。",
        "msg_no_proc_t":   "未検出",
        "msg_no_proc":     "ゲームプロセス (Launch.exe) が見つかりません。\nゲームを起動してから再度「接続」を押してください。",
        "msg_ok":          "接続成功: {p}",
        "msg_fail_t":      "接続失敗",
        "msg_fail":        "プロセスへの接続に失敗しました。\n管理者権限で実行してください。",
        "msg_detach":      "切断しました。",
        "msg_need_attach": "先にプロセスに接続してください。",
        "msg_no_addr":     "{s}: アドレス未設定",
        "msg_read":        "{s} 読込: {v}",
        "msg_read_fail":   "{s}: 読取失敗",
        "msg_bad_val":     "{s}: 値が不正です",
        "msg_write":       "{s} 書込成功: {v}",
        "msg_write_fail":  "{s}: 書込失敗",
        "msg_all_done":    "全設定適用: 成功 {ok} / 失敗 {fail}",
        "msg_saved":       "プロファイル保存完了",
        "msg_scanning":    "スキャン中です...",
        "msg_enter_val":   "検索値を入力してください。",
        "msg_bad_search":  "検索値が不正です。",
        "msg_scan_start":  "初回スキャン中... ({s}, 値={v})",
        "msg_need_first":  "先に初回スキャンを実行してください。",
        "msg_enter_new":   "新しい検索値を入力してください。",
        "msg_narrow_run":  "絞込スキャン中... ({s}, 値={v})",
        "msg_found":       "アドレス特定! {s} = {a}",
        "msg_zero":        "結果が0件です。値を確認して初回スキャンからやり直してください。",
        "msg_narrowed":    "絞込完了: {n} 件。ゲーム内で値を変更して再度絞り込んでください。",
        "msg_first_done":  "初回スキャン完了: {n} 件。ゲーム内で値を変更して「絞込スキャン」してください。",
        "msg_no_result":   "スキャン結果がありません。",
        "msg_still_many":  "まだ {n} 件あります。もう少し絞り込んでください。",
        "msg_addr_set":    "{s} のアドレスを {a} に設定しました。",
        "msg_admin_t":     "管理者権限",
        "msg_admin":       "このツールはメモリ編集のため管理者権限が必要です。\n管理者として再起動しますか？\n\n「いいえ」を選ぶとそのまま起動します。",
    },
    "en": {
        "window_title":  "DW8 Empires Camera Settings Editor",
        "author":        "Author: overmase",
        "frm_process":   "Process",
        "status_off":    "Status: Disconnected",
        "status_on":     "Status: Connected (PID {pid})",
        "btn_attach":    "Attach",
        "btn_detach":    "Detach",
        "frm_camera":    "Camera Settings",
        "frm_bugfix":    "Bug Fix",
        "vtype_label":   "Value Type:",
        "vtype_int":     "4byte Int",
        "vtype_float":   "Float",
        "lbl_preset":    "FOV Preset:",
        "section_normal":"-- Normal Camera --",
        "section_guard": "-- Guard Camera --",
        "btn_read_all":  "Read All",
        "btn_write_all": "Apply All",
        "btn_save":      "Save Profile",
        "btn_apply_blue": "Apply All (press after Battle Start)",
        "frm_scanner":   "Memory Scanner",
        "lbl_target":    "Target:",
        "lbl_search":    "Value:",
        "lbl_result":    "Results: ---",
        "result_fmt":    "Results: {n}",
        "btn_first":     "First Scan",
        "btn_narrow":    "Next Scan",
        "btn_confirm":   "Set Address",
        "frm_help":      "How to Use",
        "help": (
            "1. Launch the game, then click 'Attach' to connect to the process\n"
            "2. Once status shows 'Connected', you can leave Val as is or change it\n"
            "3. Click the blue 'Apply All (press after Battle Start)' button. FOV changes instantly\n"
            "\n"
            "Save Profile : Saves the current values\n"
            "Read All : Loads the saved profile values\n"
            "R button : Loads only that setting from the saved profile\n"
            "W button : Applies only that setting to the game\n"
            "\n"
            "* Do not change the Offset value unless you know exactly what you're doing\n"
            "\n"
            "The Memory Scanner is a personal dev tool and is not normally needed."
        ),
        "settings": {
            "normal_eye": "Eye", "normal_eye_height": "Eye Height",
            "normal_eye_tilt": "Eye Tilt", "normal_distance": "Distance",
            "guard_eye": "Eye", "guard_distance": "Distance",
            "guard_eye_height": "Eye Height", "guard_eye_tilt": "Eye Tilt",
            "bugfix1": "Bug Fix address", "bugfix2": "Bug Fix address2",
            "bugfix3": "Bug Fix address3",
        },
        "full_settings": {
            "normal_eye": "Normal Eye", "normal_eye_height": "Normal Eye Height",
            "normal_eye_tilt": "Normal Eye Tilt",
            "normal_distance": "Normal Distance",
            "guard_eye": "Guard Eye", "guard_distance": "Guard Distance",
            "guard_eye_height": "Guard Eye Height",
            "guard_eye_tilt": "Guard Eye Tilt",
            "bugfix1": "Bug Fix address", "bugfix2": "Bug Fix address2",
            "bugfix3": "Bug Fix address3",
        },
        "msg_ready":       "Ready. Launch the game, then click 'Attach'.",
        "msg_preset_applied": "Preset '{n}' filled into the Val fields. Press the blue button to apply.",
        "msg_attached":    "Already connected.",
        "msg_no_proc_t":   "Not Found",
        "msg_no_proc":     "Game process (Launch.exe) not found.\nPlease launch the game first.",
        "msg_ok":          "Connected: {p}",
        "msg_fail_t":      "Connection Failed",
        "msg_fail":        "Failed to connect to the process.\nPlease run as Administrator.",
        "msg_detach":      "Disconnected.",
        "msg_need_attach": "Please connect to the process first.",
        "msg_no_addr":     "{s}: Address not set",
        "msg_read":        "{s} read: {v}",
        "msg_read_fail":   "{s}: Read failed",
        "msg_bad_val":     "{s}: Invalid value",
        "msg_write":       "{s} written: {v}",
        "msg_write_fail":  "{s}: Write failed",
        "msg_all_done":    "Apply all: OK {ok} / Failed {fail}",
        "msg_saved":       "Profile saved.",
        "msg_scanning":    "Scanning...",
        "msg_enter_val":   "Please enter a search value.",
        "msg_bad_search":  "Invalid search value.",
        "msg_scan_start":  "Scanning... ({s}, value={v})",
        "msg_need_first":  "Please run First Scan first.",
        "msg_enter_new":   "Enter new search value.",
        "msg_narrow_run":  "Narrowing... ({s}, value={v})",
        "msg_found":       "Address found! {s} = {a}",
        "msg_zero":        "0 results. Check the value and try First Scan again.",
        "msg_narrowed":    "Narrowed to {n}. Change value in-game and scan again.",
        "msg_first_done":  "First scan done: {n} results. Change value in-game, then 'Next Scan'.",
        "msg_no_result":   "No scan results.",
        "msg_still_many":  "Still {n} results. Please narrow down further.",
        "msg_addr_set":    "{s} address set to {a}.",
        "msg_admin_t":     "Administrator",
        "msg_admin":       "This tool requires Administrator privileges.\nRestart as Administrator?\n\nSelect 'No' to continue without elevation.",
    },
    "zh_tw": {
        "window_title":  "真・三國無雙7 Empires 攝影機設定編輯器",
        "author":        "作者: overmase",
        "frm_process":   "程序連接",
        "status_off":    "狀態: 未連接",
        "status_on":     "狀態: 已連接 (PID {pid})",
        "btn_attach":    "連接",
        "btn_detach":    "斷開",
        "frm_camera":    "攝影機設定",
        "frm_bugfix":    "Bug Fix",
        "vtype_label":   "值類型:",
        "vtype_int":     "4byte 整數",
        "vtype_float":   "float 浮點數",
        "lbl_preset":    "FOV預設:",
        "section_normal":"── 一般攝影機 ──",
        "section_guard": "── 防禦攝影機 ──",
        "btn_read_all":  "全部讀取",
        "btn_write_all": "全部套用",
        "btn_save":      "儲存設定檔",
        "btn_apply_blue": "全部套用 (戰鬥開始後按下)",
        "frm_scanner":   "記憶體掃描器",
        "lbl_target":    "目標:",
        "lbl_search":    "搜尋值:",
        "lbl_result":    "結果: ---",
        "result_fmt":    "結果: {n} 筆",
        "btn_first":     "初次掃描",
        "btn_narrow":    "篩選掃描",
        "btn_confirm":   "確定位址",
        "frm_help":      "使用方法",
        "help": (
            "1. 啟動遊戲，點擊「連接」按鈕連接到程序\n"
            "2. 當連接狀態顯示「已連接」後，Val的值可以改也可以不改\n"
            "3. 點擊藍色的「全部套用 (戰鬥開始後按下)」按鈕，FOV會立即改變\n"
            "\n"
            "儲存設定檔 : 儲存目前的設定值\n"
            "全部讀取 : 載入已儲存的設定檔\n"
            "R按鈕 : 僅從設定檔載入該項設定的值\n"
            "W按鈕 : 僅將該項設定套用到遊戲中\n"
            "\n"
            "※ 除非你清楚知道用途，否則請不要更改Offset的值\n"
            "\n"
            "記憶體掃描器是為開發用途而個人實作的功能，通常不需要使用。"
        ),
        "settings": {
            "normal_eye": "視線", "normal_eye_height": "視線高度",
            "normal_eye_tilt": "視線傾斜", "normal_distance": "距離",
            "guard_eye": "視線", "guard_distance": "距離",
            "guard_eye_height": "視線高度", "guard_eye_tilt": "視線傾斜",
            "bugfix1": "Bug Fix address", "bugfix2": "Bug Fix address2",
            "bugfix3": "Bug Fix address3",
        },
        "full_settings": {
            "normal_eye": "一般 視線", "normal_eye_height": "一般 視線高度",
            "normal_eye_tilt": "一般 視線傾斜", "normal_distance": "一般 距離",
            "guard_eye": "防禦 視線", "guard_distance": "防禦 距離",
            "guard_eye_height": "防禦 視線高度",
            "guard_eye_tilt": "防禦 視線傾斜",
            "bugfix1": "Bug Fix address", "bugfix2": "Bug Fix address2",
            "bugfix3": "Bug Fix address3",
        },
        "msg_ready":       "準備就緒。啟動遊戲後點擊「連接」。",
        "msg_preset_applied": "已將預設「{n}」填入Val欄位。請按藍色按鈕套用。",
        "msg_attached":    "已經連接。",
        "msg_no_proc_t":   "未找到",
        "msg_no_proc":     "未找到遊戲程序 (Launch.exe)。\n請先啟動遊戲。",
        "msg_ok":          "連接成功: {p}",
        "msg_fail_t":      "連接失敗",
        "msg_fail":        "無法連接到程序。\n請以管理員身份執行。",
        "msg_detach":      "已斷開連接。",
        "msg_need_attach": "請先連接到程序。",
        "msg_no_addr":     "{s}: 位址未設定",
        "msg_read":        "{s} 讀取: {v}",
        "msg_read_fail":   "{s}: 讀取失敗",
        "msg_bad_val":     "{s}: 值無效",
        "msg_write":       "{s} 寫入成功: {v}",
        "msg_write_fail":  "{s}: 寫入失敗",
        "msg_all_done":    "全部套用: 成功 {ok} / 失敗 {fail}",
        "msg_saved":       "設定檔已儲存。",
        "msg_scanning":    "掃描中...",
        "msg_enter_val":   "請輸入搜尋值。",
        "msg_bad_search":  "搜尋值無效。",
        "msg_scan_start":  "初次掃描中... ({s}, 值={v})",
        "msg_need_first":  "請先執行初次掃描。",
        "msg_enter_new":   "請輸入新的搜尋值。",
        "msg_narrow_run":  "篩選掃描中... ({s}, 值={v})",
        "msg_found":       "位址確定! {s} = {a}",
        "msg_zero":        "結果為0筆。請確認值後重新初次掃描。",
        "msg_narrowed":    "篩選完成: {n} 筆。在遊戲中更改值後再次篩選。",
        "msg_first_done":  "初次掃描完成: {n} 筆。在遊戲中更改值後點擊「篩選掃描」。",
        "msg_no_result":   "沒有掃描結果。",
        "msg_still_many":  "還有 {n} 筆。請繼續篩選。",
        "msg_addr_set":    "{s} 的位址已設定為 {a}。",
        "msg_admin_t":     "管理員權限",
        "msg_admin":       "此工具需要管理員權限。\n是否以管理員身份重新啟動？\n\n選擇「否」將直接啟動。",
    },
}

# ============================================================
# プロファイル管理
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def profile_path(lang):
    return os.path.join(BASE_DIR, f"dw8e_camera_profile_{lang}.json")


def load_profile(lang):
    p = profile_path(lang)
    if os.path.exists(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_profile_data(lang, data):
    with open(profile_path(lang), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ============================================================
# GUI アプリケーション
# ============================================================
class CameraEditorApp:
    def __init__(self, root, lang):
        self.root = root
        self.lang = lang
        self.T = TEXTS[lang]
        self.mem = MemoryEditor()
        self.scan_data = {}
        self.addr_vars = {}
        self.val_vars = {}
        self.scanning = False

        prof = load_profile(lang)

        self.root.title(self.T["window_title"])
        self.root.geometry("700x760")
        self.root.minsize(500, 400)
        self.root.resizable(True, True)
        self._build_ui(prof)
        self._log(self.T["msg_ready"])

    def _t(self, key, **kw):
        return self.T[key].format(**kw) if kw else self.T[key]

    # ── UI 構築 ──────────────────────────────────────────
    def _build_ui(self, prof):
        style = ttk.Style()
        style.configure("Header.TLabel", font=("Meiryo UI", 11, "bold"))
        style.configure("Sub.TLabel", font=("Meiryo UI", 9))
        style.configure("Author.TLabel", font=("Meiryo UI", 9, "italic"))
        style.configure("Log.TLabel", font=("Consolas", 9))
        pad = dict(padx=6, pady=3)

        # ── スクロール可能なコンテナ ──────────────────
        # ウィンドウの高さより内容が長くなっても、マウスホイールや
        # スクロールバーで下の項目(使い方やログなど)を確認できるようにする。
        outer = ttk.Frame(self.root)
        outer.pack(fill="both", expand=True)

        canvas = tk.Canvas(outer, highlightthickness=0)
        vsb = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        body = ttk.Frame(canvas)
        body_id = canvas.create_window((0, 0), window=body, anchor="nw")

        def _on_body_configure(_e=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
        body.bind("<Configure>", _on_body_configure)

        def _on_canvas_configure(e):
            canvas.itemconfig(body_id, width=e.width)
        canvas.bind("<Configure>", _on_canvas_configure)

        def _on_mousewheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        root = body  # 以降のウィジェットはすべてこのスクロール領域内に配置する

        # 作者名
        ttk.Label(root, text=self.T["author"],
                  style="Author.TLabel").pack(anchor="e", padx=10, pady=(4, 0))

        # ── プロセス接続 ────────────────────────────
        fp = ttk.LabelFrame(root, text=self.T["frm_process"], padding=8)
        fp.pack(fill="x", **pad)
        self.lbl_status = ttk.Label(fp, text=self.T["status_off"], foreground="red")
        self.lbl_status.pack(side="left", padx=(0, 12))
        ttk.Button(fp, text=self.T["btn_attach"],
                   command=self._on_attach).pack(side="left", padx=2)
        ttk.Button(fp, text=self.T["btn_detach"],
                   command=self._on_detach).pack(side="left", padx=2)

        # ── カメラ設定 ──────────────────────────────
        fc = ttk.LabelFrame(root, text=self.T["frm_camera"], padding=8)
        fc.pack(fill="x", **pad)

        tf = ttk.Frame(fc)
        tf.pack(fill="x", pady=(0, 6))
        ttk.Label(tf, text=self.T["vtype_label"]).pack(side="left")
        self.vtype_var = tk.StringVar(value=prof.get("vtype", "float"))
        ttk.Radiobutton(tf, text=self.T["vtype_float"],
                        variable=self.vtype_var, value="float").pack(side="left", padx=4)
        ttk.Radiobutton(tf, text=self.T["vtype_int"],
                        variable=self.vtype_var, value="int32").pack(side="left", padx=4)

        ttk.Label(fc, text=self.T["section_normal"],
                  style="Header.TLabel").pack(anchor="w", pady=(4, 2))
        for k in NORMAL_KEYS:
            self._add_row(fc, k, prof)

        ttk.Label(fc, text=self.T["section_guard"],
                  style="Header.TLabel").pack(anchor="w", pady=(8, 2))
        for k in GUARD_KEYS:
            self._add_row(fc, k, prof)

        # ── FOVプリセット (保存ボタンの上に配置) ──────
        fpreset = ttk.Frame(fc)
        fpreset.pack(fill="x", pady=(8, 0))
        ttk.Label(fpreset, text=self.T["lbl_preset"]).pack(side="left", padx=(0, 4))
        for name in FOV_PRESETS:
            ttk.Button(fpreset, text=name,
                       command=lambda n=name: self._apply_preset(n)
                       ).pack(side="left", padx=2)

        bf = ttk.Frame(fc)
        bf.pack(fill="x", pady=(8, 0))
        ttk.Button(bf, text=self.T["btn_read_all"],
                   command=self._read_all).pack(side="left", padx=2)
        ttk.Button(bf, text=self.T["btn_write_all"],
                   command=self._write_all).pack(side="left", padx=2)
        ttk.Button(bf, text=self.T["btn_save"],
                   command=self._save_profile).pack(side="right", padx=2)

        # ── Bug Fix (カメラ設定とは別枠。基本は4byte整数を使用) ──
        fb = ttk.LabelFrame(root, text=self.T["frm_bugfix"], padding=8)
        fb.pack(fill="x", **pad)
        for k in BUGFIX_KEYS:
            self._add_row(fb, k, prof)

        # ── 全項目(カメラ設定 + Bug Fix)を一括適用する青色ボタン ──
        style.configure("Blue.TButton", foreground="white", background="#1565C0")
        fapply = ttk.Frame(root)
        fapply.pack(fill="x", padx=6, pady=(0, 4))
        self.btn_apply_blue = tk.Button(
            fapply, text=self.T["btn_apply_blue"],
            bg="#1565C0", fg="white", activebackground="#0D47A1",
            activeforeground="white", relief="raised",
            font=("Meiryo UI", 10, "bold"),
            command=self._write_all_with_bugfix)
        self.btn_apply_blue.pack(fill="x", pady=2)

        # ── メモリスキャナー ────────────────────────
        fs = ttk.LabelFrame(root, text=self.T["frm_scanner"], padding=8)
        fs.pack(fill="x", **pad)

        r1 = ttk.Frame(fs); r1.pack(fill="x", pady=2)
        ttk.Label(r1, text=self.T["lbl_target"]).pack(side="left")
        self.scan_target_var = tk.StringVar()
        full = self.T["full_settings"]
        combo_vals = [full[k] for k in SETTING_KEYS + BUGFIX_KEYS]
        cbo = ttk.Combobox(r1, textvariable=self.scan_target_var, width=20,
                           state="readonly", values=combo_vals)
        cbo.current(0)
        cbo.pack(side="left", padx=4)
        cbo.bind("<<ComboboxSelected>>", self._on_target_changed)

        r2 = ttk.Frame(fs); r2.pack(fill="x", pady=2)
        ttk.Label(r2, text=self.T["lbl_search"]).pack(side="left")
        self.scan_val_var = tk.StringVar()
        ttk.Entry(r2, textvariable=self.scan_val_var, width=12).pack(side="left", padx=4)
        self.lbl_scan_result = ttk.Label(r2, text=self.T["lbl_result"])
        self.lbl_scan_result.pack(side="right")

        r3 = ttk.Frame(fs); r3.pack(fill="x", pady=4)
        self.btn_first = ttk.Button(r3, text=self.T["btn_first"],
                                    command=self._on_scan_first)
        self.btn_first.pack(side="left", padx=2)
        self.btn_narrow = ttk.Button(r3, text=self.T["btn_narrow"],
                                     command=self._on_scan_narrow)
        self.btn_narrow.pack(side="left", padx=2)
        ttk.Button(r3, text=self.T["btn_confirm"],
                   command=self._on_scan_confirm).pack(side="left", padx=2)
        self.progress = ttk.Progressbar(fs, mode="determinate", length=300)
        self.progress.pack(fill="x", pady=(4, 0))

        # ── 使い方 ──────────────────────────────────
        fh = ttk.LabelFrame(root, text=self.T["frm_help"], padding=6)
        fh.pack(fill="x", **pad)
        ttk.Label(fh, text=self.T["help"], style="Sub.TLabel",
                  justify="left").pack(anchor="w")

        # ── ログ ────────────────────────────────────
        self.lbl_log = ttk.Label(root, text="", style="Log.TLabel",
                                 foreground="gray")
        self.lbl_log.pack(fill="x", padx=8, pady=(0, 4), side="bottom")

    def _add_row(self, parent, key, prof):
        frm = ttk.Frame(parent)
        frm.pack(fill="x", pady=1)

        label = self.T["settings"][key]
        ttk.Label(frm, text=f"  {label}", width=12).pack(side="left")

        ttk.Label(frm, text="Offset:").pack(side="left", padx=(4, 0))
        av = tk.StringVar(value=prof.get(f"addr_{key}", ""))
        self.addr_vars[key] = av
        ttk.Entry(frm, textvariable=av, width=14,
                  font=("Consolas", 9)).pack(side="left", padx=2)

        ttk.Label(frm, text="Val:").pack(side="left", padx=(4, 0))
        default = prof.get(f"val_{key}", DEFAULT_VALUES.get(key, ""))
        vv = tk.StringVar(value=default)
        self.val_vars[key] = vv
        ttk.Entry(frm, textvariable=vv, width=10,
                  font=("Consolas", 9)).pack(side="left", padx=2)

        ttk.Button(frm, text="R", width=3,
                   command=lambda k=key: self._read_one(k)).pack(side="left", padx=1)
        ttk.Button(frm, text="W", width=3,
                   command=lambda k=key: self._write_one(k)).pack(side="left", padx=1)

    # ── 補助 ────────────────────────────────────────
    def _log(self, msg):
        self.lbl_log.config(text=msg)

    def _scan_key(self):
        label = self.scan_target_var.get()
        full = self.T["full_settings"]
        for k, v in full.items():
            if v == label:
                return k
        return SETTING_KEYS[0]

    def _on_target_changed(self, _e=None):
        k = self._scan_key()
        n = len(self.scan_data.get(k, []))
        self.lbl_scan_result.config(text=self._t("result_fmt", n=n))

    def _parse_addr(self, key):
        """アドレス欄の文字列を「ベースアドレスからのオフセット」として解釈し、
        現在アタッチ中のプロセスのベースアドレスを加算した実アドレスを返す。
        ベースアドレスが未取得(未接続)の場合はNoneを返す。"""
        if not self.mem.is_attached() or self.mem.base is None:
            return None
        s = self.addr_vars[key].get().strip()
        if not s:
            return None
        s = s[2:] if s.lower().startswith("0x") else s
        s = s[1:] if s.startswith("+") else s
        try:
            offset = int(s, 16)
        except ValueError:
            return None
        return self.mem.base + offset

    def _vtype_for(self, key):
        """この項目の値タイプを返す。Bug Fix項目は常に4byte整数を使う。"""
        if key in BUGFIX_KEYS:
            return "int32"
        return self.vtype_var.get()

    def _rv(self, addr, key=None):
        if self._vtype_for(key) == "float":
            return self.mem.read_float(addr)
        return self.mem.read_int32(addr)

    def _wv(self, addr, val, key=None):
        if self._vtype_for(key) == "float":
            return self.mem.write_float(addr, val)
        return self.mem.write_int32(addr, val)

    def _full_name(self, key):
        return self.T["full_settings"][key]

    # ── プロセス接続 ────────────────────────────────
    def _on_attach(self):
        if self.mem.is_attached():
            self._log(self.T["msg_attached"])
            return
        procs = MemoryEditor.find_game_process()
        if not procs:
            messagebox.showwarning(self.T["msg_no_proc_t"], self.T["msg_no_proc"])
            return
        pid, _name, path = procs[0]
        if self.mem.attach(pid):
            base_s = f"0x{self.mem.base:X}" if self.mem.base else "?"
            self.lbl_status.config(
                text=self._t("status_on", pid=pid) + f"  Base: {base_s}",
                foreground="green")
            self._log(self._t("msg_ok", p=path))
        else:
            messagebox.showerror(self.T["msg_fail_t"], self.T["msg_fail"])

    def _on_detach(self):
        self.mem.detach()
        self.lbl_status.config(text=self.T["status_off"], foreground="red")
        self._log(self.T["msg_detach"])

    # ── 読み書き ────────────────────────────────────
    def _read_one(self, key):
        if not self.mem.is_attached():
            self._log(self.T["msg_need_attach"]); return
        addr = self._parse_addr(key)
        fn = self._full_name(key)
        if addr is None:
            self._log(self._t("msg_no_addr", s=fn)); return
        val = self._rv(addr, key)
        if val is not None:
            s = f"{val:.4f}" if self._vtype_for(key) == "float" else str(val)
            self.val_vars[key].set(s)
            self._log(self._t("msg_read", s=fn, v=s))
        else:
            self._log(self._t("msg_read_fail", s=fn))

    def _write_one(self, key):
        if not self.mem.is_attached():
            self._log(self.T["msg_need_attach"]); return
        addr = self._parse_addr(key)
        fn = self._full_name(key)
        if addr is None:
            self._log(self._t("msg_no_addr", s=fn)); return
        try:
            val = float(self.val_vars[key].get()) if self._vtype_for(key) == "float" \
                else int(self.val_vars[key].get())
        except ValueError:
            self._log(self._t("msg_bad_val", s=fn)); return
        if self._wv(addr, val, key):
            self._log(self._t("msg_write", s=fn, v=val))
        else:
            self._log(self._t("msg_write_fail", s=fn))

    def _read_all(self):
        for k in SETTING_KEYS:
            self._read_one(k)

    def _write_all(self):
        ok, fail = self._write_keys(SETTING_KEYS)
        self._log(self._t("msg_all_done", ok=ok, fail=fail))

    def _write_all_with_bugfix(self):
        """カメラ設定 + Bug Fix の全項目を一括で書き込む(青色ボタン)。"""
        if not self.mem.is_attached():
            self._log(self.T["msg_need_attach"]); return
        ok, fail = self._write_keys(SETTING_KEYS + BUGFIX_KEYS)
        self._log(self._t("msg_all_done", ok=ok, fail=fail))

    def _write_keys(self, keys):
        ok = fail = 0
        for k in keys:
            addr = self._parse_addr(k)
            if addr is None:
                continue
            vs = self.val_vars[k].get().strip()
            if not vs:
                continue
            try:
                val = float(vs) if self._vtype_for(k) == "float" else int(vs)
            except ValueError:
                fail += 1; continue
            if self._wv(addr, val, k):
                ok += 1
            else:
                fail += 1
        return ok, fail

    # ── FOVプリセット ──────────────────────────────
    def _apply_preset(self, name):
        """FOVプリセットの値をカメラ設定のVal欄にまとめて入力する。
        この時点ではメモリへの書き込みは行わない(Val欄を埋めるだけ)。
        実際にゲームへ反映するには青色の全て適応ボタンを押す。"""
        preset = FOV_PRESETS.get(name)
        if not preset:
            return
        for k, v in preset.items():
            if k in self.val_vars:
                self.val_vars[k].set(v)
        self._log(self._t("msg_preset_applied", n=name))

    # ── プロファイル ────────────────────────────────
    def _save_profile(self):
        data = {"vtype": self.vtype_var.get()}
        for k in SETTING_KEYS + BUGFIX_KEYS:
            data[f"addr_{k}"] = self.addr_vars[k].get()
            data[f"val_{k}"] = self.val_vars[k].get()
        save_profile_data(self.lang, data)
        self._log(self.T["msg_saved"])

    # ── スキャナー ──────────────────────────────────
    def _on_scan_first(self):
        if not self.mem.is_attached():
            self._log(self.T["msg_need_attach"]); return
        if self.scanning:
            self._log(self.T["msg_scanning"]); return
        vs = self.scan_val_var.get().strip()
        if not vs:
            self._log(self.T["msg_enter_val"]); return
        key = self._scan_key()
        vt = self._vtype_for(key)
        try:
            val = float(vs) if vt == "float" else int(vs)
        except ValueError:
            self._log(self.T["msg_bad_search"]); return
        fn = self._full_name(key)
        self.scanning = True
        self.btn_first.config(state="disabled")
        self.btn_narrow.config(state="disabled")
        self._log(self._t("msg_scan_start", s=fn, v=val))
        self.progress["value"] = 0

        def run():
            def cb(scanned, total):
                pct = min(100, int(scanned / total * 100))
                self.root.after(0, lambda p=pct: self.progress.configure(value=p))
            res = self.mem.scan_initial(val, vt, cb)
            self.root.after(0, lambda: self._scan_done(key, res))
        threading.Thread(target=run, daemon=True).start()

    def _on_scan_narrow(self):
        if not self.mem.is_attached():
            self._log(self.T["msg_need_attach"]); return
        key = self._scan_key()
        fn = self._full_name(key)
        prev = self.scan_data.get(key)
        if not prev:
            self._log(self.T["msg_need_first"]); return
        vs = self.scan_val_var.get().strip()
        if not vs:
            self._log(self.T["msg_enter_new"]); return
        vt = self._vtype_for(key)
        try:
            val = float(vs) if vt == "float" else int(vs)
        except ValueError:
            self._log(self.T["msg_bad_search"]); return
        self._log(self._t("msg_narrow_run", s=fn, v=val))
        res = self.mem.scan_narrow(prev, val, vt)
        self.scan_data[key] = res
        n = len(res)
        self.lbl_scan_result.config(text=self._t("result_fmt", n=n))
        if n == 1:
            self._log(self._t("msg_found", s=fn, a=f"0x{res[0]:08X}"))
        elif n == 0:
            self._log(self.T["msg_zero"])
        else:
            self._log(self._t("msg_narrowed", n=n))

    def _scan_done(self, key, res):
        self.scanning = False
        self.btn_first.config(state="normal")
        self.btn_narrow.config(state="normal")
        self.progress["value"] = 100
        self.scan_data[key] = res
        fn = self._full_name(key)
        n = len(res)
        self.lbl_scan_result.config(text=self._t("result_fmt", n=n))
        if n == 1:
            self._log(self._t("msg_found", s=fn, a=f"0x{res[0]:08X}"))
        elif n == 0:
            self._log(self.T["msg_zero"])
        else:
            self._log(self._t("msg_first_done", n=n))

    def _on_scan_confirm(self):
        if not self.mem.is_attached() or self.mem.base is None:
            self._log(self.T["msg_need_attach"]); return
        key = self._scan_key()
        fn = self._full_name(key)
        addrs = self.scan_data.get(key, [])
        if not addrs:
            self._log(self.T["msg_no_result"]); return
        if len(addrs) > 1:
            self._log(self._t("msg_still_many", n=len(addrs))); return
        # 絶対アドレスではなく、ベースアドレスからのオフセットとして保存する。
        # これによりPC/ゲームの再起動やASLRでベースアドレスが変わっても
        # オフセットは変化しないため、再スキャン不要で使い続けられる。
        offset = addrs[0] - self.mem.base
        oh = f"0x{offset:X}"
        self.addr_vars[key].set(oh)
        self._log(self._t("msg_addr_set", s=fn, a=oh))

    # ── 終了 ────────────────────────────────────────
    def on_close(self):
        self.mem.detach()
        self.root.destroy()


# ============================================================
# 言語選択ダイアログ
# ============================================================
def select_language():
    """起動時の言語選択。選択した言語コードを返す。"""
    result = {"lang": None}

    dlg = tk.Tk()
    dlg.title("Language / 言語選択 / 語言選擇")
    dlg.geometry("340x200")
    dlg.resizable(False, False)

    ttk.Label(dlg, text="真・三國無双7 Empires\nCamera Settings Editor",
              font=("Meiryo UI", 12, "bold"), justify="center").pack(pady=(16, 4))
    ttk.Label(dlg, text="by overmase", font=("Meiryo UI", 9, "italic")).pack()
    ttk.Label(dlg, text="Select language:", font=("Meiryo UI", 10)).pack(pady=(12, 6))

    bf = ttk.Frame(dlg)
    bf.pack()

    def pick(lang):
        result["lang"] = lang
        dlg.destroy()

    ttk.Button(bf, text="日本語", width=12, command=lambda: pick("ja")).pack(side="left", padx=4)
    ttk.Button(bf, text="English", width=12, command=lambda: pick("en")).pack(side="left", padx=4)
    ttk.Button(bf, text="繁體中文", width=12, command=lambda: pick("zh_tw")).pack(side="left", padx=4)

    dlg.protocol("WM_DELETE_WINDOW", dlg.destroy)
    dlg.mainloop()
    return result["lang"]


# ============================================================
# エントリポイント
# ============================================================
def main():
    if not is_admin():
        # 管理者権限チェック（言語未選択なので日本語でダイアログ）
        resp = messagebox.askyesno(
            "Administrator / 管理者権限",
            "This tool requires Administrator privileges for memory editing.\n"
            "Restart as Administrator?\n\n"
            "このツールはメモリ編集のため管理者権限が必要です。\n"
            "管理者として再起動しますか？")
        if resp:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable,
                f'"{os.path.abspath(__file__)}"', None, 1)
            sys.exit(0)

    lang = select_language()
    if lang is None:
        sys.exit(0)

    root = tk.Tk()
    app = CameraEditorApp(root, lang)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()

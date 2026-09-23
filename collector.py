"""Own, read-only Windows WeCom collector. No third-party collector is executed.

This is intentionally strict: unrecognised database formats fail closed. Keys
remain in process memory and are never written to the index or logs.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


HEADER = b"SQLite format 3\0"
PAGE_SIZE = 4096
DB_NAMES = ("message.db", "session.db", "user.db")
MEDIA_TYPES = {4: "mixed", 14: "image", 15: "file", 20: "file"}
MEDIA_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".heic",
                    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                    ".txt", ".csv", ".zip", ".rar", ".7z", ".mp3", ".wav",
                    ".mp4", ".mov", ".bin", ".eml", ".midimage", ".thumbimage"}
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010


class MemoryInfo(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("PartitionId", wt.WORD),
                ("RegionSize", ctypes.c_size_t), ("State", wt.DWORD),
                ("Protect", wt.DWORD), ("Type", wt.DWORD)]


def kernel_api():
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    api.OpenProcess.restype = wt.HANDLE
    api.CloseHandle.argtypes = [wt.HANDLE]
    api.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MemoryInfo), ctypes.c_size_t]
    api.VirtualQueryEx.restype = ctypes.c_size_t
    api.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    api.ReadProcessMemory.restype = wt.BOOL
    api.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
    api.QueryFullProcessImageNameW.restype = wt.BOOL
    return api


def aes_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def page_iv(number: int) -> bytes:
    seed = number + 1
    words = []
    for _ in range(4):
        quotient = seed // 52774
        seed = 40692 * (seed - quotient * 52774) - quotient * 3791
        if seed < 0:
            seed += 2147483399
        words.append(seed)
    return hashlib.md5(struct.pack("<4I", *words)).digest()


def decrypt_page(key: bytes, page: bytes, number: int) -> bytes:
    if len(page) != PAGE_SIZE or len(key) != 16:
        raise ValueError("unsupported page or key size")
    derived = hashlib.md5(key + struct.pack("<I", number) + b"sAlT").digest()
    if number != 1:
        return aes_cbc(derived, page_iv(number), page)
    expected = page[16:24]
    shifted = page[8:16] + page[24:]
    plaintext = aes_cbc(derived, page_iv(number), shifted)
    if plaintext[:8] != expected:
        raise ValueError("database key did not validate")
    return HEADER + plaintext


def valid_key(key: bytes, encrypted_first_page: bytes) -> bool:
    try:
        plain = decrypt_page(key, encrypted_first_page, 1)
        return plain[:16] == HEADER and plain[100] in (2, 5, 10, 13)
    except (ValueError, IndexError):
        return False


def source_files(source: Path) -> list[Path]:
    paths = []
    for name in DB_NAMES:
        base = source / name
        if not base.is_file():
            raise FileNotFoundError(name)
        paths.append(base)
        for suffix in ("-wal", "-shm"):
            path = source / (name + suffix)
            if path.is_file():
                paths.append(path)
    return paths


def snapshot(source: Path, target: Path) -> None:
    files = source_files(source)
    target.mkdir(parents=True, exist_ok=True)
    for attempt in range(4):
        before = [(p.stat().st_size, p.stat().st_mtime_ns) for p in files]
        for path in files:
            shutil.copyfile(path, target / path.name)
        after = [(p.stat().st_size, p.stat().st_mtime_ns) for p in files]
        if before == after:
            return
        time.sleep(0.1 * (attempt + 1))
    raise RuntimeError("source changed during snapshot; no index update was made")


def wxwork_pids() -> list[int]:
    done = subprocess.run(["tasklist", "/FI", "IMAGENAME eq WXWork.exe", "/FO", "CSV", "/NH"],
                          text=True, capture_output=True, check=True)
    found = []
    for row in csv.reader(done.stdout.splitlines()):
        if len(row) > 1 and row[0].lower() == "wxwork.exe":
            try:
                found.append(int(row[1]))
            except ValueError:
                pass
    return found


def key_from_process(first_page: bytes, scan_limit_mb: int = 1024, diagnostics: dict | None = None) -> bytes:
    api = kernel_api()
    stats = diagnostics if diagnostics is not None else {}
    stats.update({"processes": 0, "readable_bytes": 0, "hex_candidates": 0, "struct_candidates": 0})
    hex_keys = re.compile(rb"[xX]'([0-9a-fA-F]{32,192})'")
    page_size_bytes = [struct.pack("<I", n) for n in (0, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)]
    structures = re.compile(rb"[\x00\x01]\x00\x00\x00(?:" + b"|".join(re.escape(n) for n in page_size_bytes) + rb")\x10\x00\x00\x00")
    cipher_contexts = re.compile(rb"[\x01\x02]\x00\x00\x00(?:[\x01\x02]\x00\x00\x00|\x00\x10\x00\x00|\x00\x20\x00\x00|\x00\x40\x00\x00)")
    for pid in wxwork_pids():
        handle = api.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not handle:
            continue
        try:
            namebuf = ctypes.create_unicode_buffer(32768)
            length = wt.DWORD(len(namebuf))
            if not api.QueryFullProcessImageNameW(handle, 0, namebuf, ctypes.byref(length)):
                continue
            executable = Path(namebuf.value)
            if executable.name.lower() != "wxwork.exe" or "wxwork" not in str(executable.parent).lower():
                continue
            stats["processes"] += 1
            address = 0
            scanned = 0
            previous = b""
            while address < 0x7FFF_FFFF_FFFF and scanned < scan_limit_mb * 1024 * 1024:
                info = MemoryInfo()
                if not api.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info)):
                    break
                base = int(info.BaseAddress or 0)
                size = int(info.RegionSize)
                next_address = base + size
                if next_address <= address:
                    break
                address = next_address
                if info.State != MEM_COMMIT or info.Type != MEM_PRIVATE or info.Protect not in READABLE:
                    continue
                for pos in range(0, min(size, scan_limit_mb * 1024 * 1024 - scanned), 1024 * 1024):
                    count = min(1024 * 1024, size - pos)
                    buffer = ctypes.create_string_buffer(count)
                    got = ctypes.c_size_t()
                    if not api.ReadProcessMemory(handle, ctypes.c_void_p(base + pos), buffer, count, ctypes.byref(got)):
                        previous = b""
                        continue
                    chunk = previous + buffer.raw[:got.value]
                    scanned += got.value
                    stats["readable_bytes"] += got.value
                    for match in hex_keys.finditer(chunk):
                        stats["hex_candidates"] += 1
                        hex_value = match.group(1)
                        for part in (hex_value[:32], hex_value[32:64]):
                            if len(part) == 32:
                                candidate = bytes.fromhex(part.decode("ascii"))
                                if valid_key(candidate, first_page):
                                    return candidate
                    for match in cipher_contexts.finditer(chunk):
                        if match.start() % 4:
                            continue
                        stats["struct_candidates"] += 1
                        candidate = chunk[match.start() + 8:match.start() + 24]
                        if valid_key(candidate, first_page):
                            return candidate
                    for match in structures.finditer(chunk):
                        stats["struct_candidates"] += 1
                        origin = match.start()
                        if origin % 4:
                            continue
                        candidate = chunk[origin + 12:origin + 28]
                        if valid_key(candidate, first_page):
                            return candidate
                        # A wxSQLite3 context can hold its page key next to a
                        # derived cipher key. Only check the small neighborhood.
                        low = max(0, origin - 256)
                        high = min(len(chunk) - 16, origin + 256)
                        for nearby in range(low, high + 1):
                            candidate = chunk[nearby:nearby + 16]
                            if len(set(candidate)) >= 11 and valid_key(candidate, first_page):
                                return candidate
                    previous = chunk[-100:]
        finally:
            api.CloseHandle(handle)
    raise RuntimeError("未在企微进程中找到可验证的数据库密钥；未生成任何明文归档")


def decrypt_database(source: Path, target: Path, key: bytes) -> None:
    with source.open("rb") as fin, target.open("wb") as fout:
        number = 1
        while page := fin.read(PAGE_SIZE):
            if len(page) != PAGE_SIZE:
                raise ValueError("database contains a partial page")
            fout.write(decrypt_page(key, page, number))
            number += 1


def merge_wal(encrypted_wal: Path, decrypted_db: Path, key: bytes) -> int:
    if not encrypted_wal.is_file():
        return 0
    with encrypted_wal.open("rb") as wal:
        header = wal.read(32)
        if len(header) != 32 or header[:4] not in (b"7\x7f\x06\x82", b"7\x7f\x06\x83"):
            raise ValueError("unsupported WAL header")
        size = struct.unpack_from(">I", header, 8)[0]
        if size != PAGE_SIZE:
            raise ValueError("unsupported WAL page size")
        salts = header[16:24]
        pending: dict[int, bytes] = {}
        committed: dict[int, bytes] = {}
        db_pages = 0
        while frame := wal.read(24 + PAGE_SIZE):
            if len(frame) != 24 + PAGE_SIZE:
                break
            page_number, commit_pages = struct.unpack_from(">II", frame)
            if page_number == 0 or frame[8:16] != salts:
                break
            pending[page_number] = frame[24:]
            if commit_pages:
                committed.update(pending)
                pending.clear()
                db_pages = commit_pages
    if not committed:
        return 0
    with decrypted_db.open("r+b") as db:
        for page_number, encrypted_page in committed.items():
            db.seek((page_number - 1) * PAGE_SIZE)
            db.write(decrypt_page(key, encrypted_page, page_number))
        db.truncate(db_pages * PAGE_SIZE)
    return len(committed)


def decode_strings(raw: bytes, depth: int = 0) -> list[str]:
    """Extract UTF-8 leaves of protobuf wire data without replacing bad bytes."""
    if depth > 3 or not raw:
        return []
    found: list[str] = []
    try:
        text = raw.decode("utf-8")
        if text.isprintable() or any(c in text for c in "\n\r\t"):
            if text.strip() and sum(c.isprintable() or c in "\n\r\t" for c in text) / len(text) > 0.95:
                found.append(text)
    except UnicodeDecodeError:
        pass
    pos = 0
    while pos < len(raw):
        shift = 0
        tag = 0
        while pos < len(raw):
            byte = raw[pos]
            pos += 1
            tag |= (byte & 127) << shift
            if byte < 128:
                break
            shift += 7
            if shift > 63:
                return found
        wire = tag & 7
        if tag == 0:
            break
        if wire == 2:
            length = 0
            shift = 0
            while pos < len(raw):
                byte = raw[pos]
                pos += 1
                length |= (byte & 127) << shift
                if byte < 128:
                    break
                shift += 7
                if shift > 63:
                    return found
            if length > len(raw) - pos:
                break
            found.extend(decode_strings(raw[pos:pos + length], depth + 1))
            pos += length
        elif wire == 0:
            while pos < len(raw) and raw[pos] & 128:
                pos += 1
            pos += 1
        elif wire == 1:
            pos += 8
        elif wire == 5:
            pos += 4
        else:
            break
    return found


def body_of(value: object, content_type: int) -> tuple[str | None, str]:
    if value is None:
        return None, "empty"
    if isinstance(value, str):
        return value, "plain"
    raw = bytes(value)
    try:
        decoded = json.loads(raw)
        if isinstance(decoded, dict):
            for key in ("text", "content", "title", "description"):
                if isinstance(decoded.get(key), str):
                    return decoded[key], "json"
    except (ValueError, UnicodeDecodeError):
        pass
    leaves = decode_strings(raw)
    if content_type == 20 and leaves:
        readable = [text for text in leaves
                    if 4 <= len(text) <= 20000
                    and not text.startswith(("http://", "https://", "{", "*1*"))
                    and not text.lower().endswith(".eml")]
        if readable:
            chosen = max(readable, key=lambda text: (sum("\u4e00" <= c <= "\u9fff" for c in text), len(text)))
            return chosen, "shared_email_candidate"
    if content_type in (0, 1, 2) and leaves:
        chosen = max(leaves, key=len)
        if len(chosen) >= 2:
            return chosen, "protobuf_candidate"
    return None, "unparsed"


def media_candidates(value: object, content_type: int) -> list[str]:
    if content_type not in MEDIA_TYPES or value is None:
        return []
    leaves = decode_strings(bytes(value)) if isinstance(value, bytes) else [str(value)]
    names = set()
    for leaf in leaves:
        if not 1 <= len(leaf) <= 512 or any(c in leaf for c in "\r\n\t"):
            continue
        name = leaf.replace("\\", "/").rsplit("/", 1)[-1]
        if Path(name).suffix.lower() in MEDIA_EXTENSIONS and 1 <= len(name) <= 260:
            names.add(name.casefold())
    return sorted(names)[:16]


def catalog_media(target: sqlite3.Connection, account_root: Path) -> int:
    target.execute("DELETE FROM media_files")
    count = 0
    for kind in ("Image", "File"):
        root = account_root / "Cache" / kind
        if not root.is_dir():
            continue
        for base, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if not (Path(base) / d).is_symlink()]
            for name in files:
                path = Path(base) / name
                if path.is_symlink():
                    continue
                try:
                    size = path.stat().st_size
                    target.execute("INSERT INTO media_files(name,kind,path,size) VALUES(?,?,?,?)",
                                   (name.casefold(), kind.lower(), str(path), size))
                    count += 1
                except OSError:
                    continue
    return count


def table_columns(conn: sqlite3.Connection, name: str) -> set[str]:
    return {row[1] for row in conn.execute(f'PRAGMA table_info("{name}")')}


def index_snapshot(clear_dir: Path, index_path: Path, account: str, account_root: Path) -> dict:
    index_path.parent.mkdir(parents=True, exist_ok=True)
    target = sqlite3.connect(index_path)
    target.executescript("""PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS conversations(id TEXT PRIMARY KEY, name TEXT, kind TEXT, last_time INTEGER);
        CREATE TABLE IF NOT EXISTS people(id TEXT PRIMARY KEY, name TEXT, source TEXT);
        CREATE TABLE IF NOT EXISTS group_names(conversation_id TEXT, person_id TEXT, name TEXT,
            PRIMARY KEY(conversation_id,person_id));
        CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY, source_id TEXT, conversation_id TEXT,
            sender_id TEXT, sent_ms INTEGER, type INTEGER, body TEXT, parse_status TEXT);
        CREATE INDEX IF NOT EXISTS idx_conv_time ON messages(conversation_id,sent_ms,id);
        CREATE INDEX IF NOT EXISTS idx_time ON messages(sent_ms,id);
        CREATE VIRTUAL TABLE IF NOT EXISTS message_fts USING fts5(id UNINDEXED, body, tokenize='trigram');
        CREATE TABLE IF NOT EXISTS media_candidates(message_id TEXT, name TEXT, kind TEXT,
            PRIMARY KEY(message_id,name));
        CREATE INDEX IF NOT EXISTS idx_media_candidate ON media_candidates(message_id);
        CREATE TABLE IF NOT EXISTS media_files(name TEXT, kind TEXT, path TEXT PRIMARY KEY, size INTEGER);
        CREATE INDEX IF NOT EXISTS idx_media_name ON media_files(name,kind);
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
    """)
    counts = {"messages": 0, "unparsed": 0, "people": 0, "conversations": 0}
    previous = target.execute("SELECT max(sent_ms) FROM messages").fetchone()[0]
    with closing(sqlite3.connect(f"file:{(clear_dir / 'user.db').as_posix()}?mode=ro", uri=True)) as users:
        if {"id", "name"} <= table_columns(users, "user_table"):
            for row in users.execute("SELECT id, name, real_name, account FROM user_table"):
                person_id = str(row[0])
                name = row[2] or row[1] or row[3]
                if name:
                    target.execute("INSERT OR REPLACE INTO people VALUES(?,?,?)", (person_id, str(name), "user_table"))
                    counts["people"] += 1
    with closing(sqlite3.connect(f"file:{(clear_dir / 'session.db').as_posix()}?mode=ro", uri=True)) as sessions:
        if {"id", "name"} <= table_columns(sessions, "conversation_table"):
            for row in sessions.execute("SELECT id,name,roomname_remark,last_message_time FROM conversation_table"):
                cid = str(row[0])
                name = row[2] or row[1]
                target.execute("INSERT OR REPLACE INTO conversations VALUES(?,?,?,?)", (cid, name, {"R":"group","S":"direct","M":"wechat_contact","O":"app","Y":"system"}.get(cid[:1], "unknown"), row[3]))
                counts["conversations"] += 1
        if {"conversation_id", "user_id", "nick_name"} <= table_columns(sessions, "conversation_user_table"):
            for row in sessions.execute("SELECT conversation_id,user_id,nick_name FROM conversation_user_table WHERE nick_name IS NOT NULL"):
                target.execute("INSERT OR REPLACE INTO group_names VALUES(?,?,?)", tuple(map(str, row)))
    with closing(sqlite3.connect(f"file:{(clear_dir / 'message.db').as_posix()}?mode=ro", uri=True)) as source:
        tables = {r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in ("message_table", "message_small_table", "kf_message_tableV1"):
            if table not in tables:
                continue
            needed = {"message_id", "conversation_id", "sender_id", "send_time", "content_type", "content"}
            if not needed <= table_columns(source, table):
                continue
            columns = 'message_id,conversation_id,sender_id,send_time,content_type,content'
            if previous is None:
                rows = source.execute(f'SELECT {columns} FROM "{table}"')
            else:
                def unseen_rows():
                    for (raw_id,) in source.execute(f'SELECT message_id FROM "{table}"'):
                        known_id = hashlib.sha256((account + "\0" + table + "\0" + str(raw_id)).encode()).hexdigest()
                        known = target.execute("SELECT type,parse_status FROM messages WHERE id=?", (known_id,)).fetchone()
                        if known and not (known[0] == 20 and known[1] == "unparsed"):
                            continue
                        row = source.execute(f'SELECT {columns} FROM "{table}" WHERE message_id=?', (raw_id,)).fetchone()
                        if row:
                            yield row
                rows = unseen_rows()
            for row in rows:
                raw_id, cid, sender, sent, kind, content = row
                if raw_id is None or cid is None:
                    continue
                mid = hashlib.sha256((account + "\0" + table + "\0" + str(raw_id)).encode()).hexdigest()
                body, state = body_of(content, int(kind or 0))
                sent_ms = int(sent or 0)
                if 0 < sent_ms < 10**11:
                    sent_ms *= 1000
                target.execute("INSERT OR IGNORE INTO messages VALUES(?,?,?,?,?,?,?,?)",
                               (mid, str(raw_id), str(cid), str(sender) if sender is not None else None, sent_ms, int(kind or 0), body, state))
                inserted = target.execute("SELECT changes()").fetchone()[0]
                if inserted:
                    counts["messages"] += 1
                    if body:
                        target.execute("INSERT INTO message_fts VALUES(?,?)", (mid, body))
                    else:
                        counts["unparsed"] += 1
                elif body and state != "unparsed":
                    target.execute("UPDATE messages SET body=?,parse_status=? WHERE id=? AND parse_status='unparsed'",
                                   (body, state, mid))
                    if target.execute("SELECT changes()").fetchone()[0]:
                        target.execute("INSERT INTO message_fts VALUES(?,?)", (mid, body))
                for name in media_candidates(content, int(kind or 0)):
                    target.execute("INSERT OR IGNORE INTO media_candidates VALUES(?,?,?)",
                                   (mid, name, MEDIA_TYPES[int(kind or 0)]))
    counts["media_files"] = catalog_media(target, account_root)
    target.execute("INSERT OR REPLACE INTO meta VALUES('last_collection_utc',?)", (datetime.now(timezone.utc).isoformat(),))
    target.execute("INSERT OR REPLACE INTO meta VALUES('account',?)", (account,))
    watermark = target.execute("SELECT max(sent_ms) FROM messages").fetchone()[0] or 0
    target.execute("INSERT OR REPLACE INTO meta VALUES('last_source_watermark_ms',?)", (str(watermark),))
    target.commit()
    target.close()
    return counts


def collect(source: Path, data_dir: Path) -> dict:
    source = source.resolve(strict=True)
    if source.name != "Data" or not source.parent.name.isdecimal():
        raise ValueError("--source-dir 必须指向指定账号的 WXWork/<数字>/Data")
    data_dir = data_dir.resolve()
    if source == data_dir or source in data_dir.parents:
        raise ValueError("归档目录不能位于企微原始目录")
    with tempfile.TemporaryDirectory(prefix="wecom-readonly-") as temporary:
        snap = Path(temporary) / "snapshot"
        clear = Path(temporary) / "clear"
        snapshot(source, snap)
        clear.mkdir()
        with (snap / "message.db").open("rb") as f:
            first = f.read(PAGE_SIZE)
        if first.startswith(HEADER):
            raise ValueError("源数据库未加密；当前版本只支持已验证的企微加密格式")
        if first[16:24] != b"\x10\x00\x02\x02\x00\x40\x20\x20":
            raise ValueError("未知企微数据库格式，停止采集")
        key = key_from_process(first)
        merged = {}
        for name in DB_NAMES:
            with (snap / name).open("rb") as f:
                page1 = f.read(PAGE_SIZE)
            if not valid_key(key, page1):
                raise ValueError(f"{name} 与已验证密钥不匹配")
            decrypt_database(snap / name, clear / name, key)
            merged[name] = merge_wal(snap / (name + "-wal"), clear / name, key)
            check = sqlite3.connect(clear / name)
            try:
                if check.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise ValueError(f"{name} 快照完整性检查失败")
            finally:
                check.close()
        counts = index_snapshot(clear, data_dir / "index.db", source.parent.name, source.parent)
        return {"counts": counts, "wal_pages_applied": merged}


def main() -> None:
    p = argparse.ArgumentParser(description="只读采集本机企业微信可见聊天")
    p.add_argument("--source-dir", type=Path, required=True)
    p.add_argument("--data-dir", type=Path, required=True)
    args = p.parse_args()
    try:
        print(json.dumps(collect(args.source_dir, args.data_dir), ensure_ascii=False))
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()

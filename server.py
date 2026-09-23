"""Own read-only MCP server over collector.py's SQLite index."""
import argparse
import json
import os
import hashlib
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

TZ = timezone(timedelta(hours=8))
FIELDS = {
    "wecom_status": ({}, []),
    "wecom_conversations": ({"query": "string", "kind": "string", "limit": "integer", "offset": "integer"}, []),
    "wecom_messages": ({"conversation_id": "string", "start": "string", "end": "string", "limit": "integer", "offset": "integer"}, ["conversation_id"]),
    "wecom_search": ({"query": "string", "conversation_id": "string", "start": "string", "end": "string", "limit": "integer", "offset": "integer"}, ["query"]),
    "wecom_context": ({"message_id": "string", "before": "integer", "after": "integer"}, ["message_id"]),
    "wecom_attachment": ({"message_id": "string"}, ["message_id"]),
    "wecom_since": ({"since": "string", "limit": "integer", "offset": "integer"}, ["since"]),
}
DESCRIPTIONS = {
    "wecom_status": "查看归档状态、数量及时间范围",
    "wecom_conversations": "列出或筛选会话",
    "wecom_messages": "读取指定会话的消息",
    "wecom_search": "按关键词检索消息",
    "wecom_context": "读取一条消息及前后文",
    "wecom_attachment": "查看图片或文件实体及缺失原因",
    "wecom_since": "按时间获取增量消息",
}


def specs():
    return [{"name": name, "description": DESCRIPTIONS[name], "inputSchema": {
        "type": "object", "properties": {key: {"type": kind} for key, kind in fields.items()},
        "required": required, "additionalProperties": False},
        "annotations": {"readOnlyHint": name != "wecom_attachment", "destructiveHint": False,
                        "openWorldHint": False, "idempotentHint": True}}
        for name, (fields, required) in FIELDS.items()]


def limit(value, default=50, cap=100):
    try:
        return max(1, min(int(value), cap))
    except (ValueError, TypeError):
        return default


def offset(value):
    try:
        return max(0, min(int(value), 10**9))
    except (ValueError, TypeError):
        return 0


def ms(value):
    if value in (None, ""):
        return None
    moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if moment.tzinfo is None:
        raise ValueError("时间需要时区，例如 2026-09-23T09:00:00+08:00")
    return int(moment.timestamp() * 1000)


def human(value):
    return datetime.fromtimestamp(value / 1000, TZ).isoformat(timespec="seconds") if value else None


class Index:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.path = self.directory / "index.db"

    def connect(self):
        if not self.path.is_file():
            raise FileNotFoundError("尚无索引，请先运行 collector.py")
        conn = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        return conn

    def attachment(self, conn, mid):
        item = conn.execute("SELECT type FROM messages WHERE id=?", (mid,)).fetchone()
        if item is None:
            raise ValueError("找不到消息")
        if item[0] not in (4, 14, 15, 20):
            return {"message_id": mid, "attachments": [], "status": "not_media_message"}
        candidates = conn.execute("SELECT name,kind FROM media_candidates WHERE message_id=? LIMIT 16", (mid,)).fetchall()
        if not candidates:
            return {"message_id": mid, "attachments": [], "status": "locator_missing"}
        account_row = conn.execute("SELECT value FROM meta WHERE key='account'").fetchone()
        if not account_row:
            return {"message_id": mid, "attachments": [], "status": "account_missing"}
        account = account_row[0]
        found = []
        failures = []
        for name, kind in candidates:
            allowed = ("image", "file") if kind == "mixed" else (kind,)
            marks = ",".join("?" for _ in allowed)
            matches = conn.execute(f"SELECT path,size FROM media_files WHERE name=? AND kind IN ({marks}) LIMIT 3",
                                   (name, *allowed)).fetchall()
            if len(matches) != 1:
                failures.append({"name": name, "reason": "source_missing" if not matches else "ambiguous_same_name"})
                continue
            original = Path(matches[0][0])
            try:
                real = original.resolve(strict=True)
                root = next((p for p in real.parents if p.name == account and p.parent.name == "WXWork"), None)
                if root is None or real.stat().st_size != matches[0][1]:
                    raise OSError("source_changed")
                if not any(parent == root / "Cache" / k for k in ("Image", "File") for parent in real.parents):
                    raise OSError("outside_media_cache")
                digest = hashlib.sha256()
                with real.open("rb") as src:
                    while chunk := src.read(1024 * 1024):
                        digest.update(chunk)
                suffix = real.suffix.lower() if len(real.suffix) <= 16 else ""
                dst = self.directory / "attachments" / (digest.hexdigest() + suffix)
                dst.parent.mkdir(parents=True, exist_ok=True)
                existing = list(dst.parent.glob(digest.hexdigest() + ".*"))
                if existing:
                    dst = existing[0]
                if not dst.is_file():
                    with tempfile.NamedTemporaryFile(dir=dst.parent, delete=False) as temp:
                        temp_path = Path(temp.name)
                        with real.open("rb") as src:
                            shutil.copyfileobj(src, temp)
                    check = hashlib.sha256()
                    with temp_path.open("rb") as copied:
                        while chunk := copied.read(1024 * 1024):
                            check.update(chunk)
                    if check.hexdigest() != digest.hexdigest():
                        temp_path.unlink(missing_ok=True)
                        raise OSError("source_changed_during_copy")
                    temp_path.replace(dst)
                found.append({"name": name, "path": str(dst), "sha256": digest.hexdigest(),
                              "bytes": dst.stat().st_size})
            except OSError as exc:
                failures.append({"name": name, "reason": str(exc)})
        return {"message_id": mid, "attachments": found[:8], "missing": failures[:16],
                "status": "available" if found else "unavailable"}

    @staticmethod
    def rows(conn, sql, params=()):
        rows = [dict(row) for row in conn.execute(sql, params)]
        for row in rows:
            if "sent_ms" in row:
                row["sent_at"] = human(row.pop("sent_ms"))
            if "last_time" in row:
                # conversations.last_time is seconds, messages.sent_ms is
                # milliseconds; normalise before formatting.
                last = row.pop("last_time")
                row["last_message_at"] = human(last * 1000 if last and last < 10**11 else last)
        return rows

    @staticmethod
    def select(where, order="DESC"):
        return f"""SELECT m.id AS message_id,m.source_id,m.conversation_id,
            COALESCE(NULLIF(c.name,''),'未解析') AS conversation_name,c.kind AS conversation_kind,
            m.sender_id,COALESCE(NULLIF(g.name,''),NULLIF(p.name,''),'未解析') AS sender_name,
            CASE WHEN g.name IS NOT NULL THEN 'group_nickname' WHEN p.name IS NOT NULL THEN p.source ELSE 'unresolved' END AS sender_source,
            m.sent_ms,m.type AS content_type,m.body,m.parse_status
            FROM messages m LEFT JOIN conversations c ON c.id=m.conversation_id
            LEFT JOIN people p ON p.id=m.sender_id
            LEFT JOIN group_names g ON g.conversation_id=m.conversation_id AND g.person_id=m.sender_id
            WHERE {where} ORDER BY m.sent_ms {order},m.id {order} LIMIT ? OFFSET ?"""

    def call(self, name, args):
        if name not in FIELDS:
            raise ValueError("未知工具")
        conn = self.connect()
        try:
            if name == "wecom_status":
                counts = {table: conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                          for table in ("messages", "conversations", "people", "media_files", "media_candidates")}
                bounds = conn.execute("SELECT min(sent_ms),max(sent_ms),sum(parse_status='unparsed') FROM messages").fetchone()
                stamp = conn.execute("SELECT value FROM meta WHERE key='last_collection_utc'").fetchone()
                watermark = conn.execute("SELECT value FROM meta WHERE key='last_source_watermark_ms'").fetchone()
                archive = self.directory / "attachments"
                return {"counts": counts, "earliest_message_at": human(bounds[0]),
                        "latest_message_at": human(bounds[1]), "unparsed_messages": bounds[2] or 0,
                        "last_collection_utc": stamp[0] if stamp else None,
                        "source_watermark_at": human(int(watermark[0])) if watermark else None,
                        "index_bytes": self.path.stat().st_size,
                        "extracted_attachment_bytes": sum(p.stat().st_size for p in archive.iterdir() if p.is_file()) if archive.is_dir() else 0}
            if name == "wecom_conversations":
                q = str(args.get("query") or "").strip()
                kind = str(args.get("kind") or "").strip()
                pattern = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
                return self.rows(conn, """SELECT c.id AS conversation_id,COALESCE(NULLIF(c.name,''),'未解析') AS name,
                    c.kind,c.last_time,(SELECT count(*) FROM messages m WHERE m.conversation_id=c.id) AS message_count
                    FROM conversations c WHERE (?='' OR c.name LIKE ? ESCAPE '\\') AND (?='' OR c.kind=?)
                    ORDER BY c.last_time DESC LIMIT ? OFFSET ?""",
                    (q, pattern, kind, kind, limit(args.get("limit"), 30), offset(args.get("offset"))))
            if name == "wecom_messages":
                cid = str(args["conversation_id"]).strip()
                if not cid:
                    raise ValueError("conversation_id 不能为空")
                start, end = ms(args.get("start")), ms(args.get("end"))
                return self.rows(conn, self.select("m.conversation_id=? AND (? IS NULL OR m.sent_ms>=?) AND (? IS NULL OR m.sent_ms<=?)"),
                                 (cid, start, start, end, end, limit(args.get("limit")), offset(args.get("offset"))))
            if name == "wecom_search":
                q = str(args["query"]).strip()
                if not 1 <= len(q) <= 200:
                    raise ValueError("query 长度须为 1 到 200 字符")
                if len(q) >= 3:
                    clause = "m.id IN (SELECT id FROM message_fts WHERE body MATCH ?)"
                    term = '"' + q.replace('"', '""') + '"'
                else:
                    clause = "m.body LIKE ? ESCAPE '\\'"
                    term = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
                start, end = ms(args.get("start")), ms(args.get("end"))
                cid = args.get("conversation_id")
                clause += " AND (? IS NULL OR m.conversation_id=?) AND (? IS NULL OR m.sent_ms>=?) AND (? IS NULL OR m.sent_ms<=?)"
                return self.rows(conn, self.select(clause),
                                 (term, cid, cid, start, start, end, end, limit(args.get("limit"), 30), offset(args.get("offset"))))
            if name == "wecom_context":
                mid = str(args["message_id"])
                item = conn.execute("SELECT conversation_id,sent_ms FROM messages WHERE id=?", (mid,)).fetchone()
                if item is None:
                    raise ValueError("找不到消息")
                before, after = limit(args.get("before"), 10, 30), limit(args.get("after"), 10, 30)
                older = self.rows(conn, self.select("m.conversation_id=? AND (m.sent_ms,m.id)<(?,?)"),
                                  (item[0], item[1], mid, before, 0))
                current = self.rows(conn, self.select("m.id=?"), (mid, 1, 0))
                newer = self.rows(conn, self.select("m.conversation_id=? AND (m.sent_ms,m.id)>(?,?)", "ASC"),
                                  (item[0], item[1], mid, after, 0))
                return {"messages": list(reversed(older)) + current + newer}
            if name == "wecom_attachment":
                mid = str(args["message_id"])
                return self.attachment(conn, mid)
            if name == "wecom_since":
                return self.rows(conn, self.select("m.sent_ms>=?", "ASC"),
                                 (ms(args["since"]), limit(args.get("limit")), offset(args.get("offset"))))
        finally:
            conn.close()


def handle(request, index):
    rid = request.get("id")
    if rid is None:
        return None
    method = request.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "wecom-chat-readonly", "version": "0.4.0"},
                  "instructions": "仅查询本机当前账号归档。先搜索，再查看上下文；涉及图片或文件时按消息 ID 调用附件工具。姓名未解析和附件缺失须如实说明。附件工具可能把已匹配缓存文件复制到本地归档，不会修改企微源数据。"}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": specs()}
    elif method == "tools/call":
        params = request.get("params") or {}
        try:
            value = index.call(params.get("name", ""), params.get("arguments") or {})
            result = {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}]}
        except (KeyError, ValueError, FileNotFoundError, sqlite3.Error, OSError) as exc:
            result = {"isError": True, "content": [{"type": "text", "text": str(exc)}]}
    else:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Method not found"}}
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def main():
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=os.environ.get("WECOM_AGENT_DATA"))
    args = parser.parse_args()
    if not args.data_dir:
        parser.error("需要 --data-dir 或 WECOM_AGENT_DATA")
    index = Index(args.data_dir)
    for line in sys.stdin.buffer:
        try:
            request = json.loads(line)
            response = handle(request, index)
            if response is not None:
                sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n")
                sys.stdout.flush()
        except (ValueError, UnicodeDecodeError):
            continue


if __name__ == "__main__":
    main()

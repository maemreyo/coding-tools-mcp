"""Server-side tool receipts for authenticated calls (evidence for the delegation L1 live gate).

An assistant saying "I read the file" is not evidence. This log is written by the provider itself, only for calls that arrived with a verified OAuth
principal, only for an explicit allowlist of read-only tools, and never contains file content, paths or arguments: only digests. Records form a hash
chain (each carries the previous record's hash) so truncation or editing is detectable. It is same-user, same-host evidence, not a remote attestation.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any

SCHEMA = "zam.tool.receipt.v1"
DEFAULT_TOOLS = ("read_file", "list_dir")


def _sha(value: str | bytes) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


class ToolReceiptLog:
    def __init__(self, path: Path, tools: tuple[str, ...] = DEFAULT_TOOLS) -> None:
        if not path.is_absolute():
            raise ValueError("receipt log path must be absolute")
        parent = path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        pst = parent.stat()
        if pst.st_uid != os.getuid() or stat.S_IMODE(pst.st_mode) & 0o077:
            raise ValueError("receipt log directory must be owner-only (0700)")
        self.path = path
        self.tools = frozenset(tools)

    def wants(self, tool: str) -> bool:
        return tool in self.tools

    def record(self, *, tool: str, args: dict[str, Any], payload: dict[str, Any], session_id: str, client_id: str) -> dict[str, Any] | None:
        if not self.wants(tool) or payload.get("ok") is False:
            return None
        content = payload.get("content")
        entry: dict[str, Any] = {
            "schema": SCHEMA,
            "tsMs": int(time.time() * 1000),
            "tool": tool,
            "sessionSha256": _sha(session_id)[:32],
            "clientSha256": _sha(client_id)[:32],
            "argsSha256": _sha(json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)),
            "pathSha256": _sha(str(args["path"])) if isinstance(args.get("path"), str) else None,
            "resultContentSha256": _sha(content) if isinstance(content, str) else None,
            "resultBytes": len(content.encode("utf-8")) if isinstance(content, str) else None,
        }
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            with os.fdopen(os.dup(fd), "rb") as reader:
                reader.seek(0)
                last = None
                seq = 0
                for line in reader:
                    if line.strip():
                        last = json.loads(line)
                        seq = last["seq"]
            entry["seq"] = seq + 1
            entry["prevHash"] = last["hash"] if last else "0" * 64
            entry["hash"] = _sha(json.dumps({k: v for k, v in entry.items() if k != "hash"}, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
            os.write(fd, (json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        return entry


def receipt_log_from_env(env: dict[str, str], prefix: str) -> ToolReceiptLog | None:
    path = env.get(f"{prefix}_RECEIPT_LOG", "")
    if not path:
        return None
    tools = tuple(t for t in env.get(f"{prefix}_RECEIPT_TOOLS", "").split(",") if t) or DEFAULT_TOOLS
    return ToolReceiptLog(Path(path), tools)

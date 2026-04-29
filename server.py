#!/usr/bin/env python3
"""
unicornafl-mcp — MCP server that exposes Unicorn emulation + unicornafl fuzzing
as tools for Claude Desktop.

Design:
    * One persistent emulation session per server process (`SESSION` global).
    * In-process emulation uses `unicorn` directly (no fork).
    * Fuzzing snapshots the session state to disk and spawns `afl-fuzz` against
      a generated harness Python script. The MCP server tracks the spawned
      job and lets the user query status / list crashes / replay them.

Default arch is arm64 because that's what the user is fuzzing.
"""
from __future__ import annotations

import dataclasses
import io
import json
import os
import pickle
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

# Lazily imported (we want clean error messages if the venv is wrong)
try:
    import unicorn
    from unicorn import Uc, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, \
        UC_HOOK_MEM_INVALID, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_PROT_ALL
except ImportError as e:  # pragma: no cover
    sys.stderr.write(
        "[unicornafl-mcp] Failed to import unicorn — did you run setup.sh and "
        "activate the venv?\n"
    )
    raise

try:
    import capstone
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

PROJECT_ROOT = Path(__file__).resolve().parent
WORK_DIR = PROJECT_ROOT / "work"          # session artifacts (snapshots, harness, in/out)
WORK_DIR.mkdir(exist_ok=True)

# arch -> (UC_ARCH, default UC_MODE, capstone arch, capstone mode)
_ARCH_TABLE = {
    "arm64":   (unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM,
                "arm64" if _HAS_CAPSTONE else None, 0),
    "arm":     (unicorn.UC_ARCH_ARM,   unicorn.UC_MODE_ARM,
                "arm"   if _HAS_CAPSTONE else None, 0),
    "x86_64":  (unicorn.UC_ARCH_X86,   unicorn.UC_MODE_64,
                "x86"   if _HAS_CAPSTONE else None, 64),
    "x86":     (unicorn.UC_ARCH_X86,   unicorn.UC_MODE_32,
                "x86"   if _HAS_CAPSTONE else None, 32),
    "mips":    (unicorn.UC_ARCH_MIPS,  unicorn.UC_MODE_MIPS32,
                "mips"  if _HAS_CAPSTONE else None, 32),
}

# Register name -> Unicorn const, per arch.
_REG_TABLES: dict[str, dict[str, int]] = {}
def _build_reg_tables() -> None:
    from unicorn import arm64_const, arm_const, x86_const, mips_const
    def collect(prefix: str, mod) -> dict[str, int]:
        out = {}
        for name in dir(mod):
            if name.startswith(prefix):
                short = name[len(prefix):].lower()
                out[short] = getattr(mod, name)
        return out
    _REG_TABLES["arm64"]  = collect("UC_ARM64_REG_", arm64_const)
    _REG_TABLES["arm"]    = collect("UC_ARM_REG_",   arm_const)
    _REG_TABLES["x86_64"] = collect("UC_X86_REG_",   x86_const)
    _REG_TABLES["x86"]    = collect("UC_X86_REG_",   x86_const)
    _REG_TABLES["mips"]   = collect("UC_MIPS_REG_",  mips_const)
_build_reg_tables()

# Useful "summary" register lists per arch (for reg_dump)
_DUMP_REGS = {
    "arm64": [f"x{i}" for i in range(31)] + ["sp", "pc", "lr", "fp", "nzcv"],
    "arm":   [f"r{i}" for i in range(13)] + ["sp", "lr", "pc", "cpsr"],
    "x86_64": ["rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10",
               "r11","r12","r13","r14","r15","rip","rflags"],
    "x86":   ["eax","ebx","ecx","edx","esi","edi","ebp","esp","eip","eflags"],
    "mips":  [f"v{i}" for i in (0,1)] + [f"a{i}" for i in range(4)] +
             [f"t{i}" for i in range(10)] + [f"s{i}" for i in range(8)] + ["sp","pc"],
}

_PERM_MAP = {"r": UC_PROT_READ, "w": UC_PROT_WRITE, "x": UC_PROT_EXEC}

def _parse_perms(perms: str) -> int:
    """'rwx' / 'r-x' → unicorn prot mask."""
    out = 0
    for ch in perms.lower():
        if ch == "-": continue
        if ch not in _PERM_MAP:
            raise ValueError(f"bad perm char {ch!r}")
        out |= _PERM_MAP[ch]
    return out or UC_PROT_ALL


# --------------------------------------------------------------------------- #
# Session state
# --------------------------------------------------------------------------- #

@dataclasses.dataclass
class MemRegion:
    address: int
    size: int
    perms: str  # e.g. "rwx"
    label: str = ""

@dataclasses.dataclass
class HookEntry:
    hook_id: str           # public id
    handle: Any            # unicorn-internal handle
    kind: str              # "code" | "mem_rw" | "mem_invalid"
    address_range: tuple[int, int]
    events: list[dict]     # captured trace
    max_events: int = 10000

@dataclasses.dataclass
class FuzzInputSpec:
    """How the fuzzer should place each test input."""
    kind: str                       # "memory" | "register"
    address: Optional[int] = None   # for memory
    max_size: int = 1024
    min_size: int = 0
    register: Optional[str] = None  # for register
    little_endian: bool = True

@dataclasses.dataclass
class FuzzJob:
    job_id: str
    pid: int
    output_dir: Path
    input_dir: Path
    harness_path: Path
    inject_dir: Path                # AFL -F foreign sync dir for live seed injection
    started_at: float
    cmd: list[str]
    process: Optional[subprocess.Popen] = None  # not picklable — runtime only

class Session:
    def __init__(self):
        self.arch: Optional[str] = None
        self.mode_name: Optional[str] = None
        self.uc: Optional[Uc] = None
        self.regions: list[MemRegion] = []
        self.hooks: dict[str, HookEntry] = {}
        self.last_result: dict[str, Any] = {}
        self.fuzz_input: Optional[FuzzInputSpec] = None
        self.fuzz_exits: list[int] = []
        self.fuzz_persistent_iters: int = 1
        self.snapshots: dict[str, Path] = {}
        self.jobs: dict[str, FuzzJob] = {}

    def require(self) -> Uc:
        if self.uc is None:
            raise RuntimeError("No active session — call session_init first.")
        return self.uc

    def reg_const(self, name: str) -> int:
        tbl = _REG_TABLES.get(self.arch or "", {})
        try:
            return tbl[name.lower()]
        except KeyError:
            raise ValueError(f"unknown register {name!r} for arch {self.arch}")

SESSION = Session()


# --------------------------------------------------------------------------- #
# MCP server
# --------------------------------------------------------------------------- #

mcp = FastMCP("unicornafl-mcp")


def _hexdump(data: bytes, addr: int = 0, width: int = 16, max_bytes: int = 512) -> str:
    """Compact hex dump for tool replies."""
    if len(data) > max_bytes:
        head = _hexdump(data[:max_bytes], addr, width, max_bytes=10**9)
        return head + f"\n... ({len(data) - max_bytes} more bytes truncated)"
    out = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{addr+i:016x}  {hexs:<{width*3}}  {ascii_}")
    return "\n".join(out)


def _ok(msg: str, **extra) -> dict:
    return {"ok": True, "message": msg, **extra}

def _err(msg: str, **extra) -> dict:
    return {"ok": False, "error": msg, **extra}


# ---------- session lifecycle ----------

@mcp.tool()
def session_init(arch: str = "arm64", mode: str = "default") -> dict:
    """Create a fresh Unicorn session.

    Args:
        arch: One of arm64 (default), arm, x86_64, x86, mips.
        mode: 'default' uses the natural mode for the arch. Override only if needed
              (e.g. 'thumb' for arm).
    """
    if arch not in _ARCH_TABLE:
        return _err(f"unsupported arch {arch!r}; pick one of {list(_ARCH_TABLE)}")
    uc_arch, uc_mode_default, _, _ = _ARCH_TABLE[arch]
    uc_mode = uc_mode_default
    if mode == "thumb":
        uc_mode = unicorn.UC_MODE_THUMB
    elif mode != "default":
        return _err(f"unknown mode {mode!r} (try 'default' or 'thumb')")

    # destroy old session
    SESSION.__init__()
    SESSION.arch = arch
    SESSION.mode_name = mode
    SESSION.uc = Uc(uc_arch, uc_mode)
    return _ok(f"session ready (arch={arch}, mode={mode})")


@mcp.tool()
def session_status() -> dict:
    """Summary of the current emulation session."""
    if SESSION.uc is None:
        return _err("no session")
    return {
        "ok": True,
        "arch": SESSION.arch,
        "mode": SESSION.mode_name,
        "regions": [dataclasses.asdict(r) for r in SESSION.regions],
        "hooks": [{"id": h.hook_id, "kind": h.kind, "range": h.address_range,
                   "events": len(h.events)} for h in SESSION.hooks.values()],
        "fuzz_configured": SESSION.fuzz_input is not None,
        "exits": [hex(e) for e in SESSION.fuzz_exits],
        "snapshots": list(SESSION.snapshots),
        "fuzz_jobs": list(SESSION.jobs),
        "last_result": SESSION.last_result,
    }


@mcp.tool()
def session_reset() -> dict:
    """Drop the current session. Does not stop running fuzz jobs."""
    SESSION.__init__()
    return _ok("session reset")


# ---------- memory ----------

@mcp.tool()
def mem_map(address: int, size: int, perms: str = "rwx", label: str = "") -> dict:
    """Map a memory region.

    Args:
        address: Base address (must be page-aligned, usually 0x1000-aligned).
        size: Region size in bytes (will be rounded up to page granularity by Unicorn).
        perms: Permission string like 'rwx', 'r-x', 'rw-'.
        label: Free-form name for your own bookkeeping.
    """
    uc = SESSION.require()
    uc.mem_map(address, size, _parse_perms(perms))
    SESSION.regions.append(MemRegion(address, size, perms, label))
    return _ok(f"mapped {size:#x} bytes at {address:#x} ({perms})")


@mcp.tool()
def mem_unmap(address: int, size: int) -> dict:
    """Unmap a previously-mapped region."""
    uc = SESSION.require()
    uc.mem_unmap(address, size)
    SESSION.regions = [r for r in SESSION.regions
                       if not (r.address == address and r.size == size)]
    return _ok(f"unmapped {size:#x}@{address:#x}")


@mcp.tool()
def mem_write(address: int, hex_data: str) -> dict:
    """Write bytes (given as a hex string, e.g. 'deadbeef' or 'de ad be ef') at address.

    The region must already be mapped.
    """
    uc = SESSION.require()
    cleaned = re.sub(r"\s+", "", hex_data)
    if len(cleaned) % 2 != 0:
        return _err("hex_data has odd length")
    data = bytes.fromhex(cleaned)
    uc.mem_write(address, data)
    return _ok(f"wrote {len(data)} bytes @ {address:#x}")


@mcp.tool()
def mem_write_file(address: int, file_path: str, offset: int = 0, length: int = -1) -> dict:
    """Write bytes from a file on disk into emulated memory.

    Args:
        address: Where to write in emulated memory.
        file_path: Absolute path to source file.
        offset: Byte offset inside the file to start from.
        length: How many bytes to copy (-1 = until EOF).
    """
    uc = SESSION.require()
    p = Path(file_path)
    if not p.is_file():
        return _err(f"file not found: {file_path}")
    with p.open("rb") as f:
        f.seek(offset)
        data = f.read() if length < 0 else f.read(length)
    uc.mem_write(address, data)
    return _ok(f"wrote {len(data)} bytes from {file_path} to {address:#x}")


@mcp.tool()
def mem_read(address: int, size: int, format: str = "hex") -> dict:
    """Read `size` bytes from emulated memory.

    Args:
        format: 'hex' (raw hex string), 'dump' (hex+ASCII view), 'str' (utf-8 best effort).
    """
    uc = SESSION.require()
    data = bytes(uc.mem_read(address, size))
    if format == "hex":
        return {"ok": True, "address": address, "size": size, "hex": data.hex()}
    if format == "dump":
        return {"ok": True, "address": address, "size": size,
                "dump": _hexdump(data, address)}
    if format == "str":
        try:
            return {"ok": True, "address": address, "size": size,
                    "string": data.decode("utf-8", errors="replace")}
        except Exception as e:
            return _err(f"decode error: {e}")
    return _err(f"unknown format {format!r}")


@mcp.tool()
def mem_regions() -> dict:
    """List all mapped regions tracked by the session."""
    return {"ok": True, "regions": [dataclasses.asdict(r) for r in SESSION.regions]}


# ---------- registers ----------

@mcp.tool()
def reg_write(name: str, value: int) -> dict:
    """Write `value` to register `name` (case-insensitive, e.g. 'x0', 'pc')."""
    uc = SESSION.require()
    uc.reg_write(SESSION.reg_const(name), value)
    return _ok(f"{name} = {value:#x}")


@mcp.tool()
def reg_read(name: str) -> dict:
    """Read register `name`."""
    uc = SESSION.require()
    val = uc.reg_read(SESSION.reg_const(name))
    return {"ok": True, "name": name, "value": val, "hex": hex(val)}


@mcp.tool()
def reg_dump(names: list[str] | None = None) -> dict:
    """Dump a list of registers; defaults to the standard set for the arch."""
    uc = SESSION.require()
    if names is None:
        names = _DUMP_REGS.get(SESSION.arch, [])
    out = {}
    for n in names:
        try:
            out[n] = hex(uc.reg_read(SESSION.reg_const(n)))
        except Exception as e:
            out[n] = f"<err: {e}>"
    return {"ok": True, "registers": out}


# ---------- code loading ----------

@mcp.tool()
def load_code(address: int, hex_data: str = "", file_path: str = "",
              perms: str = "r-x", auto_map: bool = True, label: str = "code") -> dict:
    """Convenience: map a region (if auto_map) and write code into it.

    Either `hex_data` or `file_path` must be provided.
    """
    uc = SESSION.require()
    if (hex_data == "") == (file_path == ""):
        return _err("provide exactly one of hex_data or file_path")
    if file_path:
        data = Path(file_path).read_bytes()
    else:
        data = bytes.fromhex(re.sub(r"\s+", "", hex_data))
    if auto_map:
        # round up to nearest 0x1000
        page = 0x1000
        msize = (len(data) + page - 1) & ~(page - 1)
        if msize == 0: msize = page
        try:
            uc.mem_map(address, msize, _parse_perms(perms))
            SESSION.regions.append(MemRegion(address, msize, perms, label))
        except unicorn.UcError:
            pass  # already mapped — assume caller knows what they're doing
    uc.mem_write(address, data)
    return _ok(f"loaded {len(data)} bytes of code @ {address:#x}",
               address=address, size=len(data))


# ---------- hooks / tracing ----------

def _new_hook_id() -> str:
    return f"h{len(SESSION.hooks)+1}"


@mcp.tool()
def hook_code(start: int, end: int, max_events: int = 1000) -> dict:
    """Trace every instruction executed in [start, end].

    Returns a hook_id; use get_trace(hook_id) to read the captured events
    and remove_hook(hook_id) to remove it.
    """
    uc = SESSION.require()
    hid = _new_hook_id()
    events: list[dict] = []
    def cb(uc_, address, size, _user):
        if len(events) >= max_events:
            return
        events.append({"pc": address, "size": size})
    handle = uc.hook_add(UC_HOOK_CODE, cb, begin=start, end=end)
    SESSION.hooks[hid] = HookEntry(hid, handle, "code", (start, end), events, max_events)
    return _ok(f"installed code hook {hid}", hook_id=hid)


@mcp.tool()
def hook_mem(start: int, end: int, kind: str = "rw", max_events: int = 1000) -> dict:
    """Trace memory accesses in [start, end].

    Args:
        kind: 'r' (reads), 'w' (writes), 'rw' (both), 'invalid' (faults).
    """
    uc = SESSION.require()
    if kind not in ("r", "w", "rw", "invalid"):
        return _err(f"bad kind {kind!r}")
    hid = _new_hook_id()
    events: list[dict] = []
    def cb(uc_, access, address, size, value, _user):
        if len(events) >= max_events:
            return
        events.append({"access": access, "addr": address, "size": size, "value": value})
    if kind == "invalid":
        handle = uc.hook_add(UC_HOOK_MEM_INVALID, cb, begin=start, end=end)
        kind_full = "mem_invalid"
    else:
        flag = 0
        if "r" in kind: flag |= UC_HOOK_MEM_READ
        if "w" in kind: flag |= UC_HOOK_MEM_WRITE
        handle = uc.hook_add(flag, cb, begin=start, end=end)
        kind_full = "mem_rw"
    SESSION.hooks[hid] = HookEntry(hid, handle, kind_full, (start, end), events, max_events)
    return _ok(f"installed {kind_full} hook {hid}", hook_id=hid)


@mcp.tool()
def get_trace(hook_id: str, limit: int = 200, format_pc_hex: bool = True) -> dict:
    """Fetch (up to limit) captured events for a hook."""
    h = SESSION.hooks.get(hook_id)
    if h is None:
        return _err(f"no hook {hook_id!r}")
    events = h.events[-limit:]
    if format_pc_hex:
        events = [
            {**e, **{k: hex(v) for k, v in e.items()
                     if k in ("pc", "addr", "value") and isinstance(v, int)}}
            for e in events
        ]
    return {"ok": True, "hook_id": hook_id, "kind": h.kind, "total": len(h.events),
            "events": events}


@mcp.tool()
def remove_hook(hook_id: str) -> dict:
    """Remove a previously installed hook."""
    uc = SESSION.require()
    h = SESSION.hooks.pop(hook_id, None)
    if h is None:
        return _err(f"no hook {hook_id!r}")
    uc.hook_del(h.handle)
    return _ok(f"removed {hook_id}")


# ---------- emulation ----------

@mcp.tool()
def emu_start(begin: int, until: int = 0, timeout_us: int = 0, count: int = 0) -> dict:
    """Run the emulator from `begin` until either `until` is reached, `timeout_us`
    microseconds pass, or `count` instructions have been executed (0 = unlimited).
    """
    uc = SESSION.require()
    started = time.time()
    try:
        uc.emu_start(begin, until, timeout=timeout_us, count=count)
        ok = True; err = None
    except unicorn.UcError as e:
        ok = False; err = str(e)
    elapsed_ms = (time.time() - started) * 1000
    pc_name = {"arm64": "pc", "arm": "pc", "x86_64": "rip",
               "x86": "eip", "mips": "pc"}[SESSION.arch]
    pc_after = uc.reg_read(SESSION.reg_const(pc_name))
    SESSION.last_result = {"ok": ok, "error": err, "pc_after": hex(pc_after),
                           "elapsed_ms": round(elapsed_ms, 3)}
    return {"ok": ok, "error": err, "pc_after": hex(pc_after),
            "elapsed_ms": round(elapsed_ms, 3)}


@mcp.tool()
def emu_stop() -> dict:
    """Request the emulator to stop (effective the next instruction)."""
    SESSION.require().emu_stop()
    return _ok("emu_stop signalled")


@mcp.tool()
def disasm(address: int, count: int = 16, size_hint: int = 256) -> dict:
    """Disassemble `count` instructions at `address` using capstone (if installed)."""
    if not _HAS_CAPSTONE:
        return _err("capstone not installed; pip install capstone")
    uc = SESSION.require()
    cs_arch_name = _ARCH_TABLE[SESSION.arch][2]
    cs_arch = {"arm64": capstone.CS_ARCH_ARM64, "arm": capstone.CS_ARCH_ARM,
               "x86": capstone.CS_ARCH_X86, "mips": capstone.CS_ARCH_MIPS}[cs_arch_name]
    cs_mode = {"arm64": capstone.CS_MODE_ARM, "arm": capstone.CS_MODE_ARM,
               "x86": capstone.CS_MODE_64 if SESSION.arch == "x86_64"
                      else capstone.CS_MODE_32,
               "mips": capstone.CS_MODE_MIPS32}[cs_arch_name]
    md = capstone.Cs(cs_arch, cs_mode)
    data = bytes(uc.mem_read(address, size_hint))
    out = []
    for i, ins in enumerate(md.disasm(data, address)):
        if i >= count: break
        out.append(f"{ins.address:#x}:  {ins.mnemonic} {ins.op_str}")
    return {"ok": True, "address": hex(address), "instructions": out}


# ---------- snapshots ----------

@mcp.tool()
def snapshot_save(name: str = "default") -> dict:
    """Pickle the full session state (regs + memory) to disk for later restore
    or to feed a fuzzing harness.
    """
    uc = SESSION.require()
    snap_dir = WORK_DIR / "snapshots" / name
    snap_dir.mkdir(parents=True, exist_ok=True)

    regs = {}
    for n in _DUMP_REGS.get(SESSION.arch, []):
        try:
            regs[n] = uc.reg_read(SESSION.reg_const(n))
        except Exception:
            pass

    region_files = []
    for i, r in enumerate(SESSION.regions):
        path = snap_dir / f"region_{i:03d}.bin"
        path.write_bytes(bytes(uc.mem_read(r.address, r.size)))
        region_files.append({"address": r.address, "size": r.size,
                             "perms": r.perms, "label": r.label,
                             "file": str(path)})

    meta = {
        "arch": SESSION.arch,
        "mode_name": SESSION.mode_name,
        "regs": regs,
        "regions": region_files,
        "exits": SESSION.fuzz_exits,
        "fuzz_input": dataclasses.asdict(SESSION.fuzz_input) if SESSION.fuzz_input else None,
        "persistent_iters": SESSION.fuzz_persistent_iters,
    }
    meta_path = snap_dir / "meta.json"
    meta_path.write_text(json.dumps(meta, indent=2))
    SESSION.snapshots[name] = meta_path
    return _ok(f"snapshot '{name}' saved", path=str(meta_path))


@mcp.tool()
def snapshot_load(name: str = "default") -> dict:
    """Restore session from an on-disk snapshot."""
    meta_path = SESSION.snapshots.get(name)
    if meta_path is None:
        meta_path = WORK_DIR / "snapshots" / name / "meta.json"
        if not meta_path.exists():
            return _err(f"snapshot {name!r} not found")
    meta = json.loads(meta_path.read_text())
    session_init(meta["arch"], meta["mode_name"])  # rebuilds Uc
    uc = SESSION.require()
    for r in meta["regions"]:
        uc.mem_map(r["address"], r["size"], _parse_perms(r["perms"]))
        uc.mem_write(r["address"], Path(r["file"]).read_bytes())
        SESSION.regions.append(MemRegion(r["address"], r["size"],
                                         r["perms"], r["label"]))
    for n, v in meta["regs"].items():
        try: uc.reg_write(SESSION.reg_const(n), v)
        except Exception: pass
    if meta.get("fuzz_input"):
        SESSION.fuzz_input = FuzzInputSpec(**meta["fuzz_input"])
    SESSION.fuzz_exits = meta.get("exits", [])
    SESSION.fuzz_persistent_iters = meta.get("persistent_iters", 1)
    SESSION.snapshots[name] = meta_path
    return _ok(f"snapshot '{name}' loaded")


@mcp.tool()
def snapshot_list() -> dict:
    """List snapshots known to this session and any on-disk snapshots."""
    on_disk = []
    snap_root = WORK_DIR / "snapshots"
    if snap_root.is_dir():
        for d in snap_root.iterdir():
            if (d / "meta.json").exists():
                on_disk.append(d.name)
    return {"ok": True, "in_session": list(SESSION.snapshots),
            "on_disk": sorted(on_disk)}


# ---------- fuzzing ----------

@mcp.tool()
def fuzz_configure(input_kind: str, max_size: int = 1024, min_size: int = 0,
                   address: int = 0, register: str = "",
                   little_endian: bool = True,
                   exits: list[int] | None = None,
                   persistent_iters: int = 1) -> dict:
    """Describe how AFL inputs should be placed and where the harness exits.

    Args:
        input_kind: 'memory' or 'register'.
        max_size: Hard cap on input size accepted.
        min_size: Inputs shorter than this are rejected.
        address: For input_kind='memory': where to write the input bytes.
        register: For input_kind='register': name of register to load with input as int.
        little_endian: Endianness when loading bytes into a register.
        exits: List of addresses the harness considers as legitimate exits.
        persistent_iters: 1 = fork on every input (slow but safe). 0 = run forever
            (you must restore state inside place_input, advanced).
    """
    if input_kind not in ("memory", "register"):
        return _err("input_kind must be 'memory' or 'register'")
    if input_kind == "memory" and address == 0:
        return _err("address required for input_kind='memory'")
    if input_kind == "register" and not register:
        return _err("register required for input_kind='register'")
    if input_kind == "register":
        # validate register name early
        SESSION.reg_const(register)
    SESSION.fuzz_input = FuzzInputSpec(
        kind=input_kind,
        address=address if input_kind == "memory" else None,
        max_size=max_size,
        min_size=min_size,
        register=register if input_kind == "register" else None,
        little_endian=little_endian,
    )
    SESSION.fuzz_exits = list(exits or [])
    SESSION.fuzz_persistent_iters = persistent_iters
    return _ok("fuzz config saved",
               input=dataclasses.asdict(SESSION.fuzz_input),
               exits=[hex(e) for e in SESSION.fuzz_exits])


@mcp.tool()
def fuzz_seed_corpus(seeds: list[str] | None = None, files: list[str] | None = None,
                    clear: bool = False) -> dict:
    """Populate the AFL input corpus directory.

    Args:
        seeds: List of literal strings — each becomes one seed file.
        files: List of paths to existing files to copy in as seeds.
        clear: If True, wipe the corpus dir first.
    """
    in_dir = WORK_DIR / "in"
    if clear and in_dir.exists():
        shutil.rmtree(in_dir)
    in_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for i, s in enumerate(seeds or []):
        p = in_dir / f"seed_{i:03d}"
        p.write_bytes(s.encode() if isinstance(s, str) else bytes(s))
        written.append(str(p))
    for f in files or []:
        src = Path(f)
        if not src.is_file():
            return _err(f"file not found: {f}")
        dst = in_dir / src.name
        shutil.copy(src, dst)
        written.append(str(dst))
    if not written and not any(in_dir.iterdir()):
        # AFL refuses to start with empty corpus — drop a default
        (in_dir / "default").write_bytes(b"A" * 8)
        written.append(str(in_dir / "default"))
    return _ok(f"corpus has {len(list(in_dir.iterdir()))} entries", path=str(in_dir))


def _generate_harness(snapshot_name: str, harness_path: Path) -> None:
    """Write a self-contained Python harness that loads a snapshot and calls
    unicornafl.uc_afl_fuzz.
    """
    template = (PROJECT_ROOT / "harness_template.py").read_text()
    harness_path.write_text(
        template.replace("__SNAPSHOT_DIR__",
                         str((WORK_DIR / "snapshots" / snapshot_name).resolve()))
    )
    harness_path.chmod(0o755)


@mcp.tool()
def fuzz_generate_harness(snapshot_name: str = "default",
                          harness_name: str = "harness.py") -> dict:
    """Snapshot the current session (if not already done) and emit a Python
    harness ready to be driven by `afl-fuzz -U`.
    """
    if SESSION.fuzz_input is None:
        return _err("call fuzz_configure first")
    if not SESSION.fuzz_exits:
        return _err("fuzz_configure must include at least one exit")
    snapshot_save(snapshot_name)
    harness_path = WORK_DIR / harness_name
    _generate_harness(snapshot_name, harness_path)
    return _ok(f"harness written to {harness_path}",
               harness=str(harness_path),
               snapshot=str(WORK_DIR / "snapshots" / snapshot_name))


@mcp.tool()
def fuzz_test_harness(input_path: str = "", input_hex: str = "") -> dict:
    """Run the generated harness once in standalone mode (no afl-fuzz) to verify
    it executes correctly. Provide either a file path or raw hex bytes.
    """
    harness = WORK_DIR / "harness.py"
    if not harness.exists():
        return _err("no harness — call fuzz_generate_harness first")
    if (input_path == "") == (input_hex == ""):
        return _err("provide exactly one of input_path or input_hex")
    if input_hex:
        in_path = WORK_DIR / "standalone_input.bin"
        in_path.write_bytes(bytes.fromhex(re.sub(r"\s+", "", input_hex)))
    else:
        in_path = Path(input_path)
        if not in_path.is_file():
            return _err(f"file not found: {input_path}")
    proc = subprocess.run(
        [sys.executable, str(harness), str(in_path)],
        capture_output=True, text=True, timeout=30,
    )
    return {"ok": proc.returncode == 0, "returncode": proc.returncode,
            "stdout": proc.stdout[-4000:], "stderr": proc.stderr[-4000:]}


@mcp.tool()
def fuzz_start(timeout_sec: int = 0, cmplog: bool = True,
               extra_afl_args: list[str] | None = None) -> dict:
    """Spawn `afl-fuzz -U` against the generated harness.

    Args:
        timeout_sec: Stop the campaign after this many seconds (0 = run until stopped).
        cmplog: Pass `-c 0` to AFL++ (recommended; bypasses long compares).
        extra_afl_args: Anything else to splice into the afl-fuzz invocation.
    """
    harness = WORK_DIR / "harness.py"
    if not harness.exists():
        return _err("no harness — call fuzz_generate_harness first")
    in_dir = WORK_DIR / "in"
    if not in_dir.is_dir() or not any(in_dir.iterdir()):
        return _err("input corpus is empty — call fuzz_seed_corpus first")
    out_dir = WORK_DIR / "out"
    out_dir.mkdir(exist_ok=True)

    afl = shutil.which("afl-fuzz")
    if afl is None:
        return _err("afl-fuzz not in PATH — run setup.sh first")

    job_id = uuid.uuid4().hex[:8]
    inject_dir = WORK_DIR / "inject" / job_id
    inject_dir.mkdir(parents=True, exist_ok=True)
    cmd = [afl, "-U", "-i", str(in_dir), "-o", str(out_dir),
           "-M", "main",
           "-F", str(inject_dir)]
    if cmplog:
        cmd += ["-c", "0"]
    if timeout_sec > 0:
        cmd += ["-V", str(timeout_sec)]
    cmd += list(extra_afl_args or [])
    cmd += ["--", sys.executable, str(harness)]

    log_path = WORK_DIR / f"fuzz_{job_id}.log"
    log_fp = open(log_path, "wb")
    env = os.environ.copy()
    env.setdefault("AFL_SKIP_CPUFREQ", "1")
    env.setdefault("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
    proc = subprocess.Popen(cmd, stdout=log_fp, stderr=subprocess.STDOUT, env=env)

    job = FuzzJob(job_id=job_id, pid=proc.pid, output_dir=out_dir,
                  input_dir=in_dir, harness_path=harness,
                  inject_dir=inject_dir,
                  started_at=time.time(), cmd=cmd, process=proc)
    SESSION.jobs[job_id] = job
    return _ok(f"fuzzing started (job {job_id}, pid {proc.pid})",
               job_id=job_id, log=str(log_path), cmd=" ".join(shlex.quote(a) for a in cmd))


@mcp.tool()
def fuzz_status(job_id: str = "") -> dict:
    """Report status of a fuzzing job (or all jobs if job_id is empty).

    Reads `out/default/fuzzer_stats` produced by AFL++.
    """
    def one(job: FuzzJob) -> dict:
        proc = job.process
        alive = proc is not None and proc.poll() is None
        stats_path = job.output_dir / "default" / "fuzzer_stats"
        stats: dict[str, str] = {}
        if stats_path.exists():
            for line in stats_path.read_text().splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    stats[k.strip()] = v.strip()
        crashes_dir = job.output_dir / "default" / "crashes"
        n_crashes = sum(1 for f in crashes_dir.iterdir()
                        if f.is_file() and not f.name.startswith("README")) \
                    if crashes_dir.exists() else 0
        return {
            "job_id": job.job_id, "pid": job.pid, "alive": alive,
            "uptime_sec": int(time.time() - job.started_at),
            "output_dir": str(job.output_dir),
            "stats": stats, "crashes": n_crashes,
        }

    if job_id:
        job = SESSION.jobs.get(job_id)
        if job is None: return _err(f"no job {job_id!r}")
        return {"ok": True, **one(job)}
    return {"ok": True, "jobs": [one(j) for j in SESSION.jobs.values()]}


@mcp.tool()
def fuzz_stop(job_id: str) -> dict:
    """Send SIGINT to a fuzz job (afl-fuzz handles it gracefully)."""
    job = SESSION.jobs.get(job_id)
    if job is None:
        return _err(f"no job {job_id!r}")
    if job.process is None or job.process.poll() is not None:
        return _ok(f"job {job_id} already terminated")
    try:
        os.kill(job.pid, signal.SIGINT)
    except ProcessLookupError:
        return _ok(f"pid {job.pid} not running anymore")
    return _ok(f"SIGINT sent to {job_id} (pid {job.pid})")


@mcp.tool()
def fuzz_list_crashes(job_id: str = "") -> dict:
    """List crash inputs found by an AFL job."""
    job = SESSION.jobs.get(job_id) if job_id \
          else next(iter(SESSION.jobs.values()), None)
    if job is None: return _err("no fuzz job — start one first")
    crashes_dir = job.output_dir / "default" / "crashes"
    if not crashes_dir.exists():
        return {"ok": True, "crashes": []}
    crashes = []
    for f in sorted(crashes_dir.iterdir()):
        if f.is_file() and not f.name.startswith("README"):
            crashes.append({"name": f.name, "size": f.stat().st_size,
                            "path": str(f)})
    return {"ok": True, "job_id": job.job_id, "crashes": crashes}


@mcp.tool()
def fuzz_replay_crash(crash_path: str, timeout_sec: int = 30) -> dict:
    """Re-run the harness in standalone mode against a crash input and report
    the resulting Unicorn error / register state.
    """
    harness = WORK_DIR / "harness.py"
    if not harness.exists():
        return _err("no harness")
    proc = subprocess.run(
        [sys.executable, str(harness), crash_path, "--replay"],
        capture_output=True, text=True, timeout=timeout_sec,
    )
    return {"ok": proc.returncode == 0, "returncode": proc.returncode,
            "stdout": proc.stdout[-8000:], "stderr": proc.stderr[-8000:]}


# --------------------------------------------------------------------------- #
# LLM-guided fuzzing helpers
#
# These tools turn the MCP into a feedback loop with Claude:
#   - The MCP exposes structured signals about the target (immediates, strings,
#     access patterns, comparisons, coverage trend).
#   - Claude reasons over them and proposes new seeds / templates.
#   - The MCP injects those seeds back into a live AFL campaign.
#
# Loosely follows ChatAFL (NDSS '24) — adapted from protocol/text fuzzing to
# binary fuzzing where Claude itself is the LLM.
# --------------------------------------------------------------------------- #

import csv
import itertools
import random
import struct


# Field-encoding formats for seeds_from_struct_spec
_INT_FMTS = {
    "u8":     "<B",  "i8":     "<b",
    "u16_le": "<H",  "u16_be": ">H",
    "i16_le": "<h",  "i16_be": ">h",
    "u32_le": "<I",  "u32_be": ">I",
    "i32_le": "<i",  "i32_be": ">i",
    "u64_le": "<Q",  "u64_be": ">Q",
    "i64_le": "<q",  "i64_be": ">q",
}


def _capstone_for_session():
    if not _HAS_CAPSTONE:
        raise RuntimeError("capstone not installed")
    cs_arch_name = _ARCH_TABLE[SESSION.arch][2]
    cs_arch = {"arm64": capstone.CS_ARCH_ARM64, "arm": capstone.CS_ARCH_ARM,
               "x86": capstone.CS_ARCH_X86, "mips": capstone.CS_ARCH_MIPS}[cs_arch_name]
    cs_mode = {"arm64": capstone.CS_MODE_ARM, "arm": capstone.CS_MODE_ARM,
               "x86": capstone.CS_MODE_64 if SESSION.arch == "x86_64"
                      else capstone.CS_MODE_32,
               "mips": capstone.CS_MODE_MIPS32}[cs_arch_name]
    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = True
    return md


def _imm_op_type() -> int:
    """Capstone OP_IMM constant for the active arch."""
    return {
        "arm64":  capstone.arm64.ARM64_OP_IMM,
        "arm":    capstone.arm.ARM_OP_IMM,
        "x86":    capstone.x86.X86_OP_IMM,
        "x86_64": capstone.x86.X86_OP_IMM,
        "mips":   capstone.mips.MIPS_OP_IMM,
    }[SESSION.arch]


def _reg_op_type() -> int:
    return {
        "arm64":  capstone.arm64.ARM64_OP_REG,
        "arm":    capstone.arm.ARM_OP_REG,
        "x86":    capstone.x86.X86_OP_REG,
        "x86_64": capstone.x86.X86_OP_REG,
        "mips":   capstone.mips.MIPS_OP_REG,
    }[SESSION.arch]


# ---------- (1) Static / dynamic input-structure analysis ---------- #

@mcp.tool()
def find_immediates(start: int, end: int, min_value: int = 0x10,
                    max_value: int = 0xFFFFFFFFFFFFFFFF,
                    only_compares: bool = True) -> dict:
    """Walk disassembly in [start, end) and collect immediate constants.

    These are prime "magic byte" candidates for shaping seeds — the input
    likely needs to match one of them somewhere.

    Args:
        only_compares: If True, only immediates appearing in compare-like
            instructions (cmp, subs, cbz/cbnz, tbz/tbnz, etc.). If False,
            include all immediates (mov, add, etc.).
        min_value/max_value: Filter range.
    """
    if not _HAS_CAPSTONE:
        return _err("capstone not installed")
    uc = SESSION.require()
    md = _capstone_for_session()
    data = bytes(uc.mem_read(start, end - start))
    cmp_mnems = {"cmp", "cmn", "subs", "tst", "teq", "cbz", "cbnz",
                 "tbz", "tbnz", "test", "ccmp", "ccmn"}
    imm_ty = _imm_op_type()
    out: list[dict] = []
    seen = set()
    for ins in md.disasm(data, start):
        if only_compares and ins.mnemonic.lower() not in cmp_mnems:
            continue
        for op in ins.operands:
            if getattr(op, "type", None) != imm_ty:
                continue
            iv = (op.imm if hasattr(op, "imm") else op.value) & 0xFFFFFFFFFFFFFFFF
            if not (min_value <= iv <= max_value): continue
            key = (ins.address, iv)
            if key in seen: continue
            seen.add(key)
            out.append({"pc": hex(ins.address),
                        "insn": f"{ins.mnemonic} {ins.op_str}",
                        "value": iv, "hex": hex(iv)})
    # Also dedupe by value across PCs and emit a "popular constants" summary
    by_value: dict[int, int] = {}
    for e in out:
        by_value[e["value"]] = by_value.get(e["value"], 0) + 1
    popular = sorted(by_value.items(), key=lambda kv: -kv[1])[:32]
    return {"ok": True, "count": len(out), "events": out[:200],
            "popular_values": [{"value": v, "hex": hex(v), "occurrences": n}
                               for v, n in popular]}


@mcp.tool()
def find_strings(address: int, size: int, min_len: int = 4) -> dict:
    """Scan a memory region for printable ASCII / wide strings.

    String constants in the target often hint at format keywords (magic,
    field names, error messages) — useful for Claude to infer structure.
    """
    uc = SESSION.require()
    data = bytes(uc.mem_read(address, size))
    out_ascii = []
    cur = bytearray(); cur_off = 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7F:
            if not cur: cur_off = i
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out_ascii.append({"offset": cur_off, "addr": hex(address+cur_off),
                                  "len": len(cur), "text": cur.decode()})
            cur = bytearray()
    if len(cur) >= min_len:
        out_ascii.append({"offset": cur_off, "addr": hex(address+cur_off),
                          "len": len(cur), "text": cur.decode()})
    return {"ok": True, "ascii": out_ascii[:200], "total": len(out_ascii)}


@mcp.tool()
def probe_input_access(input_address: int, input_size: int, begin: int,
                       until: int = 0, seed_hex: str = "",
                       timeout_us: int = 5_000_000,
                       max_events: int = 1024) -> dict:
    """Run the emulator once and record every read of the input buffer.

    Tells Claude exactly which offsets are read, in what order, and at which
    sizes — i.e. the access pattern of the parser. Excellent for inferring
    record/field layout.

    Args:
        input_address/input_size: Region treated as the input buffer.
        begin/until: Where to start/stop emulation.
        seed_hex: Optional bytes to write into [input_address, +input_size)
            before starting. If empty, uses whatever is currently there.
        timeout_us: Hard timeout (microseconds).
    """
    uc = SESSION.require()
    if seed_hex:
        data = bytes.fromhex(re.sub(r"\s+", "", seed_hex))
        if len(data) > input_size:
            return _err(f"seed_hex ({len(data)}B) > input_size ({input_size}B)")
        uc.mem_write(input_address, data + b"\x00" * (input_size - len(data)))
    events: list[dict] = []
    def cb(uc_, access, addr, size, value, _u):
        if len(events) >= max_events: return
        events.append({
            "pc": hex(uc_.reg_read(SESSION.reg_const(
                "pc" if SESSION.arch in ("arm64","arm","mips") else
                ("rip" if SESSION.arch == "x86_64" else "eip")))),
            "offset": addr - input_address,
            "addr": hex(addr), "size": size, "value": value,
        })
    h = uc.hook_add(UC_HOOK_MEM_READ, cb,
                    begin=input_address, end=input_address + input_size - 1)
    err = None
    try:
        uc.emu_start(begin, until, timeout=timeout_us)
    except unicorn.UcError as e:
        err = str(e)
    finally:
        uc.hook_del(h)

    # Summarise accessed offsets
    touched = sorted({(e["offset"], e["size"]) for e in events})
    by_offset: dict[int, int] = {}
    for off, sz in touched:
        by_offset[off] = max(by_offset.get(off, 0), sz)
    coverage = sorted(by_offset.items())
    return {"ok": err is None, "error": err, "events_total": len(events),
            "events": events[:200],
            "byte_offsets_read": [{"offset": o, "max_width": w}
                                  for o, w in coverage]}


@mcp.tool()
def probe_compare_log(begin: int, until: int = 0, seed_hex: str = "",
                      input_address: int = 0, input_size: int = 0,
                      timeout_us: int = 5_000_000,
                      max_events: int = 256) -> dict:
    """Run the emulator with a code hook on every compare-like instruction
    and log the runtime operand values. This is a lightweight CmpLog —
    extremely useful for spotting "input must equal 0xDEADBEEF" comparisons
    that AFL would otherwise need many cycles to crack.

    If seed_hex + input_address are given, writes the seed first.
    """
    if not _HAS_CAPSTONE:
        return _err("capstone not installed")
    uc = SESSION.require()
    md = _capstone_for_session()
    cmp_mnems = {"cmp", "cmn", "subs", "tst", "teq", "cbz", "cbnz",
                 "tbz", "tbnz", "test", "ccmp", "ccmn"}

    if seed_hex and input_size > 0:
        data = bytes.fromhex(re.sub(r"\s+", "", seed_hex))
        if len(data) <= input_size:
            uc.mem_write(input_address, data + b"\x00" * (input_size - len(data)))

    imm_ty = _imm_op_type()
    reg_ty = _reg_op_type()
    events: list[dict] = []
    def code_cb(uc_, address, ins_size, _u):
        if len(events) >= max_events: return
        try:
            insn_bytes = bytes(uc_.mem_read(address, ins_size))
            ins = next(md.disasm(insn_bytes, address), None)
        except Exception:
            return
        if ins is None or ins.mnemonic.lower() not in cmp_mnems:
            return
        ops = []
        for op in ins.operands:
            ty = getattr(op, "type", None)
            try:
                if ty == reg_ty:
                    name = ins.reg_name(op.reg)
                    if name:
                        v = uc_.reg_read(SESSION.reg_const(name))
                        ops.append({"kind": "reg", "name": name, "value": hex(v)})
                elif ty == imm_ty:
                    ops.append({"kind": "imm",
                                "value": hex(op.imm & 0xFFFFFFFFFFFFFFFF)})
            except Exception:
                pass
        events.append({"pc": hex(address), "insn": f"{ins.mnemonic} {ins.op_str}",
                       "operands": ops})

    h = uc.hook_add(UC_HOOK_CODE, code_cb, begin=begin,
                    end=until if until else begin + 0x1_000_000)
    err = None
    try:
        uc.emu_start(begin, until, timeout=timeout_us)
    except unicorn.UcError as e:
        err = str(e)
    finally:
        uc.hook_del(h)
    return {"ok": err is None, "error": err,
            "compares_logged": len(events), "events": events}


@mcp.tool()
def analyze_input_handling(start: int, end: int,
                           input_address: int = 0, input_size: int = 0,
                           seed_hex: str = "",
                           include_strings_in_code: bool = True) -> dict:
    """One-shot structural cheat sheet for Claude.

    Combines: disassembly listing + immediates in compares + ASCII strings
    in the code region + (if input_address provided) dynamic input access
    pattern + dynamic compare log. Read this once, then design seeds.
    """
    out: dict[str, Any] = {"ok": True, "range": [hex(start), hex(end)]}
    try:
        out["disasm"] = disasm(start, count=min(256, (end - start) // 4))["instructions"]
    except Exception as e:
        out["disasm_error"] = str(e)
    out["immediates"] = find_immediates(start, end, only_compares=True)
    if include_strings_in_code:
        out["strings_in_code"] = find_strings(start, end - start, min_len=4)
    if input_address and input_size:
        out["input_access"] = probe_input_access(
            input_address=input_address, input_size=input_size,
            begin=start, until=end, seed_hex=seed_hex)
        out["compare_log"] = probe_compare_log(
            begin=start, until=end, seed_hex=seed_hex,
            input_address=input_address, input_size=input_size)
    return out


# ---------- (2) Seed enrichment ---------- #

@mcp.tool()
def seed_describe(limit: int = 100, head_bytes: int = 32) -> dict:
    """List all seeds currently in work/in/ with size + ASCII preview, so
    Claude can see what's already there and decide what's missing.
    """
    in_dir = WORK_DIR / "in"
    if not in_dir.is_dir():
        return _err("no corpus dir yet")
    out = []
    for f in sorted(in_dir.iterdir()):
        if not f.is_file(): continue
        data = f.read_bytes()
        head = data[:head_bytes]
        out.append({
            "name": f.name, "size": len(data),
            "head_hex": head.hex(),
            "head_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in head),
        })
        if len(out) >= limit: break
    return {"ok": True, "count": len(out), "corpus": str(in_dir), "seeds": out}


@mcp.tool()
def seed_add_many(seeds: list[dict], target: str = "corpus",
                  job_id: str = "") -> dict:
    """Add a batch of seeds from a list of {"name": str, "hex": str}.

    Args:
        target: Either 'corpus' (write to work/in/, only effective before
            fuzz_start) or 'inject' (write to the live AFL foreign-sync dir
            so a running campaign picks them up immediately).
        job_id: When target='inject', which job's inject dir to use
            (empty = most recent).
    """
    if target not in ("corpus", "inject"):
        return _err("target must be 'corpus' or 'inject'")
    if target == "corpus":
        dst = WORK_DIR / "in"; dst.mkdir(parents=True, exist_ok=True)
    else:
        job = SESSION.jobs.get(job_id) if job_id else \
              next(iter(SESSION.jobs.values()), None)
        if job is None:
            return _err("no fuzz job — start one first or use target='corpus'")
        dst = job.inject_dir
    written = []
    for s in seeds:
        name = s.get("name") or f"seed_{uuid.uuid4().hex[:8]}"
        data = bytes.fromhex(re.sub(r"\s+", "", s["hex"]))
        p = dst / name
        p.write_bytes(data)
        written.append({"name": name, "size": len(data), "path": str(p)})
    return _ok(f"wrote {len(written)} seeds to {target}", seeds=written, dir=str(dst))


@mcp.tool()
def template_seeds(prefix_hex: str = "", suffix_hex: str = "",
                   body_min: int = 0, body_max: int = 64,
                   body_kinds: list[str] | None = None,
                   count: int = 20, name_prefix: str = "tpl",
                   target: str = "corpus", job_id: str = "") -> dict:
    """Generate seeds of form prefix_hex + body + suffix_hex.

    body_kinds chooses how each body is filled:
        'random' — random bytes
        'zero'   — all 0x00
        'ones'   — all 0xff
        'ascii'  — random printable ascii
        'incr'   — incrementing 0x00, 0x01, 0x02...

    Useful right after Claude identifies a magic prefix from find_immediates.
    """
    body_kinds = body_kinds or ["random", "zero", "ones", "ascii", "incr"]
    valid = {"random", "zero", "ones", "ascii", "incr"}
    if any(k not in valid for k in body_kinds):
        return _err(f"body_kinds must be subset of {valid}")
    pre = bytes.fromhex(re.sub(r"\s+", "", prefix_hex))
    suf = bytes.fromhex(re.sub(r"\s+", "", suffix_hex))
    rng = random.Random(0xCAFEB10B)
    seeds = []
    for i in range(count):
        kind = body_kinds[i % len(body_kinds)]
        sz = rng.randint(body_min, body_max)
        if kind == "random":
            body = bytes(rng.randint(0, 255) for _ in range(sz))
        elif kind == "zero":
            body = b"\x00" * sz
        elif kind == "ones":
            body = b"\xff" * sz
        elif kind == "ascii":
            body = bytes(rng.choice(b" !\"#$%&'()*+,-./0123456789:;<=>?@"
                                   b"ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
                                   b"abcdefghijklmnopqrstuvwxyz{|}~")
                         for _ in range(sz))
        elif kind == "incr":
            body = bytes((j & 0xff) for j in range(sz))
        else:
            body = b""
        seeds.append({"name": f"{name_prefix}_{i:03d}_{kind}",
                      "hex": (pre + body + suf).hex()})
    return seed_add_many(seeds, target=target, job_id=job_id)


@mcp.tool()
def seeds_from_struct_spec(spec: dict, count: int = 32,
                           target: str = "corpus", job_id: str = "",
                           name_prefix: str = "spec") -> dict:
    """Generate seeds from a structured field specification — the natural
    bridge from IDA-derived (or hand-written) struct layouts into the corpus.

    Each field can be a fixed value, a list of candidate values, or random.
    The tool computes the Cartesian product of all explicit-value lists and
    emits up to `count` seeds; if the product is smaller than `count`, the
    remainder is filled by randomizing the choice independently per seed.

    spec format:
        {
          "size": 32,                          # base payload size (fields can extend)
          "seed": 0xCAFEB10B,                  # optional RNG seed
          "fields": [
            {"offset": 0,  "kind": "u32_le", "value":  0xAB7EC0DE},
            {"offset": 4,  "kind": "u8",     "values": [0, 1, 2, 0xFF]},
            {"offset": 8,  "kind": "u32_le", "values": [0, 0xFF, 0x10000]},
            {"offset": 12, "kind": "bytes_random", "size": 20}
          ]
        }

    Field kinds:
        Integers (omit value/values to randomize):
            u8 i8  u16_le u16_be i16_le i16_be
            u32_le u32_be i32_le i32_be
            u64_le u64_be i64_le i64_be
        bytes_literal (hex="DEADBEEF" or values=["aa..","bb.."])
        bytes_random  (size=N)              random bytes per seed
        bytes_zero    (size=N)
        bytes_repeat  (size=N, byte=0x41)

    target: 'corpus' (work/in/) or 'inject' (live AFL foreign-sync dir).
    """
    if not isinstance(spec, dict):
        return _err("spec must be a dict")
    fields = spec.get("fields", [])
    if not fields:
        return _err("spec.fields is required and non-empty")
    base_size = int(spec.get("size", 0))
    rng = random.Random(int(spec.get("seed", 0xCAFEB10B)))

    # Normalize each field into (offset, kind, candidates_or_None, extra)
    normalized: list[tuple[int, str, Any, dict]] = []
    for f in fields:
        if "offset" not in f or "kind" not in f:
            return _err(f"field missing offset/kind: {f}")
        off, k = int(f["offset"]), str(f["kind"])
        if k in _INT_FMTS:
            cands: Any
            if "value" in f:
                cands = [int(f["value"])]
            elif "values" in f:
                cands = [int(v) for v in f["values"]]
            else:
                cands = None  # randomize
            normalized.append((off, k, cands, {}))
        elif k == "bytes_literal":
            if "values" in f:
                lits = [bytes.fromhex(re.sub(r"\s+", "", str(v))) for v in f["values"]]
            elif "hex" in f:
                lits = [bytes.fromhex(re.sub(r"\s+", "", f["hex"]))]
            else:
                return _err(f"bytes_literal needs hex or values: {f}")
            normalized.append((off, k, lits, {}))
        elif k in ("bytes_random", "bytes_zero", "bytes_repeat"):
            normalized.append((off, k, None,
                               {"size": int(f.get("size", 0)),
                                "byte": int(f.get("byte", 0x41))}))
        else:
            return _err(f"unknown field kind: {k!r}")

    # Compute total payload size (max of explicit size + furthest field)
    total = base_size
    for off, k, cands, extra in normalized:
        if k in _INT_FMTS:
            end = off + struct.calcsize(_INT_FMTS[k])
        elif k == "bytes_literal":
            end = off + max(len(c) for c in cands)
        else:
            end = off + extra["size"]
        if end > total:
            total = end
    if total <= 0:
        return _err("computed payload size is 0 — fields produce no bytes")

    # Build candidate axes for the cross-product
    axes = [c if c is not None else [None] for (_, _, c, _) in normalized]
    combos = list(itertools.islice(itertools.product(*axes), count))
    while len(combos) < count:
        combos.append(tuple(rng.choice(a) if a != [None] else None for a in axes))

    # Emit seeds
    out_seeds = []
    for i, combo in enumerate(combos):
        buf = bytearray(total)
        for ((off, k, _, extra), v) in zip(normalized, combo):
            if k in _INT_FMTS:
                fmt = _INT_FMTS[k]
                width = struct.calcsize(fmt)
                if v is None:
                    buf[off:off+width] = bytes(rng.randint(0, 255) for _ in range(width))
                else:
                    if k.startswith("u"):
                        v_packed = v & ((1 << (width * 8)) - 1)
                    else:
                        v_packed = v
                    try:
                        buf[off:off+width] = struct.pack(fmt, v_packed)
                    except struct.error as e:
                        return _err(f"pack {k}={v} failed: {e}")
            elif k == "bytes_literal":
                data = v if isinstance(v, (bytes, bytearray)) else b""
                buf[off:off+len(data)] = data
            elif k == "bytes_random":
                sz = extra["size"]
                buf[off:off+sz] = bytes(rng.randint(0, 255) for _ in range(sz))
            elif k == "bytes_zero":
                pass  # already zero
            elif k == "bytes_repeat":
                sz, byte = extra["size"], extra["byte"]
                buf[off:off+sz] = bytes([byte & 0xFF]) * sz
        out_seeds.append({"name": f"{name_prefix}_{i:04d}",
                          "hex": bytes(buf).hex()})

    return seed_add_many(out_seeds, target=target, job_id=job_id)


# ---------- (3) Coverage plateau / live injection ---------- #

def _read_plot_data(job: FuzzJob) -> tuple[list[str], list[list[str]]]:
    """Parse out/default/plot_data into (header_fields, rows)."""
    plot = job.output_dir / "default" / "plot_data"
    if not plot.exists():
        return [], []
    text = plot.read_text()
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines: return [], []
    header = []
    rows = []
    for ln in lines:
        if ln.startswith("#"):
            header = [h.strip() for h in ln.lstrip("#").split(",")]
            continue
        rows.append([c.strip() for c in ln.split(",")])
    return header, rows


@mcp.tool()
def fuzz_coverage_history(job_id: str = "", points: int = 20) -> dict:
    """Return the coverage time-series for a job by sampling AFL's plot_data.

    Useful for detecting plateaus: if the trailing edges_found / paths_total
    is flat for a while, the fuzzer is stuck.
    """
    job = SESSION.jobs.get(job_id) if job_id \
          else next(iter(SESSION.jobs.values()), None)
    if job is None: return _err("no fuzz job")
    header, rows = _read_plot_data(job)
    if not rows: return {"ok": True, "samples": [], "note": "plot_data not yet written"}
    # downsample to 'points' rows
    step = max(1, len(rows) // points)
    sampled = rows[::step][-points:]
    samples = [dict(zip(header, r)) for r in sampled]
    return {"ok": True, "header": header, "samples": samples,
            "total_rows": len(rows)}


@mcp.tool()
def fuzz_plateau_check(job_id: str = "", threshold_sec: int = 600) -> dict:
    """Has new coverage stopped landing for at least `threshold_sec` seconds?

    Returns plateau=True if so — that's Claude's cue to inspect the target,
    propose a structurally-novel seed, and call seed_add_many(target='inject').
    """
    job = SESSION.jobs.get(job_id) if job_id \
          else next(iter(SESSION.jobs.values()), None)
    if job is None: return _err("no fuzz job")
    # Cheapest signal: fuzzer_stats has last_find / last_path / last_update.
    stats_path = job.output_dir / "default" / "fuzzer_stats"
    if not stats_path.exists():
        return {"ok": True, "plateau": False, "note": "fuzzer_stats missing yet"}
    stats: dict[str, str] = {}
    for ln in stats_path.read_text().splitlines():
        if ":" in ln:
            k, v = ln.split(":", 1)
            stats[k.strip()] = v.strip()
    now = time.time()
    last_find = None
    for k in ("last_find", "last_path", "last_update"):
        if k in stats:
            try:
                last_find = int(stats[k]); break
            except ValueError:
                pass
    if last_find is None:
        return {"ok": True, "plateau": False, "note": "no last_find timestamp"}
    silence_sec = max(0, int(now - last_find))
    return {"ok": True, "plateau": silence_sec >= threshold_sec,
            "silence_sec": silence_sec, "threshold_sec": threshold_sec,
            "fuzzer_stats_excerpt": {k: stats.get(k) for k in (
                "execs_per_sec", "edges_found", "corpus_count",
                "saved_crashes", "last_find", "cycles_done")}}


@mcp.tool()
def fuzz_inject_seed(hex_data: str, name: str = "", job_id: str = "") -> dict:
    """Drop a single seed into the running fuzzer's foreign-sync dir.

    AFL++ is started with `-F <inject_dir>` in fuzz_start, so anything we
    write there is automatically synced into the live queue without
    restarting the campaign. Use this from the plateau-breaker loop.
    """
    return seed_add_many(
        [{"name": name or f"inj_{uuid.uuid4().hex[:8]}", "hex": hex_data}],
        target="inject", job_id=job_id,
    )


@mcp.tool()
def fuzz_break_plateau(job_id: str = "",
                       code_start: int = 0, code_end: int = 0,
                       offsets: list[int] | None = None,
                       count: int = 24,
                       strategies: list[str] | None = None,
                       seed: int = 0xCAFEB10B) -> dict:
    """Mechanically break a coverage plateau by injecting *structurally-aware*
    seeds that AFL++'s built-in mutators won't naturally try.

    AFL++ already does random bit-flips, arithmetic, and havoc — that's why
    plateau happened. This tool does what AFL can't, because it requires
    knowledge of the target's code:

        magic_overlay   Extract immediates from [code_start, code_end] via
                        find_immediates, then overlay each (u32-LE / u64-LE)
                        at common header-field offsets of random corpus seeds.
                        This is the single biggest plateau-breaker for parsers
                        with magic-byte gates.
        length_probe    Write boundary length values (0, 1, 0xFF, 0x100, 0xFFF,
                        0x1000, 0x7FFF, 0x8000, 0xFFFF, 0x10000) at typical
                        length-field offsets (4, 6, 8) of corpus seeds.
        splice          Concatenate halves of two random corpus seeds —
                        AFL++ has its own splice but only between favorites,
                        and only after long stalls.

    Generated seeds are written into the live AFL inject directory, so a
    running campaign picks them up via foreign-sync without restart.

    Args:
        job_id: Fuzz job to inject into. Empty = most recent.
        code_start/code_end: Range to scan for immediates. If both 0,
            magic_overlay is skipped (still useful as a length+splice tool).
        offsets: Byte offsets at which to overlay magics. Default: typical
            header field positions [0, 4, 8, 12, 16, 24, 32].
        count: Approximate total seeds to generate (split across strategies).
        strategies: Subset of {'magic_overlay', 'length_probe', 'splice'}.
            Default: all three.
        seed: RNG seed for reproducibility.
    """
    job = SESSION.jobs.get(job_id) if job_id \
          else next(iter(SESSION.jobs.values()), None)
    if job is None: return _err("no fuzz job — start one first")
    in_dir = WORK_DIR / "in"
    if not in_dir.is_dir() or not any(in_dir.iterdir()):
        return _err("corpus is empty — nothing to base mutations on")

    strategies = strategies or ["magic_overlay", "length_probe", "splice"]
    offsets = offsets or [0, 4, 8, 12, 16, 24, 32]
    rng = random.Random(seed)

    # Snapshot the current corpus once
    corpus_files = [p for p in sorted(in_dir.iterdir()) if p.is_file()]
    corpus = [(p.name, p.read_bytes()) for p in corpus_files]

    generated: list[tuple[str, bytes]] = []   # (name, payload)
    notes: list[str] = []

    # ---------- magic_overlay ----------
    if "magic_overlay" in strategies:
        if code_start and code_end and code_start < code_end:
            # Pull immediates: scan compares first (high signal),
            # then mov-style for completeness if too few found.
            try:
                imm_cmp = find_immediates(code_start, code_end, only_compares=True,
                                          min_value=0)
                imm_all = find_immediates(code_start, code_end, only_compares=False,
                                          min_value=0x100)
            except Exception as e:
                return _err(f"find_immediates failed: {e}")
            uniq = []
            seen = set()
            for evt in (imm_cmp.get("events", []) + imm_all.get("events", [])):
                v = evt["value"]
                if v in seen: continue
                seen.add(v); uniq.append(v)
            uniq = uniq[:32]   # cap to keep seed count sane
            notes.append(f"magic_overlay: {len(uniq)} unique immediates "
                         f"in [{hex(code_start)}, {hex(code_end)})")
            target_count = max(1, count // len(strategies))
            i = 0
            while i < target_count and uniq:
                base_name, base = corpus[rng.randrange(len(corpus))]
                value = uniq[i % len(uniq)]
                offset = offsets[(i // max(1, len(uniq))) % len(offsets)]
                # Pick width based on magnitude
                if value <= 0xFFFFFFFF:
                    enc = struct.pack("<I", value & 0xFFFFFFFF)
                else:
                    enc = struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)
                if offset + len(enc) > len(base):
                    pad = (offset + len(enc)) - len(base)
                    payload = bytes(base) + b"\x00" * pad
                else:
                    payload = bytearray(base); payload[offset:offset+len(enc)] = enc
                    payload = bytes(payload)
                payload = payload[:offset] + enc + payload[offset+len(enc):]
                name = f"plat_magic_{i:03d}_{value:#x}_off{offset}"
                generated.append((name, payload))
                i += 1
        else:
            notes.append("magic_overlay: skipped (code_start/code_end not provided)")

    # ---------- length_probe ----------
    if "length_probe" in strategies:
        boundaries = [0, 1, 0xFF, 0x100, 0xFFF, 0x1000,
                      0x7FFF, 0x8000, 0xFFFE, 0xFFFF, 0x10000, 0xFFFFFFFF]
        len_offsets = [4, 6, 8, 12, 16]
        target_count = max(1, count // len(strategies))
        for i in range(target_count):
            base_name, base = corpus[rng.randrange(len(corpus))]
            v = boundaries[i % len(boundaries)]
            off = len_offsets[(i // len(boundaries)) % len(len_offsets)]
            enc = struct.pack("<I", v & 0xFFFFFFFF)
            if off + 4 > len(base):
                payload = bytes(base) + b"\x00" * (off + 4 - len(base))
                payload = payload[:off] + enc + payload[off+4:]
            else:
                payload = bytes(base[:off]) + enc + bytes(base[off+4:])
            name = f"plat_len_{i:03d}_v{v:#x}_off{off}"
            generated.append((name, payload))
        notes.append(f"length_probe: {target_count} seeds with boundary lengths")

    # ---------- splice ----------
    if "splice" in strategies and len(corpus) >= 2:
        target_count = max(1, count // len(strategies))
        for i in range(target_count):
            a_name, a = corpus[rng.randrange(len(corpus))]
            b_name, b = corpus[rng.randrange(len(corpus))]
            if not a or not b: continue
            cut_a = rng.randrange(1, len(a)) if len(a) > 1 else 1
            cut_b = rng.randrange(0, len(b))
            payload = bytes(a[:cut_a]) + bytes(b[cut_b:])
            name = f"plat_splice_{i:03d}_{a_name[:8]}_{b_name[:8]}"
            generated.append((name, payload))
        notes.append(f"splice: {target_count} seeds")
    elif "splice" in strategies:
        notes.append("splice: skipped (need >=2 corpus seeds)")

    # ---------- inject ----------
    written = []
    for name, payload in generated:
        # cap payload size to a sensible max (matches typical fuzz_configure)
        payload = payload[:8192]
        p = job.inject_dir / name
        p.write_bytes(payload)
        written.append({"name": name, "size": len(payload)})

    return {"ok": True,
            "job_id": job.job_id,
            "inject_dir": str(job.inject_dir),
            "injected": len(written),
            "strategies_used": strategies,
            "notes": notes,
            "samples": written[:10]}


@mcp.tool()
def fuzzing_advisor(job_id: str = "") -> dict:
    """Single dashboard call returning everything Claude needs to decide what
    to do next: live status, plateau verdict, coverage trend tail, last few
    crashes, current corpus summary.
    """
    job = SESSION.jobs.get(job_id) if job_id \
          else next(iter(SESSION.jobs.values()), None)
    advice: dict[str, Any] = {"ok": True}
    if job is None:
        advice["status"] = "no_job"
        advice["next_action"] = "start a fuzz job with fuzz_start, or call analyze_input_handling first"
        return advice
    advice["job"] = fuzz_status(job_id=job.job_id)
    advice["plateau"] = fuzz_plateau_check(job_id=job.job_id)
    advice["coverage_tail"] = fuzz_coverage_history(job_id=job.job_id, points=10)
    advice["recent_crashes"] = fuzz_list_crashes(job_id=job.job_id)
    advice["corpus"] = seed_describe(limit=20)
    # Heuristic recommendation
    if advice["plateau"].get("plateau"):
        advice["next_action"] = (
            "PLATEAU detected. Two options:\n"
            "  (1) FAST/AUTOMATED: call fuzz_break_plateau(job_id=..., "
            "code_start=<parser_start>, code_end=<parser_end>) — overlays "
            "magics from disasm + length boundaries + splice. Mechanical, "
            "works without further reasoning.\n"
            "  (2) DEEPER/REASONED: re-read disasm via analyze_input_handling "
            "around uncovered branches, hand-craft 5–10 structurally-novel "
            "seeds, then seed_add_many(seeds=[...], target='inject', "
            "job_id=...).\n"
            "Try (1) first; if coverage still flat after a minute, do (2).")
    elif advice["recent_crashes"].get("crashes"):
        advice["next_action"] = (
            "Crashes present. Run crash_summarize on each, then crash_minimize "
            "the unique ones.")
    else:
        advice["next_action"] = "Fuzzer is making progress — let it run."
    return advice


# ---------- (4) Crash analysis / minimization ---------- #

_UC_ERR_RE = re.compile(r"\[replay\] UcError: (.+)")

@mcp.tool()
def crash_summarize(crash_path: str, timeout_sec: int = 30) -> dict:
    """Replay a crash input through the harness and produce a structured
    summary: classification, final PC, register dump.
    """
    rep = fuzz_replay_crash(crash_path=crash_path, timeout_sec=timeout_sec)
    stdout = rep.get("stdout", "") or ""
    stderr = rep.get("stderr", "") or ""
    blob = stdout + "\n" + stderr
    m = _UC_ERR_RE.search(blob)
    error = m.group(1).strip() if m else None
    # Try to lift the register-dump dict that pprint'd in the harness
    regs: dict[str, str] = {}
    in_dump = False
    for line in stdout.splitlines():
        s = line.strip()
        if s.startswith("{") and ":" in s:
            in_dump = True
        if in_dump:
            for piece in re.findall(r"'(\w+)':\s*'(0x[0-9a-fA-F]+)'", s):
                regs[piece[0]] = piece[1]
            if s.endswith("}"):
                in_dump = False
    classification = "no_crash"
    if error:
        e = error.lower()
        if "unmapped" in e and "fetch" in e:    classification = "exec_unmapped"
        elif "unmapped" in e and "read" in e:   classification = "read_unmapped"
        elif "unmapped" in e and "write" in e:  classification = "write_unmapped"
        elif "exception" in e:                  classification = "cpu_exception"
        elif "fetch" in e:                      classification = "fetch_fault"
        else:                                   classification = "other"
    return {"ok": True,
            "crash_path": crash_path,
            "size": Path(crash_path).stat().st_size if Path(crash_path).is_file() else None,
            "classification": classification,
            "error": error,
            "registers": regs,
            "stdout_tail": stdout[-2000:],
            "stderr_tail": stderr[-2000:]}


@mcp.tool()
def crash_minimize(crash_path: str, output_path: str = "",
                   timeout_sec: int = 60) -> dict:
    """Run afl-tmin on a crash input to shrink it to a minimal reproducer."""
    afl_tmin = shutil.which("afl-tmin")
    if afl_tmin is None:
        return _err("afl-tmin not in PATH")
    if not Path(crash_path).is_file():
        return _err(f"crash not found: {crash_path}")
    out = output_path or str(WORK_DIR / "min" / Path(crash_path).name)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    harness = WORK_DIR / "harness.py"
    if not harness.exists():
        return _err("no harness — call fuzz_generate_harness first")
    cmd = [afl_tmin, "-U", "-i", crash_path, "-o", out, "--",
           sys.executable, str(harness), "@@"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
    return {"ok": proc.returncode == 0, "returncode": proc.returncode,
            "minimized_to": out if Path(out).exists() else None,
            "stdout": proc.stdout[-4000:], "stderr": proc.stderr[-4000:]}


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    mcp.run()

#!/usr/bin/env python3
"""Auto-generated unicornafl harness.

This file is overwritten by the MCP server every time `fuzz_generate_harness`
is called. Do not edit directly — change the session state and regenerate.

Entry points:
    afl-fuzz -U ... -- python harness.py            # fuzzing (input via SHM)
    python harness.py /path/to/input                # standalone test
    python harness.py /path/to/input --replay       # replay (verbose, dumps regs)
"""
from __future__ import annotations
import json, os, sys, traceback
from pathlib import Path

SNAPSHOT_DIR = Path(r"__SNAPSHOT_DIR__")

import unicorn
from unicorn import Uc, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_PROT_ALL
import unicornafl

_PERM_MAP = {"r": UC_PROT_READ, "w": UC_PROT_WRITE, "x": UC_PROT_EXEC}

_ARCH_TABLE = {
    "arm64":  (unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM),
    "arm":    (unicorn.UC_ARCH_ARM,   unicorn.UC_MODE_ARM),
    "x86_64": (unicorn.UC_ARCH_X86,   unicorn.UC_MODE_64),
    "x86":    (unicorn.UC_ARCH_X86,   unicorn.UC_MODE_32),
    "mips":   (unicorn.UC_ARCH_MIPS,  unicorn.UC_MODE_MIPS32),
}

def _reg_const(arch: str, name: str) -> int:
    from unicorn import arm64_const, arm_const, x86_const, mips_const
    mods = {"arm64": (arm64_const, "UC_ARM64_REG_"),
            "arm":   (arm_const,   "UC_ARM_REG_"),
            "x86":   (x86_const,   "UC_X86_REG_"),
            "x86_64":(x86_const,   "UC_X86_REG_"),
            "mips":  (mips_const,  "UC_MIPS_REG_")}
    mod, prefix = mods[arch]
    return getattr(mod, prefix + name.upper())

def _parse_perms(s: str) -> int:
    out = 0
    for ch in s.lower():
        if ch == "-": continue
        out |= _PERM_MAP.get(ch, 0)
    return out or UC_PROT_ALL


def build_uc():
    meta = json.loads((SNAPSHOT_DIR / "meta.json").read_text())
    uc_arch, uc_mode = _ARCH_TABLE[meta["arch"]]
    if meta.get("mode_name") == "thumb":
        uc_mode = unicorn.UC_MODE_THUMB
    uc = Uc(uc_arch, uc_mode)
    for r in meta["regions"]:
        uc.mem_map(r["address"], r["size"], _parse_perms(r["perms"]))
        uc.mem_write(r["address"], Path(r["file"]).read_bytes())
    for n, v in meta["regs"].items():
        try: uc.reg_write(_reg_const(meta["arch"], n), v)
        except Exception: pass
    return uc, meta


def _is_replay() -> bool:
    return "--replay" in sys.argv


def main():
    uc, meta = build_uc()
    arch = meta["arch"]
    fi = meta["fuzz_input"]
    if fi is None:
        print("[harness] fuzz_input not configured", file=sys.stderr)
        sys.exit(2)
    exits = meta["exits"]
    persistent_iters = meta.get("persistent_iters", 1)

    # We want the harness to start fresh on every iteration. Snapshot regs +
    # the contents of writable regions once, and restore them inside the
    # place_input callback.
    saved_regs = {}
    for n in meta["regs"]:
        try: saved_regs[n] = uc.reg_read(_reg_const(arch, n))
        except Exception: pass
    saved_writable: list[tuple[int, bytes]] = []
    for r in meta["regions"]:
        if "w" in r["perms"]:
            saved_writable.append((r["address"], bytes(uc.mem_read(r["address"], r["size"]))))

    def restore_state():
        for addr, data in saved_writable:
            uc.mem_write(addr, data)
        for n, v in saved_regs.items():
            try: uc.reg_write(_reg_const(arch, n), v)
            except Exception: pass

    def place_input(uc_, inp, persistent_round, _data):
        if len(inp) < fi["min_size"] or len(inp) > fi["max_size"]:
            return False
        if persistent_round > 0:
            restore_state()
        if fi["kind"] == "memory":
            uc_.mem_write(fi["address"], bytes(inp))
        else:  # register
            byteorder = "little" if fi["little_endian"] else "big"
            value = int.from_bytes(bytes(inp), byteorder=byteorder)
            uc_.reg_write(_reg_const(arch, fi["register"]), value)
        return True

    # ---------- standalone replay ---------- #
    if _is_replay() and len(sys.argv) >= 2 and sys.argv[1] not in ("-",):
        crash_input = Path(sys.argv[1]).read_bytes()
        print(f"[replay] input size = {len(crash_input)}")
        if not place_input(uc, crash_input, 0, None):
            print("[replay] place_input rejected the input"); sys.exit(2)
        # Pick a sane PC if exit is the only signal
        try:
            uc.emu_start(uc.reg_read(_reg_const(arch, "pc" if arch in ("arm64","arm","mips") else "rip" if arch=="x86_64" else "eip")),
                         until=exits[0] if exits else 0,
                         timeout=5_000_000, count=0)
            print("[replay] emulation finished cleanly")
            rc = 0
        except unicorn.UcError as e:
            print(f"[replay] UcError: {e}")
            rc = 1
        # Dump a few key regs
        try:
            from pprint import pprint
            dump = {}
            for n in saved_regs:
                try: dump[n] = hex(uc.reg_read(_reg_const(arch, n)))
                except Exception: pass
            pprint(dump)
        except Exception:
            pass
        sys.exit(rc)

    # ---------- fuzz / standalone ---------- #
    input_file = sys.argv[1] if len(sys.argv) >= 2 else None
    try:
        unicornafl.uc_afl_fuzz(
            uc=uc,
            input_file=input_file,
            place_input_callback=place_input,
            exits=exits,
            persistent_iters=persistent_iters,
        )
    except unicornafl.UcAflError as e:
        # NO_AFL is normal in standalone mode
        if hasattr(e, "errno") and e.errno == unicornafl.UC_AFL_RET_NO_AFL:
            print("[harness] NO_AFL (standalone mode finished)")
            return
        print(f"[harness] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException:
        traceback.print_exc()
        sys.exit(2)

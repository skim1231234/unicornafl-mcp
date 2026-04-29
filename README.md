# unicornafl-mcp

> **An MCP server that turns Claude Desktop into a hands-on driver for Unicorn emulation and AFL++ fuzzing of binaries — with LLM-guided seed enrichment and coverage-plateau breaking adapted from ChatAFL (NDSS '24).**

[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)]()
[![Platform](https://img.shields.io/badge/platform-macOS%20arm64%20%7C%20Linux-444444?logo=apple&logoColor=white)]()
[![MCP](https://img.shields.io/badge/protocol-MCP-A259FF)]()
[![AFL++](https://img.shields.io/badge/fuzzer-AFL%2B%2B-FF5500)]()
[![Unicorn](https://img.shields.io/badge/emulator-Unicorn-FF1493)]()
[![Tools](https://img.shields.io/badge/tools-46-007ACC)]()
[![License](https://img.shields.io/badge/license-MIT-2EA44F)]()

---

## ✨ What it does

Talk to Claude in chat, and from the same conversation:

- 🎮 **Emulate** — Step ARM64 / x86_64 / ARM / x86 / MIPS binaries through Unicorn interactively
- 🔬 **Analyze** — Disassemble, extract magic constants, scan strings, dynamically trace input reads & comparisons to infer parser structure
- 🌱 **Generate seeds** — Have Claude design seeds from inferred structure (magic bytes, length fields, dispatcher gmids…) and inject them at any time
- 🐝 **Fuzz** — Spawn AFL++ `unicorn-mode` campaigns; poll `fuzzer_stats` and `plot_data`
- 📈 **Break plateaus** — Detect coverage stalls and *hot-inject* new seeds via AFL's `-F` foreign-sync directory — no campaign restart
- 🔥 **Triage crashes** — Auto-classify (`exec_unmapped`, `read_unmapped`, `cpu_exception`, …) and minimize with `afl-tmin`

> [!IMPORTANT]
> **The differentiator: no external LLM API calls.** Claude itself does the reasoning, so the MCP only has to expose *clean signals* and accept *structured seed proposals*. The bidirectional loop happens naturally inside the chat.

---

## 🚀 Quick start

### TL;DR — three steps

```bash
git clone https://github.com/skim1231234/unicornafl-mcp
cd unicornafl-mcp && ./setup.sh        # builds everything + auto-registers in Claude Desktop
# fully quit and relaunch Claude Desktop  ← only manual step
```

> [!IMPORTANT]
> Fully quit and relaunch Claude Desktop after `setup.sh` finishes — it's the only manual step.

That's it. `setup.sh` builds AFL++/Rust/unicornafl/venv **and** patches Claude Desktop's `claude_desktop_config.json` for you (existing entries preserved, with a timestamped backup). Open Claude Desktop's tools panel and you should see 48 `unicornafl` tools.

### Requirements

- macOS arm64 (Apple Silicon) or Linux x86_64 — other platforms are untested
- Python ≥ 3.11
- Homebrew (macOS) or your distro's package manager
- git
- Claude Desktop

(Rust ≥ 1.87 and AFL++ are installed by `setup.sh` if missing.)

### What `setup.sh` does

1. Installs **AFL++** via Homebrew
2. Installs / updates the **Rust toolchain** (rustc ≥ 1.87)
3. Clones the **unicornafl** source into `./vendor/unicornafl/`
4. Builds the unicornafl wheel (`cargo build` + `maturin build`)
5. Creates `./.venv/` and installs `unicorn`, `unicornafl`, `mcp`, `capstone`
6. Runs an import smoke test
7. Writes a config snippet to `./claude_desktop_config.local.json` (with absolute paths)
8. **Merges that snippet into Claude Desktop's `claude_desktop_config.json`**, preserving any other `mcpServers` entries you already have, and saving a timestamped backup of the original

> [!TIP]
> Idempotent — re-run any time. See [External dependencies](#-external-dependencies) for what each piece is.

#### Flags & environment overrides

```bash
./setup.sh                               # default: prompt before patching Claude Desktop config
./setup.sh --yes                         # non-interactive (CI etc.)
./setup.sh --no-register                 # build only, leave Claude Desktop config alone

UNICORNAFL_SRC=$HOME/src/unicornafl ./setup.sh    # use an existing checkout
UNICORNAFL_REF=v3.0.0 ./setup.sh                  # pin upstream ref
PYTHON_BIN=python3.12 ./setup.sh                  # different interpreter
VENV_DIR=$HOME/.venvs/unicornafl-mcp ./setup.sh   # different venv location
CLAUDE_CONFIG=/custom/path/claude_desktop_config.json ./setup.sh   # see below
```

| Variable | Default | Purpose |
|---|---|---|
| `UNICORNAFL_SRC` | `./vendor/unicornafl` | Use an existing unicornafl checkout (skips clone) |
| `UNICORNAFL_REF` | `main` | git ref to clone (branch / tag / commit) |
| `PYTHON_BIN` | `python3.11` | Python interpreter to use for the venv |
| `VENV_DIR` | `./.venv` | Override venv location |
| `CLAUDE_CONFIG` | (auto, see below) | Path to Claude Desktop's `claude_desktop_config.json` |

#### Claude Desktop config path

`setup.sh` auto-detects the config path per OS:

| OS | Default config path |
|---|---|
| **macOS** | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Linux** | `~/.config/Claude/claude_desktop_config.json` |
| **Windows** | (not auto-detected — pass `CLAUDE_CONFIG` explicitly) |

> [!NOTE]
> The defaults match a standard install of Claude Desktop. **If your install has it somewhere else** — e.g. a portable install, a containerized launcher, an enterprise-managed home directory, or a different OS / desktop variant — the auto-detected path will be wrong. In that case override it:
>
> ```bash
> CLAUDE_CONFIG="$HOME/some/other/place/claude_desktop_config.json" ./setup.sh
> ```

To find out where Claude Desktop actually keeps its config on your machine:

- macOS: open Finder → ⌘⇧G → paste `~/Library/Application Support/Claude/`
- Linux: `find ~ -name claude_desktop_config.json 2>/dev/null`
- Windows: typically `%APPDATA%\Claude\claude_desktop_config.json`

> [!TIP]
> Before patching, `setup.sh` prints the path it's about to write to and waits for confirmation — abort with `n` and re-run with `CLAUDE_CONFIG=...` if the path is wrong.

### Manual registration (only if you ran `--no-register`)

`setup.sh` writes a fully-resolved config snippet to `./claude_desktop_config.local.json`. Merge its `mcpServers.unicornafl` block into your Claude Desktop config — see [Claude Desktop config path](#claude-desktop-config-path) above for typical locations and how to find yours if it differs.

The template form (with placeholders) is in [`claude_desktop_config.example.json`](claude_desktop_config.example.json):

```json
{
  "mcpServers": {
    "unicornafl": {
      "command": "/path/to/unicornafl-mcp/.venv/bin/python",
      "args": ["/path/to/unicornafl-mcp/server.py"],
      "env": { "PYTHONUNBUFFERED": "1" }
    }
  }
}
```

> [!IMPORTANT]
> Fully quit and relaunch Claude Desktop — all 48 tools should appear in the tools panel.

### Uninstall / unregister

Open Claude Desktop's `claude_desktop_config.json` and remove the `mcpServers.unicornafl` block (a backup made by `setup.sh` is alongside, named `claude_desktop_config.json.bak.<timestamp>`). Then `rm -rf` the cloned `unicornafl-mcp/` directory.

### 30-second smoke test

Drop this prompt into Claude:

> Make an arm64 session, map an r-x 4 KB region at 0x100000, write the bytes
> `40 00 80 52 1f a8 00 71 3f 6a 00 71 1f 00 1f 72 c0 03 5f d6` (mov w0,#2;
> cmp w0,#0x2a; cmp w17,#0x1a; tst w0,#2; ret), and run `find_immediates`
> over [0x100000, 0x100014).

You should see exactly three constants pulled out of the `cmp`/`tst` instructions: `0x2a`, `0x1a`, and `0x2`.

---

## 🛠️ Tool catalog (48 tools)

### Session / memory / registers

`session_init`, `session_status`, `session_reset` ·
`mem_map`, `mem_unmap`, `mem_write`, `mem_write_file`, `mem_read`, `mem_regions` ·
`reg_write`, `reg_read`, `reg_dump`

### Code loading / disassembly / hooks

`load_code`, `disasm` (capstone) ·
`hook_code`, `hook_mem`, `get_trace`, `remove_hook`

### Emulation / snapshots

`emu_start`, `emu_stop` ·
`snapshot_save`, `snapshot_load`, `snapshot_list`

### Fuzzing (basic)

`fuzz_configure` (input_kind = `memory` / `register`) · `fuzz_seed_corpus` · `fuzz_generate_harness` · `fuzz_test_harness` · `fuzz_start` (auto-adds `-F <inject_dir>`) · `fuzz_status` · `fuzz_stop` · `fuzz_list_crashes` · `fuzz_replay_crash`

### LLM-guided (★ ChatAFL adaptation)

| Phase | Tools |
|---|---|
| **Input-structure inference** (paper §IV-A) | `analyze_input_handling`, `find_immediates`, `find_strings`, `probe_input_access`, `probe_compare_log` |
| **Seed enrichment** (paper §IV-B) | `seed_describe`, `seed_add_many`, `template_seeds`, `seeds_from_struct_spec` ★ |
| **Coverage-plateau breaking** (paper §IV-C) | `fuzz_coverage_history`, `fuzz_plateau_check`, `fuzz_break_plateau` ★, `fuzz_inject_seed`, `fuzzing_advisor` |
| **Crash analysis** | `crash_summarize`, `crash_minimize` |

Tool signatures are documented in the Claude Desktop tool panel and in `server.py` docstrings.

---

## 🔄 LLM-guided workflow

```
                ┌──────────────────────────────────────────────┐
                │              MCP server (Python)             │
                │   Unicorn session   ·   AFL++ subprocess     │
                └──────────┬─────────────────────▲─────────────┘
                           │                     │
              clean signals│                     │ structured seeds
                           ▼                     │
                ┌──────────────────────────────────────────────┐
                │                   Claude                     │
                │      (in chat — no external LLM API)         │
                └──────────────────────────────────────────────┘
```

A typical cycle:

1. **Bootstrap**
   - `session_init('arm64')`, `mem_map`, load function code + an input buffer
   - `analyze_input_handling(start, end, input_address, input_size)` — combined disasm + immediates + strings + read access pattern + compare log
   - Claude reads the report and forms a structural hypothesis (e.g. *"12-byte header, magic 0xAB7EC0DE, 6-bit gid, then TLV payload"*)
2. **Enrich seeds**
   - `template_seeds(prefix_hex='<inferred header>', body_min, body_max, count)`, or
   - `seed_add_many([{name, hex}, …])` for hand-picked structured seeds
3. **Run the fuzzer**
   - `fuzz_generate_harness` → `fuzz_test_harness` to verify → `fuzz_start`
4. **Monitor / break plateaus** — every 30 s to a few minutes
   - `fuzzing_advisor(job_id)` — one call returns status + plateau verdict + coverage tail + crashes + a recommended next action
   - If `plateau == True`, two paths:
     - **Fast / mechanical** — `fuzz_break_plateau(job_id, code_start, code_end)` overlays disasm-derived magic constants at typical header offsets, probes length-field boundaries, and splices corpus pairs. Doesn't need Claude reasoning; runs in milliseconds.
     - **Deep / reasoned** — re-read disassembly around uncovered branches → `seed_add_many(target='inject', …)` for hand-crafted seeds. Use when (1) didn't help.
5. **Triage**
   - `crash_summarize` to bucket crashes → `crash_minimize` once per unique bucket

This mirrors the paper's Algorithm 1 (`PlateauLen ≥ MaxPlateau → ChatNextMessage`), with the external LLM call replaced by Claude inside the chat context.

---

## 🤝 Pairs well with: [IDA Pro MCP](https://github.com/mrexodia/ida-pro-mcp)

Plateau-breaking gets dramatically stronger when [`ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp) is registered alongside `unicornafl-mcp` in Claude Desktop. Both servers run independently — Claude orchestrates them in a single chat: IDA provides *structural ground truth*, unicornafl applies that knowledge to a live AFL campaign.

### What IDA unlocks (vs. raw memory analysis)

| Signal | `unicornafl-mcp` alone | `+ ida-pro-mcp` |
|---|---|---|
| Function boundaries | guess via `code_start` / `code_end` | `lookup_funcs` returns prologue–epilogue exactly |
| Magic constants | `find_immediates` over a memory range | `decompile` reveals `*(u32)msg == 0xAB7EC0DE`, plus xrefs to other parsers using the same magic |
| Input layout | inferred from dynamic read pattern | typed structs (if user has typed them in IDA) → exact field offsets / widths |
| Length field | guessed offsets `[4, 6, 8]` | `trace_data_flow` from a `memcpy` length argument back to input bytes |
| Untaken branches | not directly visible | AFL bitmap × `basic_blocks` CFG → exact `b.ne` instructions never flipped |
| Dispatch tables | not directly visible | `read_struct` over `g_DISPATCH[64]` → enumerates every valid `(gid, mid)` pair |

### Workflow

```
[plateau detected via fuzz_plateau_check]
  ↓
ida-pro-mcp__decompile(<parser_va>)             # readable pseudocode
ida-pro-mcp__list_globals(pattern=...)          # locate dispatch / msgdef tables
ida-pro-mcp__read_struct(addr, stride, ...)     # enumerate valid IDs / fields
ida-pro-mcp__xrefs_to(<parser_va>)              # find caller contexts
  ↓ (Claude reasons over the structural facts)
unicornafl-mcp__seeds_from_struct_spec(spec, target="inject", job_id=...)
  ↓
AFL picks them up via foreign-sync, plateau breaks
```

### Concrete example — protocol parser plateau

Scenario: a campaign against an `Extract` parser has stalled because mechanical magic overlays keep getting rejected at the dispatch gate (`gid` not in the dispatch table).

```python
# 1. IDA — enumerate every valid (gid, mid) pair from the dispatch table
ida__read_struct(addr=0x5BE05C8, stride=8, count=64)              # group pointers
for gp in active_groups:
    msgdefs = ida__read_struct(addr=gp, stride=56, terminator="mid==0")
    valid_pairs += [(gid, m.mid) for m in msgdefs]

# 2. unicornafl-mcp — one structurally-correct seed per pair
spec = {
  "size": 12,
  "fields": [
    {"offset": 0, "kind": "u32_le", "value":  0xAB7EC0DE},
    {"offset": 4, "kind": "u8",     "values": [g << 3 for g, _ in valid_pairs]},
    {"offset": 5, "kind": "u8",     "value":  0},
    {"offset": 6, "kind": "u16_le", "value":  0},
    {"offset": 8, "kind": "u16_le", "values": [m << 6 for _, m in valid_pairs]},
    {"offset": 10,"kind": "u16_le", "value":  0},
  ]
}
seeds_from_struct_spec(spec, count=200, target="inject", job_id=current_job)
```

Every emitted seed passes the magic + size + gid + msgdef + mid gates and lands inside the per-group native handler — exactly where the deeper, less-tested code lives. Tens-of-percent coverage gain in a single batch is normal for protocols with structured headers.

### Setup pointer

Install `ida-pro-mcp` per its [own README](https://github.com/mrexodia/ida-pro-mcp) and add it to Claude Desktop's `claude_desktop_config.json` alongside `unicornafl`:

```json
{
  "mcpServers": {
    "unicornafl": { "command": "...", "args": ["..."] },
    "ida":        { "command": "...", "args": ["..."] }
  }
}
```

Both servers operate independently — no code changes needed in `unicornafl-mcp`. Claude can call both in the same chat turn.

---

## 📁 Working directory layout

```
unicornafl-mcp/
├── setup.sh
├── server.py                          # MCP server (~1800 lines, 48 tools)
├── harness_template.py                # filled in by fuzz_generate_harness → work/harness.py
├── claude_desktop_config.example.json # template with /path/to/... placeholders
├── claude_desktop_config.local.json   # generated by setup.sh, real paths (gitignored)
├── vendor/
│   └── unicornafl/                    # auto-cloned by setup.sh (gitignored)
├── .venv/                             # Python venv (gitignored)
└── work/                              # runtime artifacts (gitignored)
    ├── snapshots/<name>/{meta.json, region_*.bin}
    ├── harness.py                     # overwritten on every fuzz_generate_harness
    ├── in/                            # AFL seed corpus
    ├── inject/<job_id>/               # AFL -F live-injection directory
    ├── out/                           # AFL output (out/default/{queue,crashes,fuzzer_stats,plot_data})
    └── fuzz_<job_id>.log
```

---

## 📦 External dependencies

unicornafl-mcp is a thin layer on top of three external projects. None of them are vendored into this repository — `setup.sh` fetches and builds them on first run.

### unicornafl  (separate upstream project)

[unicornafl](https://github.com/AFLplusplus/unicornafl) (AFL++ ↔ Unicorn bridge) is the central dependency. Its Python wheel doesn't ship on PyPI, so it has to be built from source.

| | |
|---|---|
| Upstream | `https://github.com/AFLplusplus/unicornafl` |
| Default install location | `./vendor/unicornafl/` (this repo, gitignored) |
| Override | `UNICORNAFL_SRC=/path/to/checkout ./setup.sh` |
| Build chain | Rust (`cargo build --release`) → Python wheel (`maturin build --release`) → `pip install` into `.venv` |
| Pinned ref | `main` by default; override with `UNICORNAFL_REF=v3.0.0 ./setup.sh` |

If you already maintain a unicornafl checkout elsewhere (e.g. for development), point at it via `UNICORNAFL_SRC` and `setup.sh` will skip the clone and build straight from there.

### AFL++

[AFL++](https://github.com/AFLplusplus/AFLplusplus) provides `afl-fuzz`, `afl-tmin`, and the unicorn-mode forkserver. Installed via Homebrew:

```bash
brew install afl++
```

`setup.sh` runs this automatically if `afl-fuzz` is not already on `$PATH`. On Linux you'll have to install it from source per the upstream instructions and re-run `./setup.sh` afterwards.

### Unicorn Engine

[Unicorn Engine](https://github.com/unicorn-engine/unicorn) is pulled in transitively through the `unicorn>=2.1.3` Python package (binary wheel on PyPI — no native build required). The `unicornafl` Python wheel dynamically links against the same `libunicorn.so` that the `unicorn` package ships.

### Other Python deps (PyPI)

Installed into the project venv by `setup.sh`:

- `mcp>=1.2.0` — Model Context Protocol Python SDK
- `capstone` — disassembler used by `disasm`, `find_immediates`, `probe_compare_log`
- `maturin>=1.8,<2.0` — used to build the unicornafl wheel
- `pydantic>=2` — transitive dependency of `mcp`

### What you need to install yourself

Only these prerequisites have to exist before running `setup.sh`:

| Tool | macOS install |
|---|---|
| Python ≥ 3.11 | `brew install python@3.11` |
| Homebrew | [brew.sh](https://brew.sh) |
| git | `xcode-select --install` |

Everything else (AFL++, Rust, unicornafl source, Python packages, venv) is handled by `setup.sh`.

---

## 🏗️ Architecture notes

- **The session is process-scoped.** Claude Desktop's stdio MCP serves a single client, so a global `SESSION` is sufficient.
- **Emulation is in-process** (Unicorn only); **fuzzing is out-of-process** — `fuzz_generate_harness` snapshots the live session to disk and emits a self-contained Python harness, which `afl-fuzz` then spawns.
- **Live seed injection** — `fuzz_start` automatically appends `-F WORK_DIR/inject/<job_id>` to the AFL command line. AFL++ watches that directory as a foreign queue, so anything dropped there by `fuzz_inject_seed` flows into the running queue without restart.
- **Stats are AFL++'s own files** — `out/default/fuzzer_stats` (key:value) and `out/default/plot_data` (CSV with `#` header). No custom telemetry.
- **Persistent fuzzing supported** — `harness_template.py` captures the initial register set and writable memory and restores it inside the `place_input` callback. Set `persistent_iters=0` for the throughput-optimal fork-free loop the paper recommends.

---

## ⚠️ Limitations / caveats

> [!WARNING]
> **Not a full OS emulator.** Page tables, MMIO, interrupts, and syscalls have to be stubbed by hand. unicornafl is designed for *function-isolated* fuzzing, and so is this.

> [!NOTE]
> On **macOS arm64** the unicornafl wheel build occasionally needs a Rust nightly; `setup.sh` tries stable first and prints guidance otherwise.

> [!CAUTION]
> **AFL++ on macOS** auto-sets `AFL_SKIP_CPUFREQ=1` and `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1`, but you may still hit one-time permission/coredump prompts on first run.

> [!WARNING]
> **Claude Desktop has a message-length limit.** `analyze_input_handling` over a very large function may get truncated — pass smaller `count` / `size_hint` values.

> [!NOTE]
> **arm64 thumb / mips64 / etc.** are untested — PRs welcome.

---

## 📄 The paper this is built on

This tool ports the three strategies (grammar extraction · seed enrichment · saturation handler) from the following paper to *binary fuzzing* with *Claude as the in-context LLM*:

> **Large Language Model guided Protocol Fuzzing.**
> Ruijie Meng, Martin Mirchev, Marcel Böhme, Abhik Roychoudhury.
> *NDSS Symposium 2024.* [doi:10.14722/ndss.2024.24556](https://dx.doi.org/10.14722/ndss.2024.24556)

The original ChatAFL targets text-based protocols (RTSP/FTP/SIP/…) and calls the OpenAI API. unicornafl-mcp differs as follows:

| Aspect | ChatAFL | unicornafl-mcp |
|---|---|---|
| Target | Text protocols | Binary code (ARM64-first) |
| LLM invocation | OpenAI API | Claude Desktop chat context (no external call) |
| Grammar extraction | RFC NL → message grammar | disasm + immediates + strings + dynamic read pattern |
| Seed enrichment | LLM generates missing message types | Claude designs seeds → `template_seeds` / `seed_add_many` |
| Plateau breaking | LLM proposes next message | `fuzz_plateau_check` → Claude reasoning → `fuzz_inject_seed` |

---

## 🙏 Dependencies / credits

- [Unicorn Engine](https://github.com/unicorn-engine/unicorn)
- [unicornafl](https://github.com/AFLplusplus/unicornafl) — the AFL++ ↔ Unicorn bridge
- [AFL++](https://github.com/AFLplusplus/AFLplusplus)
- [Capstone](https://github.com/capstone-engine/capstone)
- [Model Context Protocol Python SDK](https://github.com/modelcontextprotocol/python-sdk)

---

## 🤝 Contributing

Issues and PRs welcome. Before opening a PR, please make sure:

- `python -m py_compile server.py harness_template.py` passes
- New tools are added to the README catalog in this file
- If practical, ship a tiny smoke test that exercises the new tool against a real Unicorn instance

---

## 📜 License

MIT — see [`LICENSE`](LICENSE).

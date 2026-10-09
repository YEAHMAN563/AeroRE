# Roadmap

## 0.2 — buildable foundation

- Reproducible CMake/vcpkg configuration for Windows x64 and headless Linux
- CI build and native regression suite
- Zydis primary decoder with built-in fallback
- Full PE metadata parser and deterministic multithreaded analysis
- SQLite IDB, IAT reconstruction, unpacker registry, debugger, Python and MCP

## 0.3 — analysis depth

- Parse x64 exception/unwind data and use it as high-confidence function ranges
- Recover switch tables with value-range propagation
- Add tail-call classification and thunk folding
- Add incremental invalidation rather than replacing all derived facts
- Corpus tests for malformed/truncated/adversarial PE inputs

## 0.4 — debugger UX

- Thread/module/breakpoint managers and exception policy UI
- Editable register, stack, memory, and synchronized disassembly panes
- Robust step-over/out state across exceptions and multiple threads
- Python-backed breakpoint conditions in a sandboxed callback queue
- Minidump and live-process snapshot import

## 0.5 — import reconstruction

- Delay-import and forwarded-export reconstruction
- Confidence scoring and manual-review table before patching
- Wider wrapper IR beyond one-hop trampolines
- Round-trip validation with the Windows loader and a PE conformance corpus

## 0.6 — unpacker SDK

- Out-of-process plugin host with time and memory limits
- Trace capture, taint propagation, normalized micro-IR, and provenance
- VM dispatcher and handler discovery
- Handler semantic equivalence grouping and reconstructed native stream
- VMProtect plugin as a separately testable package; Themida/Enigma can reuse
  the ABI without touching the core

## 1.0 — release bar

- Stable plugin and database schema versions with migrations
- Signed Windows packages and symbol files
- Crash-safe project recovery and reproducible analysis hashes
- Performance corpus, fuzzing, and documented threat model


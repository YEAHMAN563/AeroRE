# AeroRE architecture

## Design rule

Parallel work discovers facts; it never mutates canonical program state.
Workers receive immutable PE bytes and return instructions, candidate
functions, CFG edges, strings, and xrefs. A single deterministic fixup phase
sorts and resolves those facts before SQLite or the UI can observe them.

## Modules

| Module | Responsibility | Boundary |
|---|---|---|
| `pe` | PE32/PE32+ parsing, RVA mapping, rebuilds, added sections | Immutable after load except explicit rebuild operations |
| `decoder` | Zydis adapter plus dependency-free fallback decoder | One decoder per analysis context |
| `engine` | Linear sweep, function seeds, recursive descent, CFGs, loops, xrefs, strings | Worker-local output, ordered merge |
| `pool` | Per-worker queues with work stealing | Jobs do not own global analysis state |
| `model` | Stable program snapshot and bidirectional lookup | Published atomically through `Session` |
| `database` | SQLite IDB, schema migration, annotations, netnodes, read-only query gate | Serialized commit after analysis |
| `debugger` | Windows debug loop, breakpoints, registers, memory and module snapshots | Dedicated debug-event thread |
| `emu` | Bounded concrete execution for straight-line protector stubs | No host execution of target code |
| `unpack` | `IUnpacker` registry, scoring, trace/OEP handoff | Returns rebuilt bytes and provenance |
| `iat` | Export reverse-map, trampoline resolution, import report/rebuild | Works on image/module snapshots |
| `session` | Orchestration and snapshot lifetime | API used by UI, CLI, Python, MCP |
| `mcp` | Local JSON-RPC tool facade | Stdio; no network listener |
| `ui` | Dear ImGui docking frontend | Consumes snapshots and progress events |

## Data flow and threads

```mermaid
flowchart LR
    subgraph UI["UI thread"]
      V["Docked views"]
      Q["Progress drain"]
    end
    subgraph IO["Coordinator / DB"]
      L["Load and parse"]
      M["Deterministic merge"]
      S["SQLite transaction"]
    end
    subgraph W["Work-stealing pool"]
      U["Unpack trace"]
      A["Section sweep"]
      F["Function CFG"]
    end
    L --> U
    U --> A
    A --> M
    M --> F
    F --> M
    M --> S
    S --> V
    U -. "events" .-> Q
    A -. "events" .-> Q
    F -. "events" .-> Q
```

The loader/coordinator owns the mutable `PeImage`. Analysis workers receive
only const references. Section sweep jobs run first. Their decoded candidates
are sorted by address and overlap conflicts are resolved deterministically.
Entry point, exports, TLS callbacks, direct call targets, and prologue matches
form the function seed set. Function jobs then recurse over the canonical
instruction map. Results are sorted again before a `ProgramModel` snapshot is
published.

The debugger has its own Win32 event loop. Live memory and module lists become
explicit snapshots before they enter analysis or IAT reconstruction. The UI
never calls `WaitForDebugEvent` and workers never call rendering APIs.

## Analysis invariants

- Persisted addresses are virtual addresses; PE directory fields remain RVAs.
- Every PE read is bounds checked against the owned file/mapped image.
- Canonical instruction ranges never overlap.
- Given the same bytes and settings, output ordering is independent of worker
  count.
- Direct calls add function seeds and bidirectional call xrefs.
- Conditional branches add taken and fall-through CFG edges.
- Backward CFG edges are retained as loop candidates.
- User names, comments, and types are logically separate from derived facts.

## SQLite IDB

The database stores segments, instructions, functions, basic blocks, edges,
loops, xrefs, strings, imports, exports, names, comments, structures, applied
types, reconstructed IAT entries, metadata, and plugin `netnode` blobs. WAL
mode and foreign keys are enabled. Schema changes run transactionally.

`query_json` accepts one read-only `SELECT`, `WITH`, `PRAGMA`, or `EXPLAIN`
statement and rejects mutation, which is the surface exposed through MCP.

## Unpacker boundary

`IUnpacker` has three jobs: score an image, run with progress reporting, and
return an `UnpackResult` containing rebuilt bytes, OEP, confidence, log, and
lifted effects. Packer-specific logic stays outside the PE loader and analyzer.

The built-in tracer is deliberately bounded. It interprets a useful subset of
x86/x64 arithmetic, memory, stack, and control flow, recognizes a handoff from
a protector section to a clean executable section, patches the OEP, and feeds
the new image back through normal analysis. General VM handler discovery and
devirtualization require the micro-IR milestone described in the roadmap.

## IAT reconstruction

The fixer scans pointer-sized slots in non-executable sections. Values are
matched against module ranges and exact export VAs. If a pointer targets the
image, up to four direct/indirect trampoline steps are followed. Named and
ordinal imports are grouped per DLL, then a new import descriptor, ILT, IAT,
hint/name data, and DLL strings are emitted into `.aeroiat`. RIP-relative and
embedded absolute references to old slots are rewritten.

## UI boundary

Dear ImGui owns rendering only. All panes operate on `ProgramModel`, `PeImage`,
`Debugger`, and command methods on `Session`. No ImGui type appears in a public
engine header, preserving a clean migration path to Qt.


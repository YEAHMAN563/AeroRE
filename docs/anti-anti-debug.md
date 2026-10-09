# Anti-anti-debug module

`AntiAntiDebug` is a user-mode companion to AeroRE's Windows debugger. It is
activated from the existing create/attach lifecycle, receives module and thread
events, and restores every reversible patch before detach. It does not require
or install a kernel driver.

## Defaults and configuration

Settings live in `aerore-hide.ini` and are also exposed under **Debug →
Anti-anti-debug settings**. The default profile enables reversible concealment
and keeps the two options that materially reduce debugger visibility disabled:

| Option | Default | Behavior / tradeoff |
|---|---:|---|
| `patch_peb` | on | Clears `BeingDebugged` and the three heap-debug bits in `NtGlobalFlag` |
| `patch_heap` | on | Removes tail/free/parameter validation flags from the process heap |
| `hook_debug_apis` | on | Installs per-module IAT redirects into target-owned executable memory |
| `hook_nt_query_system` | on | Returns `KernelDebuggerEnabled=false`, `KernelDebuggerNotPresent=true` |
| `block_thread_hide_calls` | on | Makes target calls to `ThreadHideFromDebugger` report success without hiding the thread |
| `hide_new_threads` | off | Actually hides newly-created threads; those threads stop producing debug events |
| `sanitize_debug_registers` | off | Clears DR0–DR7 while running and restores them at the next event; hardware breakpoints cannot fire while cleared |
| `neutralize_output_debug_string` | on | No-ops imported `OutputDebugStringA/W` and consumes their debug-print exceptions |
| `neutralize_invalid_handle` | on | Consumes `STATUS_INVALID_HANDLE` raised by invalid `CloseHandle` probes |
| `restore_on_detach` | on | Restores PEB, heap, and IAT bytes before releasing remote stubs |

## Countermeasure map

| Target check | AeroRE response |
|---|---|
| `PEB.BeingDebugged` | Writes zero in the native or WOW64 PEB |
| `PEB.NtGlobalFlag` | Clears `FLG_HEAP_ENABLE_TAIL_CHECK`, `FLG_HEAP_ENABLE_FREE_CHECK`, and `FLG_HEAP_VALIDATE_PARAMETERS` |
| Heap `Flags` / `ForceFlags` | Clears debug validation bits, preserves normal flags, enables `HEAP_GROWABLE`, and zeroes `ForceFlags` |
| `IsDebuggerPresent` | IAT hook returns `FALSE` |
| `CheckRemoteDebuggerPresent` | IAT hook returns success and writes `FALSE` |
| `NtQueryInformationProcess` | Filters `ProcessDebugPort`, `ProcessDebugObjectHandle`, and `ProcessDebugFlags`; forwards other classes |
| `NtQuerySystemInformation` | Filters `SystemKernelDebuggerInformation`; forwards other classes |
| `NtSetInformationThread` | Filters target attempts to hide a thread from AeroRE |
| `OutputDebugStringA/W` | Optional IAT no-op plus debug-print exception consumption |
| Invalid `CloseHandle` | Optional `STATUS_INVALID_HANDLE` consumption before target SEH sees debugger-only behavior |
| DR0–DR7 scans | Optional save/clear/restore cycle around continues, with the documented hardware-breakpoint tradeoff |

The hooker walks the import table of every loaded module and repeats the pass on
`LOAD_DLL_DEBUG_EVENT`. Stubs handle x86 `stdcall` and the Windows x64 calling
convention separately. Queries not related to debugger detection jump to the
original imported NT routine, which avoids breaking ordinary process queries.

## Thread hiding modes

Two distinct behaviors are intentionally separate:

- Blocking `NtSetInformationThread(ThreadHideFromDebugger)` prevents the target
  from making itself invisible to AeroRE.
- Enabling `hide_new_threads` asks ntdll to hide each new target thread. This is
  useful for narrow experiments but prevents AeroRE from receiving later debug
  events from those threads and cannot be reversed. It is therefore off by
  default.

## Scope and limitations

- The first pass is user-mode only. Kernel callbacks, hypervisor checks, timing
  attacks, direct syscalls that bypass imported APIs, and integrity checks over
  IAT slots require separate strategies.
- IAT hooks cover normal imports in modules observed by the debugger. Code that
  resolves an API dynamically and performs a direct syscall can bypass them.
- Heap structure offsets target Windows 10/11 NT heaps. Restoration is best
  effort if the process mutates the same fields after attach.
- Use the x64 solution configuration for native x64 targets and the x86
  configuration for the complete x86 register/debugger experience. An x64
  build still recognizes and patches WOW64 PEBs and 32-bit import tables.

Every mitigation is designed for binaries and systems the operator is
authorized to inspect. The console records applied hooks and state changes so
the session remains auditable.

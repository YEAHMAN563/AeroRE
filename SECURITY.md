# Security policy

AeroRE parses untrusted executables and may attach to hostile processes. Treat
all input bytes, debug events, scripts, and plugins as adversarial.

Report vulnerabilities through GitHub private security advisories. Do not
attach live malware samples to public issues.

The MCP server is local stdio, not a network service. If a downstream project
adds HTTP transport, it must bind to loopback by default, validate origins, and
add authentication and authorization before exposing process or filesystem
operations.


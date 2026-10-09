#pragma once

#include "aerore/json.hpp"
#include "aerore/session.hpp"

namespace aerore {

// Model Context Protocol server (JSON-RPC 2.0). Current stdio messages are
// newline-delimited JSON; the reader also accepts legacy Content-Length frames.
// handle() accepts one JSON-RPC object and is what tests call directly.
class McpServer {
public:
    explicit McpServer(Session& session);
    std::string handle(const std::string& message);
    void serve_stdio();

private:
    Json tools_list() const;
    Json call_tool(const std::string& name, const Json& args);

    Session& session_;
};

// Optional localhost transport used by the GUI. The stdio server remains the
// recommended automation transport; TCP binds only to 127.0.0.1 and uses the
// same newline-delimited JSON-RPC framing.
class McpTcpServer {
public:
    explicit McpTcpServer(Session& session);
    ~McpTcpServer();
    McpTcpServer(const McpTcpServer&) = delete;
    McpTcpServer& operator=(const McpTcpServer&) = delete;

    bool start(u16 preferred_port = 37091);
    // Execute queued requests on the owning UI thread. This keeps Session's
    // mutable PE/database state single-threaded while socket I/O stays async.
    void pump();
    void stop();
    bool running() const;
    u16 port() const;
    std::string status() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace aerore

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

}  // namespace aerore

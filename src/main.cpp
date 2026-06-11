#include "ui/app.h"
#include "mcp/mcp_server.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <iostream>
#include <string_view>

int main(int argc, char** argv) {
    bool run_mcp = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--mcp") {
            run_mcp = true;
        }
    }

    if (run_mcp) {
        // When running MCP over stdio, redirect logs to a file to avoid corrupting stdout JSON
        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("hyperion_mcp.log", true);
        auto logger = std::make_shared<spdlog::logger>("mcp_logger", file_sink);
        spdlog::set_default_logger(logger);
        spdlog::set_level(spdlog::level::info);
        spdlog::set_pattern("[%H:%M:%S.%e] [%l] %v");
    } else {
        spdlog::set_level(spdlog::level::info);
        spdlog::set_pattern("[%H:%M:%S.%e] [%l] %v");
    }

    hype::App app;

    if (run_mcp) {
        hype::McpServer mcp(app);
        mcp.run_stdio();
        return 0;
    }

    return app.run();
}

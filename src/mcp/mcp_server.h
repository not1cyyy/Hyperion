#pragma once
#include <string>
#include "ui/app.h"

namespace hype {
class McpServer {
public:
    McpServer(App& app);
    void run_stdio();
private:
    void handle_message(const std::string& msg);
    App& app_;
};
}

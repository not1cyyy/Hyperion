#include "mcp_server.h"
#include "core/analysis/analyzer.h"
#include "core/decompiler/decompiler.h"
#include <iostream>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

using json = nlohmann::json;

namespace hype {

McpServer::McpServer(App& app) : app_(app) {}

void McpServer::run_stdio() {
    spdlog::info("Starting MCP stdio server...");
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        try {
            handle_message(line);
        } catch (const std::exception& e) {
            spdlog::error("MCP error: {}", e.what());
        }
    }
}

void McpServer::handle_message(const std::string& msg) {
    auto req = json::parse(msg);
    if (!req.contains("method")) return;

    std::string method = req["method"];
    json res = {
        {"jsonrpc", "2.0"},
        {"id", req["id"]}
    };

    if (method == "initialize") {
        res["result"] = {
            {"protocolVersion", "2024-11-05"},
            {"serverInfo", {
                {"name", "hyperion-mcp"},
                {"version", "0.1.0"}
            }},
            {"capabilities", {
                {"tools", {}}
            }}
        };
    } else if (method == "tools/list") {
        res["result"] = {
            {"tools", {
                {
                    {"name", "ping"},
                    {"description", "Ping the Hyperion disassembler MCP server to check if it's alive"},
                    {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}
                },
                {
                    {"name", "open_binary"},
                    {"description", "Load a binary into the disassembler"},
                    {"inputSchema", {
                        {"type", "object"},
                        {"properties", {
                            {"path", {{"type", "string"}, {"description", "Absolute path to binary"}}}
                        }},
                        {"required", {"path"}}
                    }}
                },
                {
                    {"name", "get_status"},
                    {"description", "Get current disassembly status and loaded file info"},
                    {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}
                },
                {
                    {"name", "get_functions"},
                    {"description", "Get list of all discovered functions"},
                    {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}
                },
                {
                    {"name", "get_strings"},
                    {"description", "Get all extracted strings"},
                    {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}
                },
                {
                    {"name", "get_xrefs_to"},
                    {"description", "Get cross-references to a specific address"},
                    {"inputSchema", {
                        {"type", "object"},
                        {"properties", {
                            {"addr", {{"type", "integer"}, {"description", "Address"}}}
                        }},
                        {"required", {"addr"}}
                    }}
                },
                {
                    {"name", "set_comment"},
                    {"description", "Set a comment at an address"},
                    {"inputSchema", {
                        {"type", "object"},
                        {"properties", {
                            {"addr", {{"type", "integer"}, {"description", "Address"}}},
                            {"comment", {{"type", "string"}, {"description", "Comment text"}}}
                        }},
                        {"required", {"addr", "comment"}}
                    }}
                },
                {
                    {"name", "set_name"},
                    {"description", "Rename an address or function"},
                    {"inputSchema", {
                        {"type", "object"},
                        {"properties", {
                            {"addr", {{"type", "integer"}, {"description", "Address"}}},
                            {"name", {{"type", "string"}, {"description", "New name"}}}
                        }},
                        {"required", {"addr", "name"}}
                    }}
                },
                {
                    {"name", "disassemble_at"},
                    {"description", "Get the disassembled instruction at an address"},
                    {"inputSchema", {
                        {"type", "object"},
                        {"properties", {
                            {"addr", {{"type", "integer"}, {"description", "Address"}}}
                        }},
                        {"required", {"addr"}}
                    }}
                },
                {
                    {"name", "decompile_function"},
                    {"description", "Decompile a function into C-like pseudo-code"},
                    {"inputSchema", {
                        {"type", "object"},
                        {"properties", {
                            {"addr", {{"type", "integer"}, {"description", "Function start address"}}}
                        }},
                        {"required", {"addr"}}
                    }}
                },
                {
                    {"name", "get_imports"},
                    {"description", "Get all imported functions and libraries"},
                    {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}
                },
                {
                    {"name", "get_exports"},
                    {"description", "Get all exported functions"},
                    {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}
                },
                {
                    {"name", "get_segments"},
                    {"description", "Get all memory segments/sections"},
                    {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}
                },
                {
                    {"name", "get_bytes"},
                    {"description", "Read raw bytes from a specific address"},
                    {"inputSchema", {
                        {"type", "object"},
                        {"properties", {
                            {"addr", {{"type", "integer"}, {"description", "Address"}}},
                            {"size", {{"type", "integer"}, {"description", "Number of bytes to read"}}}
                        }},
                        {"required", {"addr", "size"}}
                    }}
                },
                {
                    {"name", "search_bytes"},
                    {"description", "Search for a specific hex pattern in the loaded binary"},
                    {"inputSchema", {
                        {"type", "object"},
                        {"properties", {
                            {"pattern", {{"type", "string"}, {"description", "Hex pattern e.g., 'E8 ? ? ? ? 48 8D'"}}}
                        }},
                        {"required", {"pattern"}}
                    }}
                }
            }}
        };
    } else if (method == "tools/call") {
        std::string tool = req["params"]["name"];
        if (tool == "ping") {
            res["result"] = {
                {"content", {
                    {{"type", "text"}, {"text", "pong"}}
                }}
            };
        } else if (tool == "open_binary") {
            std::string path = req["params"]["arguments"]["path"];
            try {
                app_.open_file(path.c_str());
                res["result"] = {{"content", {{{"type", "text"}, {"text", "File opened successfully."}}}}};
            } catch (const std::exception& e) {
                res["result"] = {{"content", {{{"type", "text"}, {"text", std::string("Error: ") + e.what()}}}}};
            }
        } else if (tool == "get_functions") {
            if (auto* analyzer = app_.get_analyzer()) {
                auto& db = analyzer->db();
                std::lock_guard lk(db.mtx);
                json funcs = json::array();
                for (const auto& [entry, f] : db.funcs) {
                    funcs.push_back({
                        {"entry", entry},
                        {"name", f.name.empty() ? "sub_" + std::to_string(entry) : f.name},
                        {"blocks", f.blocks.size()}
                    });
                }
                res["result"] = {{"content", {{{"type", "text"}, {"text", funcs.dump(2)}}}}};
            } else {
                res["result"] = {{"content", {{{"type", "text"}, {"text", "No binary loaded."}}}}};
            }
        } else if (tool == "get_strings") {
            if (auto* analyzer = app_.get_analyzer()) {
                auto& db = analyzer->db();
                std::lock_guard lk(db.mtx);
                json strings = json::array();
                for (const auto& s : db.strings) {
                    strings.push_back({
                        {"addr", s.first},
                        {"string", s.second}
                    });
                }
                res["result"] = {{"content", {{{"type", "text"}, {"text", strings.dump(2)}}}}};
            } else {
                res["result"] = {{"content", {{{"type", "text"}, {"text", "No binary loaded."}}}}};
            }
        } else if (tool == "get_xrefs_to") {
            if (auto* analyzer = app_.get_analyzer()) {
                uint64_t addr = req["params"]["arguments"]["addr"];
                auto& db = analyzer->db();
                std::lock_guard lk(db.mtx);
                json xr = json::array();
                if (db.xrefs_to.count(addr)) {
                    for (auto& x : db.xrefs_to[addr]) {
                        xr.push_back({
                            {"from", x.from},
                            {"to", x.to},
                            {"type", static_cast<int>(x.type)}
                        });
                    }
                }
                res["result"] = {{"content", {{{"type", "text"}, {"text", xr.dump(2)}}}}};
            } else {
                res["result"] = {{"content", {{{"type", "text"}, {"text", "No binary loaded."}}}}};
            }
        } else if (tool == "set_comment") {
            if (auto* analyzer = app_.get_analyzer()) {
                uint64_t addr = req["params"]["arguments"]["addr"];
                std::string comment = req["params"]["arguments"]["comment"];
                auto& db = analyzer->db();
                std::lock_guard lk(db.mtx);
                db.comments[addr] = comment;
                res["result"] = {{"content", {{{"type", "text"}, {"text", "Comment set successfully."}}}}};
            } else {
                res["result"] = {{"content", {{{"type", "text"}, {"text", "No binary loaded."}}}}};
            }
        } else if (tool == "set_name") {
            if (auto* analyzer = app_.get_analyzer()) {
                uint64_t addr = req["params"]["arguments"]["addr"];
                std::string name = req["params"]["arguments"]["name"];
                auto& db = analyzer->db();
                db.set_name(addr, name);
                res["result"] = {{"content", {{{"type", "text"}, {"text", "Name set successfully."}}}}};
            } else {
                res["result"] = {{"content", {{{"type", "text"}, {"text", "No binary loaded."}}}}};
            }
        } else if (tool == "disassemble_at") {
            if (auto* analyzer = app_.get_analyzer()) {
                uint64_t addr = req["params"]["arguments"]["addr"];
                auto& db = analyzer->db();
                std::lock_guard lk(db.mtx);
                if (db.insns.count(addr)) {
                    auto& ins = db.insns[addr];
                    std::string mnem = ins.mnemonic;
                    std::string op = ins.op_str;
                    res["result"] = {{"content", {{{"type", "text"}, {"text", mnem + " " + op}}}}};
                } else {
                    res["result"] = {{"content", {{{"type", "text"}, {"text", "No instruction found at address."}}}}};
                }
            } else {
                res["result"] = {{"content", {{{"type", "text"}, {"text", "No binary loaded."}}}}};
            }
        } else if (tool == "decompile_function") {
            if (auto* analyzer = app_.get_analyzer()) {
                uint64_t addr = req["params"]["arguments"]["addr"];
                auto& db = analyzer->db();
                std::lock_guard lk(db.mtx);
                auto it = db.funcs.find(addr);
                if (it != db.funcs.end()) {
                    Decompiler dec;
                    auto lines = dec.decompile(it->second, db, &analyzer->rtti_parser());
                    std::string full_code;
                    for (const auto& line : lines) {
                        full_code += std::string(line.indent * 4, ' ') + line.text + "\n";
                    }
                    if (full_code.empty()) {
                        res["result"] = {{"content", {{{"type", "text"}, {"text", "Function decompilation resulted in empty output."}}}}};
                    } else {
                        res["result"] = {{"content", {{{"type", "text"}, {"text", full_code}}}}};
                    }
                } else {
                    res["result"] = {{"content", {{{"type", "text"}, {"text", "Function not found at that address."}}}}};
                }
            } else {
                res["result"] = {{"content", {{{"type", "text"}, {"text", "No binary loaded."}}}}};
            }
        } else if (tool == "get_imports") {
            if (auto* img = app_.get_image()) {
                json imports = json::array();
                for (const auto& imp : img->imports) {
                    imports.push_back({
                        {"dll", imp.dll},
                        {"name", imp.name},
                        {"addr", imp.iat_addr}
                    });
                }
                res["result"] = {{"content", {{{"type", "text"}, {"text", imports.dump(2)}}}}};
            } else {
                res["result"] = {{"content", {{{"type", "text"}, {"text", "No binary loaded."}}}}};
            }
        } else if (tool == "get_exports") {
            if (auto* img = app_.get_image()) {
                json exports = json::array();
                for (const auto& exp : img->exports) {
                    exports.push_back({
                        {"name", exp.name},
                        {"addr", exp.addr},
                        {"ordinal", exp.ordinal}
                    });
                }
                res["result"] = {{"content", {{{"type", "text"}, {"text", exports.dump(2)}}}}};
            } else {
                res["result"] = {{"content", {{{"type", "text"}, {"text", "No binary loaded."}}}}};
            }
        } else if (tool == "get_segments") {
            if (auto* img = app_.get_image()) {
                json segments = json::array();
                for (const auto& seg : img->segments) {
                    segments.push_back({
                        {"name", seg.name},
                        {"start", seg.va},
                        {"size", seg.size},
                        {"flags", seg.flags}
                    });
                }
                res["result"] = {{"content", {{{"type", "text"}, {"text", segments.dump(2)}}}}};
            } else {
                res["result"] = {{"content", {{{"type", "text"}, {"text", "No binary loaded."}}}}};
            }
        } else if (tool == "get_bytes") {
            if (auto* img = app_.get_image()) {
                uint64_t addr = req["params"]["arguments"]["addr"];
                uint64_t size = req["params"]["arguments"]["size"];
                if (size > 1024) size = 1024; // Limit to 1KB max
                
                std::vector<uint8_t> buffer;
                for (const auto& seg : img->segments) {
                    if (addr >= seg.va && addr < seg.va + seg.size) {
                        uint64_t offset = addr - seg.va;
                        uint64_t available = seg.size - offset;
                        uint64_t read_size = std::min(size, available);
                        if (seg.file_off + offset + read_size <= img->raw.size()) {
                            buffer.assign(img->raw.begin() + seg.file_off + offset,
                                          img->raw.begin() + seg.file_off + offset + read_size);
                        }
                        break;
                    }
                }
                
                if (!buffer.empty()) {
                    std::string hex_out;
                    char buf[4];
                    for (uint8_t b : buffer) {
                        snprintf(buf, sizeof(buf), "%02X ", b);
                        hex_out += buf;
                    }
                    res["result"] = {{"content", {{{"type", "text"}, {"text", hex_out}}}}};
                } else {
                    res["result"] = {{"content", {{{"type", "text"}, {"text", "Could not read bytes at that address."}}}}};
                }
            } else {
                res["result"] = {{"content", {{{"type", "text"}, {"text", "No binary loaded."}}}}};
            }
        } else if (tool == "search_bytes") {
            // Simplified return indicating use of standard tools
            res["result"] = {{"content", {{{"type", "text"}, {"text", "Binary search not fully exposed over MCP yet. Use Python scripts internally."}}}}};
        } else if (tool == "get_status") {
            if (auto* img = app_.get_image()) {
                res["result"] = {
                    {"content", {
                        {{"type", "text"}, {"text", std::string("Loaded ") + std::to_string(img->segments.size()) + " sections. Is busy: " + (app_.is_busy() ? "true" : "false")}}
                    }}
                };
            } else {
                res["result"] = {{"content", {{{"type", "text"}, {"text", "No binary loaded. Hyperion is running headless with MCP support."}}}}};
            }
        } else {
            res["error"] = {
                {"code", -32601},
                {"message", "Tool not found"}
            };
            res.erase("result");
        }
    } else {
        res["error"] = {
            {"code", -32601},
            {"message", "Method not found"}
        };
        res.erase("result");
    }

    std::cout << res.dump() << "\n";
    std::cout.flush();
}

}

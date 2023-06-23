#pragma once

#include <filesystem>
#include <string>
#include <variant>
#include <vector>

namespace sispop::cli {

struct command_line_options {
    std::string ip = "0.0.0.0";
    uint16_t https_port = 22934;
    uint16_t omq_port = 22540;
    std::string sispopd_omq_rpc;  // Defaults to ipc://$HOME/.sispop/[testnet/]sispopd.sock
    bool force_start = false;
    bool testnet = false;
    std::string log_level = "info";
    std::filesystem::path data_dir;
    std::string sispopd_key;          // test only (but needed for backwards compatibility)
    std::string sispopd_x25519_key;   // test only
    std::string sispopd_ed25519_key;  // test only
    // x25519 key that will be given access to get_stats omq endpoint
    std::vector<std::string> stats_access_keys;
};

using parse_result = std::variant<command_line_options, int>;

parse_result parse_cli_args(std::vector<const char*> args);
parse_result parse_cli_args(int argc, char* argv[]);

}  // namespace sispop::cli

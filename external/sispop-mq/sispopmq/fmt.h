#pragma once

#include <fmt/format.h>
#include "connections.h"
#include "auth.h"
#include "address.h"

template <>
struct fmt::formatter<sispopmq::AuthLevel> : fmt::formatter<std::string> {
  auto format(sispopmq::AuthLevel v, format_context& ctx) {
    return formatter<std::string>::format(
        fmt::format("{}", to_string(v)), ctx);
  }
};
template <>
struct fmt::formatter<sispopmq::ConnectionID> : fmt::formatter<std::string> {
  auto format(sispopmq::ConnectionID conn, format_context& ctx) {
    return formatter<std::string>::format(
        fmt::format("{}", conn.to_string()), ctx);
  }
};
template <>
struct fmt::formatter<sispopmq::address> : fmt::formatter<std::string> {
  auto format(sispopmq::address addr, format_context& ctx) {
    return formatter<std::string>::format(
        fmt::format("{}", addr.full_address()), ctx);
  }
};

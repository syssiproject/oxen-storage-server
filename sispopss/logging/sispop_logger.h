#pragma once

#include <filesystem>

#include <sispop/log.hpp>

namespace sispop::logging {

void init(const std::filesystem::path& data_dir, sispop::log::Level log_level);

}  // namespace sispop::logging

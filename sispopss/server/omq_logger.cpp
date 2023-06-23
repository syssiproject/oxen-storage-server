#include <sispopmq/sispopmq.h>
#include <sispopss/logging/sispop_logger.h>

namespace sispop {

static auto logcat = log::Cat("omq");

void omq_logger(sispopmq::LogLevel level, const char* file, int line, std::string message) {
    constexpr std::string_view format = "[{}:{}]: {}";
    switch (level) {
        case sispopmq::LogLevel::fatal: log::critical(logcat, format, file, line, message); break;
        case sispopmq::LogLevel::error: log::error(logcat, format, file, line, message); break;
        case sispopmq::LogLevel::warn: log::warning(logcat, format, file, line, message); break;
        case sispopmq::LogLevel::info: log::info(logcat, format, file, line, message); break;
        case sispopmq::LogLevel::debug: log::debug(logcat, format, file, line, message); break;
        case sispopmq::LogLevel::trace: log::trace(logcat, format, file, line, message); break;
    }
}

}  // namespace sispop

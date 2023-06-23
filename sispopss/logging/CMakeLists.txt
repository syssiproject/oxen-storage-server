
add_library(logging STATIC
    sispop_logger.cpp
)

target_link_libraries(logging PUBLIC sispop::logging)

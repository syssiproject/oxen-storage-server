
add_library(common STATIC
    namespace.cpp
    pubkey.cpp
)

target_link_libraries(common PUBLIC sispop::logging filesystem sispopc::sispopc)
target_include_directories(common PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)

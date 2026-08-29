add_executable(analyzer
    main.cpp
)

set_target_properties(analyzer PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

target_link_libraries(analyzer
    PRIVATE
        network_lib
)
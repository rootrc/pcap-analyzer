add_executable(analyzer
    main.cpp
)

target_link_libraries(analyzer
    PRIVATE
        network_lib
)

cmake_minimum_required(VERSION 3.5)

if (${TEST_ONLY})

    project(${DEFINED_PROJECT_NAME} LANGUAGES CXX)

    find_package(GTest REQUIRED)

    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++17 -Wall -pedantic -Werror -pthread -ggdb -g3 -fno-inline")

    add_definitions( -DTEST_ONLY=TRUE )

    include_directories(${CMAKE_SOURCE_DIR}/src)
    add_subdirectory(${CMAKE_SOURCE_DIR}/src)
    add_subdirectory(${CMAKE_SOURCE_DIR}/test)

    add_executable(${PROJECT_NAME}
        test/main.cpp

        $<TARGET_OBJECTS:${PROJECT_NAME}-ocra>
        $<TARGET_OBJECTS:${PROJECT_NAME}-testcases>
    )

    target_link_libraries(${PROJECT_NAME}
        PRIVATE
            gtest
            gmock
            gtest_main)

else ()

    project(${DEFINED_PROJECT_NAME})

    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++17 -Wall -pedantic -Werror -O3")

    add_subdirectory(${CMAKE_SOURCE_DIR}/src)

    add_executable(${PROJECT_NAME}
        src/main.cpp

        $<TARGET_OBJECTS:${PROJECT_NAME}-ocra>
    )

endif (${TEST_ONLY})
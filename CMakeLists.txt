cmake_minimum_required(VERSION 3.5)

if (${TEST_ONLY})

    project(${DEFINED_PROJECT_NAME} LANGUAGES CXX)

    find_package(GTest REQUIRED)
    find_package(Boost REQUIRED)

    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++17 -Wall -pedantic -Werror -pthread -ggdb -g3 -fno-inline")

    add_definitions( -DTEST_ONLY=TRUE )
    if (${OCRA_NO_THROW})
        add_definitions( -DOCRA_NO_THROW )
    endif (${OCRA_NO_THROW})

    include_directories(${CMAKE_SOURCE_DIR}/src)
    add_subdirectory(${CMAKE_SOURCE_DIR}/src)
    add_subdirectory(${CMAKE_SOURCE_DIR}/test)

    add_executable(${PROJECT_NAME}
        test/main.cpp

        $<TARGET_OBJECTS:${PROJECT_NAME}-ocra>
        $<TARGET_OBJECTS:${PROJECT_NAME}-mock>
        $<TARGET_OBJECTS:${PROJECT_NAME}-testcases>
    )

    target_link_libraries(${PROJECT_NAME}
        PRIVATE
            gtest
            gmock
            gtest_main)

else ()

    project(${DEFINED_PROJECT_NAME})

    find_package(Boost REQUIRED)

    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++17 -Wall -pedantic -Werror -O3")

    if (${OCRA_NO_THROW})
        add_definitions( -DOCRA_NO_THROW )
    endif (${OCRA_NO_THROW})

    add_subdirectory(${CMAKE_SOURCE_DIR}/src)

    add_executable(${PROJECT_NAME}
        src/main.cpp

        $<TARGET_OBJECTS:${PROJECT_NAME}-ocra>
    )

endif (${TEST_ONLY})
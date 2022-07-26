include_directories(asserts)
include_directories(mock)

add_subdirectory(mock)
add_subdirectory(testcases)
# here add another modules like stubs or mocks
# (remember to add them in the main CMakeLists file)
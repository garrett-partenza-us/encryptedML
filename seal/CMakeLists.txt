cmake_minimum_required(VERSION 3.12)
project(MyProject)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

file(GLOB_RECURSE SOURCES src/*.cpp)

# Specify the path to the SEAL library headers
include_directories(/opt/homebrew/include/SEAL-4.1)
include_directories(/opt/homebrew/include)

# Specify the path to the SEAL library
link_directories(/opt/homebrew/lib)

# Add your source file
add_executable(${PROJECT_NAME} ${SOURCES})

# Link against the SEAL library
target_link_libraries(${PROJECT_NAME} seal)
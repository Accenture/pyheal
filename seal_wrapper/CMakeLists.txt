cmake_minimum_required(VERSION 3.12)
project(seal_wrapper VERSION 0.1 LANGUAGES CXX C)
set(CMAKE_CXX_STANDARD 17)

# Retained only for standalone seal_wrapper packaging
# Ideally use top level pyheal packaging instead

add_subdirectory(pybind11)
option(BUILD_SEAL "Enable building SEAL" ON)

#set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_BUILD_TYPE Release)

if (BUILD_SEAL)
    add_subdirectory(seal/src)
    include_directories(seal/src)
    link_directories(seal/lib)
    set_target_properties(seal PROPERTIES POSITION_INDEPENDENT_CODE TRUE)

    pybind11_add_module(seal_wrapper
            seal_wrapper/base64.cpp
            seal_wrapper/wrapper.cpp)
    target_link_libraries(seal_wrapper PRIVATE seal)
ENDIF ()
if (UNIX AND NOT WIN32)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fobjc-arc")
    # Activate with: -DCMAKE_BUILD_TYPE=Profiling
    set(CMAKE_C_FLAGS_PROFILING "-g -O0 -fprofile-arcs -ftest-coverage"
        CACHE STRING "Flags used by the C compiler during PROFILING builds.")
    set(CMAKE_CXX_FLAGS_PROFILING "-g -O0 -fprofile-arcs -ftest-coverage"
        CACHE STRING "Flags used by the CXX compiler during PROFILING builds.")
    set(CMAKE_SHARED_LINKER_FLAGS_PROFILING "-fprofile-arcs -ftest-coverage"
        CACHE STRING "Flags used by the linker during the creation of shared libraries during PROFILING builds.")
    set(CMAKE_MODULE_LINKER_FLAGS_PROFILING "-fprofile-arcs -ftest-coverage"
        CACHE STRING "Flags used by the linker during the creation of shared libraries during PROFILING builds.")
    set(CMAKE_EXEC_LINKER_FLAGS_PROFILING "-fprofile-arcs -ftest-coverage"
        CACHE STRING "Flags used by the linker during PROFILING builds.")

    # Activate with: -DCMAKE_BUILD_TYPE=AddressSanitizer
    set(CMAKE_C_FLAGS_ADDRESSSANITIZER "-g -O1 -fsanitize=address -fno-omit-frame-pointer"
        CACHE STRING "Flags used by the C compiler during ADDRESSSANITIZER builds.")
    set(CMAKE_CXX_FLAGS_ADDRESSSANITIZER "-g -O1 -fsanitize=address -fno-omit-frame-pointer"
        CACHE STRING "Flags used by the CXX compiler during ADDRESSSANITIZER builds.")
    set(CMAKE_SHARED_LINKER_FLAGS_ADDRESSSANITIZER "-fsanitize=address"
        CACHE STRING "Flags used by the linker during the creation of shared libraries during ADDRESSSANITIZER builds.")
    set(CMAKE_MODULE_LINKER_FLAGS_ADDRESSSANITIZER "-fsanitize=address"
        CACHE STRING "Flags used by the linker during the creation of shared libraries during ADDRESSSANITIZER builds.")
    set(CMAKE_EXEC_LINKER_FLAGS_ADDRESSSANITIZER "-fsanitize=address"
        CACHE STRING "Flags used by the linker during ADDRESSSANITIZER builds.")
endif()

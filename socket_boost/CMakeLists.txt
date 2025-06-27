cmake_minimum_required(VERSION 3.18)
project(socket_boost CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O2")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

include_directories(include_cpp)
link_libraries(bpf rdmacm ibverbs)

# === MAIN PROGRAM ===

add_executable(scap
    src_cpp/main.cpp
    src_cpp/SocketMng.cpp
    src_cpp/BpfMng.cpp
    src_cpp/RdmaContext.cpp
    src_cpp/ThreadPool.cpp
    src_cpp/RdmaMng.cpp
)

# === BPF ===

set(BPF_OBJ ${CMAKE_BINARY_DIR}/obj/scap.bpf.o)
set(SKEL_HDR ${CMAKE_BINARY_DIR}/obj/scap.skel.h)

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/obj)

add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND clang -g -O2 -target bpf -I${CMAKE_SOURCE_DIR}/include -c ${CMAKE_SOURCE_DIR}/src_cpp/scap.bpf.c -o ${BPF_OBJ}
    DEPENDS ${CMAKE_SOURCE_DIR}/src_cpp/scap.bpf.c
)

add_custom_command(
    OUTPUT ${SKEL_HDR}
    COMMAND bpftool gen skeleton ${BPF_OBJ} > ${SKEL_HDR}
    DEPENDS ${BPF_OBJ}
)

add_custom_target(bpf_gen ALL DEPENDS ${SKEL_HDR})

# === PUSH MODIFICATIONS ===
add_custom_target(push
    COMMAND rsync -avz --delete ${CMAKE_BINARY_DIR}/bin poli-server:/home/$ENV{USER}/poli/socket-over-rdma
    COMMAND rsync -avz --delete ${CMAKE_BINARY_DIR}/obj poli-server:/home/$ENV{USER}/poli/socket-over-rdma
)

# === CLEANUP ===
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_BINARY_DIR}/bin/*;${CMAKE_BINARY_DIR}/obj/*")

cmake_minimum_required(VERSION 3.18)
project(socket_boost C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O2")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

include_directories(include)
link_libraries(bpf rdmacm ibverbs)

# === MAIN PROGRAM ===

add_executable(scap
    src/main.c
    src/scap.c
    src/sk_utils.c
    src/rdma_utils.c
    src/rdma_manager.c
    src/hashmap.c
)

# === BPF ===

set(BPF_OBJ ${CMAKE_BINARY_DIR}/obj/scap.bpf.o)
set(SKEL_HDR ${CMAKE_BINARY_DIR}/obj/scap.skel.h)

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/obj)

add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND clang -g -O2 -target bpf -I${CMAKE_SOURCE_DIR}/include -c ${CMAKE_SOURCE_DIR}/src/scap.bpf.c -o ${BPF_OBJ}
    DEPENDS ${CMAKE_SOURCE_DIR}/src/scap.bpf.c
)

add_custom_command(
    OUTPUT ${SKEL_HDR}
    COMMAND bpftool gen skeleton ${BPF_OBJ} > ${SKEL_HDR}
    DEPENDS ${BPF_OBJ}
)

add_custom_target(bpf_gen ALL DEPENDS ${SKEL_HDR})

# === TEST ===

add_executable(client tests/socket/client.c)
add_executable(server tests/socket/server.c)

target_link_libraries(client bpf rdmacm ibverbs)
target_link_libraries(server bpf rdmacm ibverbs)

# === PUSH MODIFICATIONS ===
add_custom_target(push
    COMMAND rsync -avz --delete ${CMAKE_BINARY_DIR}/bin poli-server:/home/$ENV{USER}/poli/socket-over-rdma
    DEPENDS scap client server
)

# === CLEANUP ===
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_BINARY_DIR}/obj")

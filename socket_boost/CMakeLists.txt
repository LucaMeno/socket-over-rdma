cmake_minimum_required(VERSION 3.16)
project(scap_project C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O2")

# Output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(OBJ_DIR ${CMAKE_BINARY_DIR}/obj)

# Include directory
include_directories(include)

# Librerie necessarie
find_library(BPF_LIB bpf REQUIRED)
find_library(RDMACM_LIB rdmacm REQUIRED)
find_library(IBVERBS_LIB ibverbs REQUIRED)

# =========================
# Step 1: Compilazione file BPF
# =========================
set(BPF_SRC ${CMAKE_SOURCE_DIR}/src/scap.bpf.c)
set(BPF_OBJ ${OBJ_DIR}/scap.bpf.o)
set(SKEL_H ${OBJ_DIR}/scap.skel.h)

file(MAKE_DIRECTORY ${OBJ_DIR})

add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND clang -g -O2 -target bpf -I${CMAKE_SOURCE_DIR}/include -c ${BPF_SRC} -o ${BPF_OBJ}
    DEPENDS ${BPF_SRC}
    COMMENT "Compilazione BPF: scap.bpf.o"
)

add_custom_command(
    OUTPUT ${SKEL_H}
    COMMAND bpftool gen skeleton ${BPF_OBJ} > ${SKEL_H}
    DEPENDS ${BPF_OBJ}
    COMMENT "Generazione skeleton: scap.skel.h"
)

add_custom_target(generate_skel DEPENDS ${SKEL_H})

# =========================
# Step 2: Codice utente
# =========================

# Libreria statica con i moduli C
add_library(core_objs OBJECT
    src/scap.c
    src/sk_utils.c
    src/rdma_utils.c
    src/rdma_manager.c
)

# Programma principale
add_executable(scap src/main.c $<TARGET_OBJECTS:core_objs>)
add_dependencies(scap generate_skel)
target_include_directories(scap PRIVATE include ${OBJ_DIR})
target_link_libraries(scap ${BPF_LIB} ${RDMACM_LIB} ${IBVERBS_LIB})

# =========================
# Optional: Clean-up target
# =========================
add_custom_target(clean-all
    COMMAND ${CMAKE_COMMAND} -E rm -rf ${CMAKE_BINARY_DIR}
    COMMENT "Pulizia completa della build directory"
)

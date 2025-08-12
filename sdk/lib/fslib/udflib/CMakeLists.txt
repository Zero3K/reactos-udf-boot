include_directories(
    ${REACTOS_SOURCE_DIR}/drivers/filesystems/udfs)

list(APPEND SOURCE
    udflib.c)

add_library(udflib ${SOURCE})
target_compile_definitions(udflib PRIVATE _USRDLL)
add_dependencies(udflib psdk)
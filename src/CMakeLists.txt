cmake_minimum_required(VERSION 3.10)

set(SRC_LIST main.c)
set(LIB_LIST ot_client.c ot_context.c ot_server.c ot_packet.c tk.c ht.c otfile_utils.c)

add_library(ot_core STATIC ${LIB_LIST})

foreach(SRC_FILE ${SRC_LIST})
  get_filename_component(TGT_NAME ${SRC_FILE} NAME_WE)
  add_executable(${TGT_NAME} ${SRC_FILE})
  target_link_libraries(${TGT_NAME} PRIVATE ot_core)
endforeach()


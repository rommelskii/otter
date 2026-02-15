set(TEST_SRC_LIST test_srv_runtime.c test_srv.c test_pkt.c)

include_directories(include)

foreach(SRC_FILE ${TEST_SRC_LIST})
  get_filename_component(TGT_NAME ${SRC_FILE} NAME_WE)
  add_executable(${TGT_NAME} ${SRC_FILE})
  target_link_libraries(${TGT_NAME} PRIVATE ot_core)
endforeach()

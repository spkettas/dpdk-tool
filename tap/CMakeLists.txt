project(tap)

get_filename_component(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/" ABSOLUTE)

add_executable(tap
  ${SRC_DIR}/main.c
)

target_link_libraries(tap
 ${DPDK_LIBS}
)

target_link_libraries(tap
   pthread
   crypto 
   elf 
   m 
   dl 
   numa 
   pcap
   z
 )

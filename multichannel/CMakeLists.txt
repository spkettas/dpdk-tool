project(multichannel)

get_filename_component(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/" ABSOLUTE)

add_executable(multichannel
  ${SRC_DIR}/main.c
)

target_link_libraries(multichannel
 ${DPDK_LIBS}
)

target_link_libraries(multichannel
   pthread
   crypto 
   elf 
   m 
   dl 
   numa 
   pcap
   z
 )

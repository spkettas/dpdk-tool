project(kni)

get_filename_component(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/" ABSOLUTE)

add_executable(kni
  ${SRC_DIR}/main.c
)

target_link_libraries(kni
 ${DPDK_LIBS}
)

target_link_libraries(kni
   pthread
   crypto 
   elf 
   m 
   dl 
   numa 
   pcap
   z
 )

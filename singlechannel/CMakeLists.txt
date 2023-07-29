project(singlechannel)

get_filename_component(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/" ABSOLUTE)

# simple
add_executable(simple
  ${SRC_DIR}/simple.c
)

target_link_libraries(simple
 ${DPDK_LIBS}
)

target_link_libraries(simple
   pthread
   crypto 
   elf 
   m 
   dl 
   numa 
   pcap
   z
 )

# simple channel
add_executable(singlechannel
  ${SRC_DIR}/main.c
)

target_link_libraries(singlechannel
 ${DPDK_LIBS}
)

target_link_libraries(singlechannel
   pthread
   crypto 
   elf 
   m 
   dl 
   numa 
   pcap
   z
 )

project(singlechannel)

get_filename_component(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/" ABSOLUTE)

add_executable(singlechannel
  ${SRC_DIR}/main.c
)

target_link_libraries(singlechannel
 ${DPDK_LIBS}
)

# mlnx
# target_link_libraries(${TARGET}
#     ${DPDK_MLX_LIBS}
#     mlx5 
#     ibverbs
#   )

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

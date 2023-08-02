project(kni)

get_filename_component(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/" ABSOLUTE)

function(build_kni name file)
  set(TARGET ${name})
  add_executable(${TARGET}
    ${SRC_DIR}/${file}
  )

  target_link_libraries(${TARGET}
  ${DPDK_LIBS}
  )

  target_link_libraries(${TARGET}
    pthread
    crypto 
    elf 
    m 
    dl 
    numa 
    pcap
    z
  )
endfunction()

build_kni(kni_send kni_send.c)
build_kni(kni_recv kni_recv.c)

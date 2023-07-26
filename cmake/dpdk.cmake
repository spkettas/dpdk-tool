set(MSG_PRE "[dpdk]")

if (DEFINED ENV{RTE_SDK})
    set(RTE_SDK $ENV{RTE_SDK})
else()
    set(RTE_SDK "/usr/local/dpdk")
endif()

if (DEFINED ENV{RTE_TARGET})
    set(RTE_TARGET $ENV{RTE_TARGET})
else()
    set(RTE_TARGET x86_64-native-linuxapp-gcc)
endif()

# file(STRINGS "${RTE_SDK}/VERSION" RTE_VERSION)
message(STATUS "${MSG_PRE} Using RTE_SDK=${RTE_SDK}")
message(STATUS "${MSG_PRE} Using RTE_TARGET=${RTE_TARGET}")

set(RTE_LIBRARIES librte_node.a librte_graph.a librte_bpf.a librte_flow_classify.a 
    librte_pipeline.a librte_table.a librte_port.a librte_fib.a librte_ipsec.a librte_vhost.a 
    librte_stack.a librte_security.a librte_sched.a librte_reorder.a librte_rib.a 
    librte_regexdev.a librte_rawdev.a librte_pdump.a librte_power.a librte_member.a 
    librte_lpm.a librte_latencystats.a librte_kni.a librte_jobstats.a librte_ip_frag.a 
    librte_gso.a librte_gro.a librte_eventdev.a librte_efd.a librte_distributor.a 
    librte_cryptodev.a librte_compressdev.a librte_cfgfile.a librte_bitratestats.a 
    librte_bbdev.a librte_acl.a librte_timer.a librte_hash.a librte_metrics.a 
    librte_cmdline.a librte_pci.a librte_ethdev.a librte_meter.a librte_net.a 
    librte_mbuf.a librte_mempool.a librte_rcu.a librte_ring.a librte_eal.a 
    librte_telemetry.a librte_kvargs.a librte_common_cpt.a librte_common_dpaax.a 
    librte_common_iavf.a librte_common_octeontx.a librte_common_octeontx2.a 
    librte_common_sfc_efx.a librte_bus_dpaa.a librte_bus_fslmc.a librte_bus_ifpga.a 
    librte_bus_pci.a librte_bus_vdev.a librte_bus_vmbus.a 
    librte_common_qat.a librte_mempool_bucket.a librte_mempool_dpaa.a 
    librte_mempool_dpaa2.a librte_mempool_octeontx.a librte_mempool_octeontx2.a 
    librte_mempool_ring.a librte_mempool_stack.a librte_net_af_packet.a 
    librte_net_ark.a librte_net_atlantic.a librte_net_avp.a librte_net_axgbe.a 
    librte_net_bond.a librte_net_bnx2x.a librte_net_bnxt.a librte_net_cxgbe.a 
    librte_net_dpaa.a librte_net_dpaa2.a librte_net_e1000.a librte_net_ena.a 
    librte_net_enetc.a librte_net_enic.a librte_net_failsafe.a librte_net_fm10k.a 
    librte_net_i40e.a librte_net_hinic.a librte_net_hns3.a librte_net_iavf.a 
    librte_net_ice.a librte_net_igc.a librte_net_ixgbe.a librte_net_kni.a 
    librte_net_liquidio.a librte_net_memif.a librte_net_netvsc.a 
    librte_net_nfp.a librte_net_null.a librte_net_octeontx.a librte_net_octeontx2.a 
    librte_net_pfe.a librte_net_qede.a librte_net_ring.a librte_net_sfc.a librte_net_softnic.a 
    librte_net_tap.a librte_net_thunderx.a librte_net_txgbe.a librte_net_vdev_netvsc.a librte_net_vhost.a 
    librte_net_virtio.a librte_net_vmxnet3.a librte_raw_dpaa2_cmdif.a librte_raw_dpaa2_qdma.a librte_raw_ioat.a 
    librte_raw_ntb.a librte_raw_octeontx2_dma.a librte_raw_octeontx2_ep.a librte_raw_skeleton.a 
    librte_crypto_bcmfs.a librte_crypto_caam_jr.a librte_crypto_ccp.a librte_crypto_dpaa_sec.a 
    librte_crypto_dpaa2_sec.a librte_crypto_nitrox.a librte_crypto_null.a librte_crypto_octeontx.a 
    librte_crypto_octeontx2.a librte_crypto_openssl.a librte_crypto_scheduler.a librte_crypto_virtio.a 
    librte_compress_octeontx.a librte_compress_zlib.a librte_regex_octeontx2.a 
    librte_vdpa_ifc.a librte_event_dlb.a librte_event_dlb2.a librte_event_dpaa.a 
    librte_event_dpaa2.a librte_event_octeontx2.a librte_event_opdl.a librte_event_skeleton.a 
    librte_event_sw.a librte_event_dsw.a librte_event_octeontx.a librte_baseband_null.a 
    librte_baseband_turbo_sw.a librte_baseband_fpga_lte_fec.a librte_baseband_fpga_5gnr_fec.a librte_baseband_acc100.a)

set(RTE_MLXS librte_vdpa_mlx5.a librte_common_mlx5.a librte_net_mlx5.a librte_regex_mlx5.a)

set(DPDK_COM_LIB "")
set(DPDK_MLX_LIB "")

# common
foreach(handle ${RTE_LIBRARIES})
    find_library(LIB_DPDK_RTE_${handle} ${handle} HINTS ${RTE_SDK}/lib64)

    if(NOT LIB_DPDK_RTE_${handle})
        message(FATAL_ERROR "${MSG_PRE} ${handle} not found")
    endif()

    list(APPEND DPDK_COM_LIB "${LIB_DPDK_RTE_${handle}}")
    #message(STATUS "${MSG_PRE} Found ${handle}: ${LIB_DPDK_RTE_${handle}}")
endforeach()

# mlx
foreach(handle ${RTE_MLXS})
    find_library(LIB_DPDK_RTE_${handle} ${handle} HINTS ${RTE_SDK}/lib64)

    if(NOT LIB_DPDK_RTE_${handle})
        message(FATAL_ERROR "${MSG_PRE} ${handle} not found")
    endif()

    list(APPEND DPDK_MLX_LIB "${LIB_DPDK_RTE_${handle}}")
    #message(STATUS "${MSG_PRE} Found ${handle}: ${LIB_DPDK_RTE_${handle}}")
endforeach()

# replace
set(_DPDK_COM_LIB ${DPDK_COM_LIB})
string(REPLACE ";" " " DPDK_COM_LIB "${_DPDK_COM_LIB}")

set(_DPDK_MLX_LIB ${DPDK_MLX_LIB})
string(REPLACE ";" " " DPDK_MLX_LIB "${_DPDK_MLX_LIB}")

set(GROUP_START "-Wl,--as-needed -Wl,--no-undefined -Wl,-O1 -Wl,--whole-archive -Wl,--start-group")
set(GROUP_END "-Wl,--no-whole-archive -Wl,--end-group")

# export
set(DPDK_INCLUDE ${RTE_SDK}/include)
set(DPDK_LIBS "${GROUP_START} ${DPDK_COM_LIB} ${GROUP_END}")
set(DPDK_MLX_LIBS "${GROUP_START} ${DPDK_COM_LIB} ${DPDK_MLX_LIB} ${GROUP_END}")

message(STATUS "${MSG_PRE} DPDK_INCLUDE and DPDK_LIBS set")
# message(STATUS "${MSG_PRE} ${DPDK_LIBS}")

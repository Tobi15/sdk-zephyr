/** @file
 *  @brief Bluetooth Mesh Profile APIs.
 */

/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ZEPHYR_INCLUDE_BLUETOOTH_MESH_H_
#define ZEPHYR_INCLUDE_BLUETOOTH_MESH_H_

#include <stddef.h>

#include <zephyr/types.h>
#include <zephyr/net/buf.h>

#include <zephyr/bluetooth/mesh/keys.h>
#include <zephyr/bluetooth/mesh/msg.h>
#include <zephyr/bluetooth/mesh/access.h>
#include <zephyr/bluetooth/mesh/main.h>
#include <zephyr/bluetooth/mesh/cfg.h>
#include <zephyr/bluetooth/mesh/cfg_srv.h>
#include <zephyr/bluetooth/mesh/health_srv.h>
#include <zephyr/bluetooth/mesh/blob_srv.h>
#include <zephyr/bluetooth/mesh/cfg_cli.h>
#include <zephyr/bluetooth/mesh/health_cli.h>
#include <zephyr/bluetooth/mesh/blob_cli.h>
#include <zephyr/bluetooth/mesh/blob_io_flash.h>
#include <zephyr/bluetooth/mesh/priv_beacon_srv.h>
#include <zephyr/bluetooth/mesh/priv_beacon_cli.h>
#include <zephyr/bluetooth/mesh/dfu_srv.h>
#include <zephyr/bluetooth/mesh/dfd_srv.h>
#include <zephyr/bluetooth/mesh/dfu_cli.h>
#include <zephyr/bluetooth/mesh/dfu_metadata.h>
#include <zephyr/bluetooth/mesh/proxy.h>
#include <zephyr/bluetooth/mesh/heartbeat.h>
#include <zephyr/bluetooth/mesh/cdb.h>
#include <zephyr/bluetooth/mesh/rpr_cli.h>
#include <zephyr/bluetooth/mesh/rpr_srv.h>
#include <zephyr/bluetooth/mesh/sar_cfg_srv.h>
#include <zephyr/bluetooth/mesh/sar_cfg_cli.h>
#include <zephyr/bluetooth/mesh/op_agg_srv.h>
#include <zephyr/bluetooth/mesh/op_agg_cli.h>
#include <zephyr/bluetooth/mesh/large_comp_data_srv.h>
#include <zephyr/bluetooth/mesh/large_comp_data_cli.h>
#include <zephyr/bluetooth/mesh/od_priv_proxy_srv.h>
#include <zephyr/bluetooth/mesh/od_priv_proxy_cli.h>
#include <zephyr/bluetooth/mesh/sol_pdu_rpl_srv.h>
#include <zephyr/bluetooth/mesh/sol_pdu_rpl_cli.h>
#include <zephyr/bluetooth/mesh/statistic.h>

/**
 * @brief Callback function type for auxiliary scan events.
 *
 * @param addr The Bluetooth LE address of the device.
 * @param rssi The RSSI value of the received advertisement.
 * @param buf  The buffer containing advertisement data.
 */
typedef void (*bt_mesh_aux_scan_cb_t)(const bt_addr_le_t *addr, int8_t rssi, struct net_buf_simple *buf);

/**
 * @brief Register a callback for auxiliary scan events.
 *
 * @param adv_type The advertisement type to filter.
 * @param cb       The callback function to invoke for matching advertisements.
 */
void bt_mesh_register_aux_scan_cb(uint8_t adv_type, bt_mesh_aux_scan_cb_t cb);

/**
 * @brief Unregister a callback for auxiliary scan events.
 *
 */
void bt_mesh_unregister_aux_scan_cb();

#endif /* ZEPHYR_INCLUDE_BLUETOOTH_MESH_H_ */

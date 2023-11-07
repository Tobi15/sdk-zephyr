/*********************************************************************************
 * @copyright (c) 2023 University of Applied Sciences and Arts Western Switzerland
 * All rights reserved.
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited.
 * Proprietary and confidential
 *********************************************************************************
 * Project : HEIA-FR / tm_ble-mesh_dect-2020
 * @file   : net_hbh_impl.c
 * @brief  :
 * @date   : 06.11.2023
 * @author : Louka Yerly (louka.yerly@gmail.com)
 ********************************************************************************/

#include <zephyr/kernel.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/util.h>
#include <zephyr/sys/byteorder.h>

#include <zephyr/net/buf.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/addr.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/mesh.h>

#include "common/bt_str.h"

#include "crypto.h"
#include "adv.h"
#include "mesh.h"
#include "net.h"
#include "rpl.h"
#include "lpn.h"
#include "friend.h"
#include "proxy.h"
#include "proxy_cli.h"
#include "transport.h"
#include "access.h"
#include "foundation.h"
#include "beacon.h"
#include "settings.h"
#include "prov.h"
#include "cfg.h"


#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(bt_mesh_net_hbh_impl);

/*
struct msg_id {
    uint32_t src: 15, seq: 17;
};
*/
#define BT_MESH_NET_HBH_RTO_SECS 2
#define BT_MESH_NET_HBH_MSG_CACHE_TIMEOUT_MSEC 10*1000
#define BT_MESH_NET_HBH_MAX_RETRANSMISSION 10

struct net_hbh_item {
    bt_addr_le_t src;
    union {
        struct bt_mesh_net_rx rx;
        struct bt_mesh_net_tx tx;
    };
    uint8_t data_buffer[BT_MESH_NET_MAX_PDU_LEN];
    struct net_buf_simple data_decoded;
    uint8_t transmit_number;
    int64_t recv_timestamp;
    bool acked;
    bool free;
    struct k_work_delayable dwork;
};

static struct net_hbh_item net_hbh_item_arr[10] = {
    [0] = {
        .free = true,
    },
    [1] = {
        .free = true,
    },
    [2] = {
        .free = true,
    },
    [3] = {
        .free = true,
    },
    [4] = {
        .free = true,
    },
    [5] = {
        .free = true,
    },
    [6] = {
        .free = true,
    },
    [7] = {
        .free = true,
    },
    [8] = {
        .free = true,
    },
    [9] = {
        .free = true,
    },
};


static void bt_mesh_net_hbh_free_item(struct net_hbh_item *item) {
    item->free = true;
}

static void bt_mesh_net_hbh_get_free_item(struct net_hbh_item* *item) {
    for(int i=0; i<ARRAY_SIZE(net_hbh_item_arr); i++) {
        struct net_hbh_item* item_curr = &net_hbh_item_arr[i];

        if(item_curr->free) {
            *item = item_curr;
            return;
        }
    }

    *item = NULL;
}


static void retransmit(struct k_work *work) {
    printk("Called\n");

    struct k_work_delayable *dwork = k_work_delayable_from_work(work);
    struct net_hbh_item *item = CONTAINER_OF(dwork, struct net_hbh_item, dwork);

    if(k_uptime_delta(&item->recv_timestamp) > BT_MESH_NET_HBH_MSG_CACHE_TIMEOUT_MSEC
        || item->transmit_number >= BT_MESH_NET_HBH_MAX_RETRANSMISSION) {
        // free the msg as he exceded the life time
        printk("free item\n");
        bt_mesh_net_hbh_free_item(item);
        return;
    }
    // TODO: maybe set the sequence number to a new value

    printk("Transmit\n");
    item->transmit_number++;
    bt_mesh_net_relay(&item->data_decoded, &item->rx);


    if(bt_mesh_has_addr(item->rx.ctx.recv_dst)) {
        // It is the last node, he will never receive an ACK
        k_work_reschedule(dwork, K_MSEC(BT_MESH_NET_HBH_MSG_CACHE_TIMEOUT_MSEC));
    } else {
        k_work_reschedule(dwork, K_SECONDS(BT_MESH_NET_HBH_RTO_SECS));
    }
}

/**
 * @brief 
 * 
 * @param recv_item 
 * @param cached NULL if recv_item is not cached
 */
static void bt_mesh_net_hbh_is_msg_cached(struct net_hbh_item *recv_item, struct net_hbh_item* *cached) {

    for(int i=0; i<ARRAY_SIZE(net_hbh_item_arr); i++) {
        struct net_hbh_item* item = &net_hbh_item_arr[i];

        if(!item->free &&
            item->rx.seq == recv_item->rx.seq &&
                item->rx.ctx.addr == recv_item->rx.ctx.addr) {
            *cached = item;
            return;
        }
    }

    *cached = NULL;
}

static bool bt_mesh_net_hbh_is_iack(struct net_hbh_item *recv_item) {

    for(int i=0; i<ARRAY_SIZE(net_hbh_item_arr); i++) {
        struct net_hbh_item* item = &net_hbh_item_arr[i];

        if(!item->free &&
            bt_addr_le_cmp(&item->src, &recv_item->src) != 0 &&
            item->rx.seq == recv_item->rx.seq &&
                item->rx.ctx.addr == recv_item->rx.ctx.addr) {
            // message is in cache but received by another device than the first one
            // so, it is an iack
            return true;
        }
    }

    return false;
}


void bt_mesh_net_hbh_create_item(struct net_hbh_item *item, 
                                 struct bt_mesh_net_rx *rx,
                                 struct net_buf_simple *buf) {

    item->free = false;

    memcpy(&item->src, rx->bt_addr, sizeof(bt_addr_le_t));
    
    memcpy(&item->rx, rx, sizeof(struct bt_mesh_net_rx));
    


    item->data_decoded.len = buf->len;
    item->data_decoded.size = sizeof(item->data_buffer);
    item->data_decoded.data = item->data_buffer;
    item->data_decoded.__buf = item->data_buffer;
    memcpy(item->data_decoded.data, buf->data, buf->len);

    item->acked = false;

    item->transmit_number = 0;

    item->recv_timestamp = k_uptime_get();

    k_work_init_delayable(&item->dwork, retransmit); 
}


static void bt_mesh_net_hbh_free_expired() {
    for(int i=0; i<ARRAY_SIZE(net_hbh_item_arr); i++) {
        struct net_hbh_item* item = &net_hbh_item_arr[i];

        bool expired = k_uptime_delta(&item->recv_timestamp) > BT_MESH_NET_HBH_MSG_CACHE_TIMEOUT_MSEC;
        
        if(expired) {
            printk("Remove expired packet\n");
            bt_mesh_net_hbh_free_item(item);
        }
    }
}

void print_packet_info(struct net_hbh_item *item) {
    char src[BT_ADDR_LE_STR_LEN+1] = {0};
    bt_addr_le_to_str(&item->src, src, sizeof(src)-1);
    
    printk("packet_info:\n\
\taddr: %s\n\
\tmesh_src: %#04x, mesh_dst: %#04x\n\
\tseq: %i\n\
",
src, item->rx.ctx.addr, item->rx.ctx.recv_dst, item->rx.seq);
}

void bt_mesh_net_hbh_recv(struct bt_mesh_net_rx *rx,
                          struct net_buf_simple *buf) {

    //printk("sizeof(item)=%i\n", sizeof(struct net_hbh_item));
    //bt_mesh_net_hbh_free_expired();

    printk("src: %#04x, dst: %#04x\n", rx->ctx.addr, rx->ctx.recv_dst);

    static struct net_hbh_item recv_item;

    bt_mesh_net_hbh_create_item(&recv_item, rx, buf);
    
    struct net_hbh_item *cached = NULL;
    bt_mesh_net_hbh_is_msg_cached(&recv_item, &cached);
    if(cached == NULL) {
        // add new message
        bt_mesh_net_hbh_get_free_item(&cached);
        if(cached == NULL) {
            printk("No more space to stock data... wait another transmit\n");
            return;
        }
        bt_mesh_net_hbh_create_item(cached, &recv_item.rx, &recv_item.data_decoded);
        printk("(new message)\n");
        print_packet_info(cached);
        k_work_reschedule(&cached->dwork, K_NO_WAIT);
        return;
    }

    if(bt_mesh_net_hbh_is_iack(&recv_item)) {
        // set message as acked
        cached->acked = true;
        int64_t remaining = BT_MESH_NET_HBH_MSG_CACHE_TIMEOUT_MSEC-(k_uptime_get()-cached->recv_timestamp);
        printk("(set message acked)\n");
        print_packet_info(cached);
        k_work_reschedule(&cached->dwork, K_MSEC(remaining));
        return;
    }
    
    // message is a retransmission of the sender. Need to send and Oriented-iACK
    printk("(need to send iack)\n");
    print_packet_info(cached);
    k_work_reschedule(&cached->dwork, K_NO_WAIT);    
}


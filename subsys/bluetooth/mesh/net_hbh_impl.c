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


#define BT_MESH_NET_HBH_RTO_SECS 2
#define BT_MESH_NET_HBH_MSG_CACHE_TIMEOUT_MSEC 10*1000
#define BT_MESH_NET_HBH_MAX_RETRANSMISSION 10


struct net_hbh_item {
    struct bt_mesh_net_rx rx;
    union {
        struct {
            uint8_t data_buffer[BT_MESH_NET_MAX_PDU_LEN];
            struct net_buf_simple data_decoded;
        };
        struct net_buf *tx_buf;
    };
    uint8_t transmit_number;
    int64_t recv_timestamp;
    bool is_src;
    bool acked;
	atomic_t is_free;
    struct k_work_delayable dwork;
};
static struct net_hbh_item net_hbh_item_arr[10];
#define ITEM_FREE ((atomic_val_t)1)
#define ITEM_USED ((atomic_val_t)0)
#define IS_ITEM_FREE(x)  (atomic_get(&x->is_free) == ITEM_FREE)
#define SET_ITEM_USED(x) (atomic_set(&x->is_free, ITEM_USED))
#define SET_ITEM_FREE(x) (atomic_set(&x->is_free, ITEM_FREE))



static void bt_mesh_net_hbh_free_item(struct net_hbh_item *item) {
	printk("free item\n");
	if(item->is_src) {
        printk("unref buffer\n");
        net_buf_unref(item->tx_buf);
    }
    SET_ITEM_FREE(item);
}

static void bt_mesh_net_hbh_get_free_item(struct net_hbh_item* *item) {
    for(int i=0; i<ARRAY_SIZE(net_hbh_item_arr); i++) {
        struct net_hbh_item* item_curr = &net_hbh_item_arr[i];
		
		if(IS_ITEM_FREE(item_curr)) {
            SET_ITEM_USED(item_curr);
            *item = item_curr;
            return;
        }
    }

    *item = NULL;
}


static void retransmit(struct k_work *work) {
    
    struct k_work_delayable *dwork = k_work_delayable_from_work(work);
    struct net_hbh_item *item = CONTAINER_OF(dwork, struct net_hbh_item, dwork);
    
    if(k_uptime_delta(&item->recv_timestamp) > BT_MESH_NET_HBH_MSG_CACHE_TIMEOUT_MSEC ||
		item->transmit_number >= BT_MESH_NET_HBH_MAX_RETRANSMISSION) {
        
		// free the msg as he exceded the life time
        bt_mesh_net_hbh_free_item(item);
        return;
    }
    
    item->transmit_number++;

    if(item->is_src) {
        LOG_ERR("idx %i, buf %p", ARRAY_INDEX(net_hbh_item_arr, item), item->tx_buf);
        bt_mesh_adv_send(item->tx_buf, NULL, NULL);
    } else {
        bt_mesh_net_relay(&item->data_decoded, &item->rx);
    }
    


    if(bt_mesh_has_addr(item->rx.ctx.recv_dst)) {
        // It is the last node, he will never receive an ACK
        // TODO: reshedule with delta
        k_work_reschedule(dwork, K_MSEC(BT_MESH_NET_HBH_MSG_CACHE_TIMEOUT_MSEC));
    } else {
        k_work_reschedule(dwork, K_SECONDS(BT_MESH_NET_HBH_RTO_SECS));
    }
}

static void bt_mesh_net_hbh_is_msg_cached(struct net_hbh_item *recv_item, struct net_hbh_item* *cached) {

    for(int i=0; i<ARRAY_SIZE(net_hbh_item_arr); i++) {
        struct net_hbh_item* item = &net_hbh_item_arr[i];

        if(!IS_ITEM_FREE(item) &&
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

        if(!IS_ITEM_FREE(item) &&
            bt_addr_le_cmp(&item->rx.bt_addr, &recv_item->rx.bt_addr) != 0 &&
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

	SET_ITEM_USED(item);
	
    item->is_src = false;

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


/*
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
*/

void print_packet_info(struct net_hbh_item *item) {
    return;
    char src[BT_ADDR_LE_STR_LEN+1] = {0};
    bt_addr_le_to_str(&item->rx.bt_addr, src, sizeof(src)-1);
    
    printk("packet_info:\n\
\taddr: %s\n\
\tmesh_src: %#04x, mesh_dst: %#04x\n\
\tseq: %i\n\
",
src, item->rx.ctx.addr, item->rx.ctx.recv_dst, item->rx.seq);
}

void bt_mesh_net_hbh_send(struct bt_mesh_net_tx *tx,
                          struct net_buf *buf,
                          uint32_t seq) {
    printk("New data to send\n");

    // Obviously not in the cache so no need to check
    struct net_hbh_item *item = NULL;
    bt_mesh_net_hbh_get_free_item(&item);

    if(item == NULL) {
		// WARNING: Fail silently
        LOG_ERR("No more space to stock data... wait another transmit\n");
        return;
    }

    item->is_src = true;
    item->acked = false;

    item->recv_timestamp = k_uptime_get();


    size_t count = 1;
    
	// HARDCODED: take the first possible address... Maybe it's another
	bt_id_get(&item->rx.bt_addr, &count);
    char addr_str[BT_ADDR_LE_STR_LEN+1] = {0};
    bt_addr_le_to_str(&item->rx.bt_addr, addr_str, sizeof(addr_str)-1);
    printk("id: %s\n", addr_str);
    
    // already send by the BT TX thread the first time
    item->transmit_number = 1;

    
    item->rx.ctx.addr     = tx->src;
    item->rx.ctx.recv_dst = tx->ctx->addr;
    item->rx.seq          = seq;

    
    item->tx_buf = net_buf_ref(buf);

    LOG_ERR("idx %i, buf %p", ARRAY_INDEX(net_hbh_item_arr, item), item->tx_buf);

    print_packet_info(item);

    k_work_init_delayable(&item->dwork, retransmit);
    k_work_reschedule(&item->dwork, K_SECONDS(BT_MESH_NET_HBH_RTO_SECS));
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
        if(cached->acked) {
            // possible if a ack is already received
            return;
        }
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



void bt_mesh_net_hbh_init() {
	printk("\n\n\nINITIALIZE HBH\n\n\n");
	for(int i=0; i<ARRAY_SIZE(net_hbh_item_arr); i++) {
		struct net_hbh_item* item = &net_hbh_item_arr[i];

		SET_ITEM_FREE(item);
	}
}


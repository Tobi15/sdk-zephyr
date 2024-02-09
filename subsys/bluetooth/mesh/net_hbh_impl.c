/*********************************************************************************
 * @copyright (c) 2023 University of Applied Sciences and Arts Western Switzerland
 * All rights reserved.
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited.
 * Proprietary and confidential
 *********************************************************************************
 * Project : HEIA-FR / tm_ble-mesh_dect-2020
 * @file   : net_hbh_impl.c
 * @brief  : Implementation of the HBH retransmission protocol
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

#define SEQ(pdu) (sys_get_be24(&pdu[2]))

#define BT_MESH_NET_HBH_RTO_MSEC (300+(2-1)*50)
static uint8_t bt_mesh_net_hbh_retransmission = 10;
#define BT_MESH_NET_HBH_MAX_HOP_DELAY_MSEC 60
#define BT_MESH_NET_HBH_MSG_CACHE_TIMEOUT_MSEC ((BT_MESH_NET_HBH_RTO_MSEC*\
												((int64_t)bt_mesh_net_hbh_retransmission))*2\
												+ BT_MESH_NET_HBH_MAX_HOP_DELAY_MSEC*2)

struct net_hbh_item {
	struct bt_mesh_net_rx rx;
	struct net_buf *tx_buf;

	int64_t recv_timestamp;
	uint8_t transmit_number: 6, /* [0;63] transmission possible */
			acked:1,			/* is the message acked */
			item_free: 1;		/* is the item free*/
	
	struct k_mutex item_mut;
	struct k_work_delayable dwork;
};
static struct net_hbh_item net_hbh_item_arr[CONFIG_BT_MESH_ADV_BUF_COUNT + CONFIG_BT_MESH_RELAY_BUF_COUNT];
atomic_t bt_mesh_net_hbh_number_of_transmission = ATOMIC_INIT(0);


#define ITEM_FREE (true)
#define ITEM_USED (false)
#define ITEM_LOCK(x) (k_mutex_lock(&x->item_mut, K_FOREVER))
#define ITEM_UNLOCK(x) (k_mutex_unlock(&x->item_mut))

static inline int64_t item_get_timestamp(struct net_hbh_item *item) {
	int64_t res;
	k_mutex_lock(&item->item_mut, K_FOREVER);
	res = item->recv_timestamp;
	k_mutex_unlock(&item->item_mut);
	return res;
}

static inline void item_set_timestamp(struct net_hbh_item *item, int64_t val) {
	k_mutex_lock(&item->item_mut, K_FOREVER);
	item->recv_timestamp = val;
	k_mutex_unlock(&item->item_mut);
}

static inline int64_t item_get_timestamp_delta(struct net_hbh_item *item) {
	int64_t ref = item_get_timestamp(item);
	return k_uptime_delta(&ref);
}

static inline bool item_is_item_free(struct net_hbh_item *item) {
	bool res;
	k_mutex_lock(&item->item_mut, K_FOREVER);
	res = item->item_free;
	k_mutex_unlock(&item->item_mut);
	return res;
}

static inline void item_set_item_free(struct net_hbh_item *item, bool val) {
	k_mutex_lock(&item->item_mut, K_FOREVER);
	item->item_free = val & 0x1; /* one bit field */
	k_mutex_unlock(&item->item_mut);
}
static inline int64_t item_get_remaining_time_msec(struct net_hbh_item *item) {
	/* +1 to avoid timing race */
	return BT_MESH_NET_HBH_MSG_CACHE_TIMEOUT_MSEC-item_get_timestamp_delta(item)+1;
}

static void print_packet_info(struct net_hbh_item *item) {
	char src[BT_ADDR_LE_STR_LEN+1] = {0};
	bt_addr_le_to_str(&item->rx.bt_addr, src, sizeof(src)-1);
	
	LOG_DBG("packet_info:\n\
\taddr: %s\n\
\tmesh_src: %#04x, mesh_dst: %#04x\n\
\tseq: %i (iack=%i)\
",
	src, item->rx.ctx.addr, item->rx.ctx.recv_dst, item->rx.seq, item->rx.iack_bit);
}


static void bt_mesh_net_hbh_free_item(struct net_hbh_item *item) {
	LOG_DBG("Free item (tx_buf: %p, src: %x, seq: %i, remaining: %lli, after: %lli",
		item->tx_buf,
		item->rx.ctx.addr,
		item->rx.seq,
		item_get_remaining_time_msec(item), item_get_timestamp_delta(item));

	ITEM_LOCK(item);
	{
		if(item->tx_buf->ref > 0) net_buf_unref(item->tx_buf);
		item_set_item_free(item, ITEM_FREE);
	}
	ITEM_UNLOCK(item);
}

static void bt_mesh_net_hbh_get_free_item(struct net_hbh_item* *item) {
	for(int i=0; i<ARRAY_SIZE(net_hbh_item_arr); i++) {
		struct net_hbh_item* item_curr = &net_hbh_item_arr[i];
		
		if(item_is_item_free(item_curr)) {
			item_set_item_free(item_curr, ITEM_USED);
			*item = item_curr;
			return;
		}
	}

	*item = NULL;
}

static void callback(int err, void* cb_data) {
	struct net_hbh_item *item = (struct net_hbh_item*)cb_data;
	ITEM_LOCK(item);
	{
		LOG_DBG("err %i", err);
	}
	ITEM_UNLOCK(item);
}

static const struct bt_mesh_send_cb cb = {
	.start = NULL,
	.end = callback,
};

static void retransmit(struct k_work *work) {
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct net_hbh_item *item = CONTAINER_OF(dwork, struct net_hbh_item, dwork);
	
	if(item_get_timestamp_delta(item) >= BT_MESH_NET_HBH_MSG_CACHE_TIMEOUT_MSEC) {
		LOG_DBG("delta: %lli, timeout: %lli", item_get_timestamp_delta(item), BT_MESH_NET_HBH_MSG_CACHE_TIMEOUT_MSEC);
		/* Free the msg as he exceded the life time */
		bt_mesh_net_hbh_free_item(item);
		return;
	}

	if(item->transmit_number >= bt_mesh_net_hbh_retransmission) {
		k_work_reschedule(dwork, K_MSEC(item_get_remaining_time_msec(item)));
		return;
	}

	bool acked = false;
	ITEM_LOCK(item);
	{
		if(item->tx_buf->data == NULL || item->tx_buf->ref == 0) {
			LOG_ERR("Data in tx_buf not valid");
			print_packet_info(item);
			bt_mesh_net_hbh_free_item(item);
			ITEM_UNLOCK(item);
			return;
		} else if(atomic_get(&BT_MESH_ADV(item->tx_buf)->busy)) {
			/* Message is currently in queue to be send. Wait for another attempt */
			k_work_reschedule(dwork, K_MSEC(BT_MESH_NET_HBH_RTO_MSEC));
			ITEM_UNLOCK(item);
			return;
		}
		acked = item->acked;
		item->transmit_number++;
		atomic_inc(&bt_mesh_net_hbh_number_of_transmission);
		LOG_DBG("idx %i, buf %p", ARRAY_INDEX(net_hbh_item_arr, item), item->tx_buf);
		bt_mesh_adv_send(item->tx_buf, &cb, (void*)item);
	}
	ITEM_UNLOCK(item);
	
	if(acked) {
		/* He will never receive an ACK when the message is acked */
		k_work_reschedule(dwork, K_MSEC(item_get_remaining_time_msec(item)));
	} else {
		k_work_reschedule(dwork, K_MSEC(BT_MESH_NET_HBH_RTO_MSEC));
	}
}

static void bt_mesh_net_hbh_is_msg_cached(struct bt_mesh_net_rx *rx, struct net_hbh_item* *cached) {

	for(int i=0; i<ARRAY_SIZE(net_hbh_item_arr); i++) {
		struct net_hbh_item* item = &net_hbh_item_arr[i];

		if(!item_is_item_free(item) &&
			item->rx.seq == rx->seq &&
				item->rx.ctx.addr == rx->ctx.addr) {
			*cached = item;
			return;
		}
	}

	*cached = NULL;
}

static bool bt_mesh_net_hbh_is_iack(struct bt_mesh_net_rx *rx, struct net_hbh_item *item) {

	if(!item_is_item_free(item) &&
		bt_addr_le_cmp(&item->rx.bt_addr, &rx->bt_addr) != 0 &&
			item->rx.seq == rx->seq && item->rx.ctx.addr == rx->ctx.addr) {
		/* Message is in cache but received by another device than the first one
		 * so, it is an iack 
		 */
		return true;
	}

	return false;
}


static void bt_mesh_net_hbh_create_item(struct net_hbh_item **item, 
								 struct bt_mesh_net_rx *rx,
								 struct net_buf *buf) {
	
	bt_mesh_net_hbh_get_free_item(item);

	/* No more space */
	if(*item == NULL) return;

	struct net_hbh_item *init_item = *item;

	ITEM_LOCK(init_item);
	{
		memcpy(&init_item->rx, rx, sizeof(struct bt_mesh_net_rx));

		if(buf == NULL) {
			print_packet_info(init_item);
			LOG_ERR("ADV buf is NULL");
			return;
		}

		if(bt_mesh_has_addr(init_item->rx.ctx.recv_dst)) {
			/* This is the destination. It will never receive an ack */
			init_item->acked = true;
		} else {
			init_item->acked = false;
		}
		
		init_item->tx_buf = net_buf_ref(buf);

		init_item->transmit_number = 0;

		item_set_timestamp(init_item, k_uptime_get());

	}
	ITEM_UNLOCK(init_item);
}


void bt_mesh_net_hbh_check_iack(struct bt_mesh_net_rx *rx,
						  struct net_buf_simple *buf) {
	/* check if iack is set */
	rx->iack_bit = (SEQ(buf->data) & BIT(23))>0;
	
	if(rx->iack_bit) {
		LOG_DBG("IACK BIT SET");
		buf->data[2] &= ~BIT(7);
	}
	
}


static void bt_mesh_net_hbh_set_iack(struct net_hbh_item *item) {
	ITEM_LOCK(item);
	{
		/* Byte 2 contains MSB of SEQ number */
		item->tx_buf->data[2] |= BIT(7);
	}
	ITEM_UNLOCK(item);
}

void static inline bt_mesh_net_hbh_copy_addr(struct bt_mesh_net_rx *rx) {
	if(CONFIG_BT_ID_MAX > 1) {
		LOG_ERR("Possibly selecting the wrong address as there is %i bt_addr_le possible",
				CONFIG_BT_ID_MAX);
	}

	size_t count = 1;
	bt_id_get(&rx->bt_addr, &count);

	char addr_str[BT_ADDR_LE_STR_LEN+1] = {0};
	bt_addr_le_to_str(&rx->bt_addr, addr_str, sizeof(addr_str)-1);
	LOG_DBG("id: %s\n", addr_str);
}

void bt_mesh_net_hbh_send(struct bt_mesh_net_tx *tx,
						  struct net_buf *buf,
						  uint32_t seq) {
	/* Obviously not in the cache so no need to check */
	LOG_DBG("New data to send\n");

	/* Initialize a new rx struture to copy tx data */
	struct bt_mesh_net_rx rx = {
		.ctx.addr = tx->src,
		.ctx.recv_dst = tx->ctx->addr,
		.seq = seq,
		.iack_bit = 0,
	};
	bt_mesh_net_hbh_copy_addr(&rx);
	
	struct net_hbh_item *item = NULL;
	bt_mesh_net_hbh_create_item(&item, &rx, buf);
	if(item == NULL) {
		LOG_ERR("No more space to stock advertising");
		return;
	}
	
	ITEM_LOCK(item);
	{
		/* already send by the BT TX thread the first time */
		item->transmit_number++;
		atomic_inc(&bt_mesh_net_hbh_number_of_transmission);
	}
	ITEM_UNLOCK(item);

	print_packet_info(item);

	/* Schedule next send */
	k_work_reschedule(&item->dwork, K_MSEC(BT_MESH_NET_HBH_RTO_MSEC));
}


void bt_mesh_net_hbh_recv(struct bt_mesh_net_rx *rx,
						  struct net_buf *buf) {

	LOG_DBG("src: %#04x, dst: %#04x, seq %u", rx->ctx.addr, rx->ctx.recv_dst, rx->seq);

	struct net_hbh_item *cached = NULL;
	bt_mesh_net_hbh_is_msg_cached(rx, &cached);
	
	if(cached == NULL && buf != NULL) {
		/* Message not yet cached. So it's a new message that need to be relayed */
		bt_mesh_net_hbh_create_item(&cached, rx, buf);
		if(cached == NULL) {
			LOG_ERR("No more space to stock advertising");
			return;
		}
		LOG_DBG("(new message)");
		print_packet_info(cached);
		k_work_reschedule(&cached->dwork, K_NO_WAIT);

		return;
	}

	if(cached == NULL && buf == NULL) {
		/* This case happen when this is a retransmission of the a node.
		 * The message is thus already in the bt_mesh_net::cache and the destination
		 * address is not decrypted. Need to rely on the protocol and simply drop
		 * the packet. 
		 */
		LOG_ERR("Drop HBH message special case");
		return;
	}

	if(cached->tx_buf->data == NULL) {
		LOG_ERR("tx_buf data is null");
		return;
	}


	/* Data is cached so it's maybe an iack.
	 * It's not an iack if the bt_addr_le is the same as first received (Ni+1).
	 */
	if(bt_mesh_net_hbh_is_iack(rx, cached)) {

		if(cached->acked) {
			/* Possible if an ack is already received.
			 * It's just a retransmission of node n+1.
			 */
			return;
		}
		
		cached->acked = true;
		
		LOG_DBG("(set message acked)");
		print_packet_info(cached);
		
		int64_t remaining = item_get_remaining_time_msec(cached);
		k_work_reschedule(&cached->dwork, K_MSEC(remaining));
		return;
	}

	/* Message from the sender (Ni-1) */	
	if(!rx->iack_bit) {
		/* Message is a retransmission of the sender not marked as iack. 
	 	 * Need to send an ACK.
	 	 */
		LOG_DBG("(need to send iack)");
		if(cached->acked) {
			/* Need to send an Oriented-iACK as the message is already
			 * acked by Ni+1 but Ni-1 not received the message
			 */
			bt_mesh_net_hbh_set_iack(cached);
		}
		print_packet_info(cached);
		k_work_reschedule(&cached->dwork, K_NO_WAIT);
	}

	/* Message from the sender (Ni-1) marked as Oriented-iACK.
	 * No need to do anything
	 */
}



void bt_mesh_net_hbh_init(void) {
	LOG_DBG("Initialize HBH");

	for(int i=0; i<ARRAY_SIZE(net_hbh_item_arr); i++) {
		struct net_hbh_item* item = &net_hbh_item_arr[i];

		/* init item mutex */
		k_mutex_init(&item->item_mut);

		/* init delayable work */
		k_work_init_delayable(&item->dwork, retransmit);

		/* set item as free */
		item_set_item_free(item, ITEM_FREE);
	}
}

void bt_mesh_net_hbh_set_max_retransmission(uint8_t retransmission) {
	bt_mesh_net_hbh_retransmission = retransmission;
}
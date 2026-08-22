#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define FLOWERSEC_MAX_JITTER_VALUES 8
/* Keep duplicate clones on the original veth ingress so legacy IFB drivers
 * cannot mistake a BPF clone for an egress packet and discard it. */
#define FLOWERSEC_DUPLICATE_MARK 0x4653
#define FLOWERSEC_LOSS_NONE 0
#define FLOWERSEC_LOSS_PERIODIC 1
#define FLOWERSEC_LOSS_BURST 2

struct fault_config {
	__u64 base_delay_ns;
	__s64 jitter_ns[FLOWERSEC_MAX_JITTER_VALUES];
	__u32 jitter_count;
	__u32 loss_mode;
	__u32 every_nth;
	__u32 block_size;
	__u32 burst_first;
	__u32 burst_last;
	__u32 link_mtu;
	__u32 reserved;
	__u32 reorder_basis_points;
	__u32 duplicate_basis_points;
	__u64 outage_start_ns;
	__u64 outage_duration_ns;
	__u64 reorder_delay_ns;
	__u32 duplicate_ifindex;
	__u32 reserved_2;
};

struct fault_stats {
	struct bpf_spin_lock lock;
	__u32 reserved_lock;
	__u64 packets;
	__u64 bytes;
	__u64 delay_packets;
	__u64 jitter_packets;
	__u64 periodic_loss_packets;
	__u64 burst_loss_packets;
	__u64 mtu_drop_packets;
	__u64 gso_packets;
	__u64 timestamp_errors;
	__u64 reorder_packets;
	__u64 duplicate_packets;
	__u64 duplicate_errors;
	__u64 outage_drop_packets;
	__u64 first_packet_ns;
	__u64 last_packet_ns;
	__u64 delivered_packets;
	__u64 jitter_slot_packets[FLOWERSEC_MAX_JITTER_VALUES];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct fault_config);
} flowersec_fault_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct fault_stats);
} flowersec_fault_stats SEC(".maps");

static __always_inline __u8 selected_ordinal(__u64 ordinal, __u32 basis_points, __u64 offset)
{
	__u64 period;

	if (basis_points == 0 || basis_points > 10000)
		return 0;
	period = 10000 / basis_points;
	return (ordinal - 1 + offset) % period == 0;
}

SEC("classifier")
int flowersec_packet_fault(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct fault_config *config = bpf_map_lookup_elem(&flowersec_fault_config, &key);
	struct fault_stats *stats = bpf_map_lookup_elem(&flowersec_fault_stats, &key);
	__u64 ordinal;
	__u64 now;
	__u64 first_packet_ns;
	__s64 jitter = 0;
	__s64 delay;
	__u32 l3_length = 0;
	__u32 jitter_slot = 0;
	__u8 reorder = 0;
	__u8 duplicate_replay = 0;

	if (!config || !stats)
		return TC_ACT_SHOT;
	/* A clone re-enters this classifier once; clear the private marker and
	 * suppress another clone while retaining the normal fault schedule. */
	if (skb->mark == FLOWERSEC_DUPLICATE_MARK) {
		duplicate_replay = 1;
		skb->mark = 0;
	}
	if (skb->protocol != bpf_htons(ETH_P_IP) && skb->protocol != bpf_htons(ETH_P_IPV6))
		return TC_ACT_OK;
	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		__be16 total_length;

		if (bpf_skb_load_bytes(skb, ETH_HLEN + __builtin_offsetof(struct iphdr, tot_len),
					       &total_length, sizeof(total_length)) < 0)
			return TC_ACT_SHOT;
		l3_length = bpf_ntohs(total_length);
	} else {
		__be16 payload_length;
		__be16 source_prefix;
		__u8 destination_prefix;

		if (bpf_skb_load_bytes(skb, ETH_HLEN + __builtin_offsetof(struct ipv6hdr, payload_len),
					       &payload_length, sizeof(payload_length)) < 0)
			return TC_ACT_SHOT;
		if (bpf_skb_load_bytes(skb, ETH_HLEN + __builtin_offsetof(struct ipv6hdr, saddr),
					       &source_prefix, sizeof(source_prefix)) < 0 ||
		    bpf_skb_load_bytes(skb, ETH_HLEN + __builtin_offsetof(struct ipv6hdr, daddr),
					       &destination_prefix, sizeof(destination_prefix)) < 0)
			return TC_ACT_SHOT;
		/* Interface-local control traffic must not shift workload packet ordinals. */
		if ((bpf_ntohs(source_prefix) & 0xffc0) == 0xfe80 || destination_prefix == 0xff)
			return TC_ACT_OK;
		l3_length = sizeof(struct ipv6hdr) + bpf_ntohs(payload_length);
	}

	now = bpf_ktime_get_ns();
	bpf_spin_lock(&stats->lock);
	ordinal = stats->packets + 1;
	stats->packets = ordinal;
	stats->bytes += skb->len;
	first_packet_ns = stats->first_packet_ns;
	if (first_packet_ns == 0) {
		stats->first_packet_ns = now;
		first_packet_ns = now;
	}
	stats->last_packet_ns = now;
	bpf_spin_unlock(&stats->lock);

	if (skb->gso_segs > 1) {
		__sync_fetch_and_add(&stats->gso_packets, 1);
		return TC_ACT_SHOT;
	}
	if (config->link_mtu > 0 && l3_length > config->link_mtu) {
		__sync_fetch_and_add(&stats->mtu_drop_packets, 1);
		return TC_ACT_SHOT;
	}
	if (config->outage_duration_ns > 0 && now >= first_packet_ns) {
		__u64 elapsed = now - first_packet_ns;
		if (elapsed >= config->outage_start_ns &&
		    elapsed - config->outage_start_ns < config->outage_duration_ns) {
			__sync_fetch_and_add(&stats->outage_drop_packets, 1);
			return TC_ACT_SHOT;
		}
	}
	if (config->loss_mode == FLOWERSEC_LOSS_PERIODIC &&
	    config->every_nth > 0 && ordinal % config->every_nth == 0) {
		__sync_fetch_and_add(&stats->periodic_loss_packets, 1);
		return TC_ACT_SHOT;
	}
	if (config->loss_mode == FLOWERSEC_LOSS_BURST && config->block_size > 0) {
		__u32 position = (__u32)((ordinal - 1) % config->block_size) + 1;
		if (position >= config->burst_first && position <= config->burst_last) {
			__sync_fetch_and_add(&stats->burst_loss_packets, 1);
			return TC_ACT_SHOT;
		}
	}

	if (config->jitter_count == FLOWERSEC_MAX_JITTER_VALUES) {
		jitter_slot = (ordinal - 1) & (FLOWERSEC_MAX_JITTER_VALUES - 1);
		jitter = config->jitter_ns[jitter_slot];
		__sync_fetch_and_add(&stats->jitter_slot_packets[jitter_slot], 1);
	}
	delay = (__s64)config->base_delay_ns + jitter;
	reorder = selected_ordinal(ordinal, config->reorder_basis_points, 0);
	if (reorder)
		delay += (__s64)config->reorder_delay_ns;
	if (delay > 0) {
		__u64 delivery = now + (__u64)delay;
		__sync_fetch_and_add(&stats->delay_packets, 1);
		if (jitter != 0)
			__sync_fetch_and_add(&stats->jitter_packets, 1);
#ifdef BPF_SKB_TSTAMP_DELIVERY_MONO
		if (bpf_skb_set_tstamp(skb, delivery, BPF_SKB_TSTAMP_DELIVERY_MONO) < 0) {
			__sync_fetch_and_add(&stats->timestamp_errors, 1);
			return TC_ACT_SHOT;
		}
#else
		/* Older supported kernels expose the writable delivery timestamp directly. */
		skb->tstamp = delivery;
#endif
		if (reorder)
			__sync_fetch_and_add(&stats->reorder_packets, 1);
	}
	if (!duplicate_replay && config->duplicate_basis_points > 0 && config->duplicate_basis_points <= 10000) {
		__u64 duplicate_period = 10000 / config->duplicate_basis_points;
		if (selected_ordinal(ordinal, config->duplicate_basis_points, duplicate_period / 2)) {
			skb->mark = FLOWERSEC_DUPLICATE_MARK;
			if (bpf_clone_redirect(skb, config->duplicate_ifindex, BPF_F_INGRESS) < 0)
				__sync_fetch_and_add(&stats->duplicate_errors, 1);
			else
				__sync_fetch_and_add(&stats->duplicate_packets, 1);
			skb->mark = 0;
		}
	}
	__sync_fetch_and_add(&stats->delivered_packets, 1);
	/* Continue to the lower-priority mirred filter; direct redirect clears EDT. */
	return TC_ACT_UNSPEC;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

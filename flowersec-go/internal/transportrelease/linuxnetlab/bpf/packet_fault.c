#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define FLOWERSEC_MAX_JITTER_VALUES 8
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
};

struct fault_stats {
	__u64 packets;
	__u64 bytes;
	__u64 delay_packets;
	__u64 jitter_packets;
	__u64 periodic_loss_packets;
	__u64 burst_loss_packets;
	__u64 mtu_drop_packets;
	__u64 gso_packets;
	__u64 timestamp_errors;
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

SEC("classifier")
int flowersec_packet_fault(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct fault_config *config = bpf_map_lookup_elem(&flowersec_fault_config, &key);
	struct fault_stats *stats = bpf_map_lookup_elem(&flowersec_fault_stats, &key);
	__u64 ordinal;
	__s64 jitter = 0;
	__s64 delay;
	__u32 l3_length = 0;
	__u32 jitter_slot = 0;

	if (!config || !stats)
		return TC_ACT_SHOT;
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

	ordinal = __sync_fetch_and_add(&stats->packets, 1) + 1;
	__sync_fetch_and_add(&stats->bytes, skb->len);

	if (skb->gso_segs > 1) {
		__sync_fetch_and_add(&stats->gso_packets, 1);
		return TC_ACT_SHOT;
	}
	if (config->link_mtu > 0 && l3_length > config->link_mtu) {
		__sync_fetch_and_add(&stats->mtu_drop_packets, 1);
		return TC_ACT_SHOT;
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
	if (delay > 0) {
		__u64 delivery = bpf_ktime_get_ns() + (__u64)delay;
		__sync_fetch_and_add(&stats->delay_packets, 1);
		if (jitter != 0)
			__sync_fetch_and_add(&stats->jitter_packets, 1);
		if (bpf_skb_set_tstamp(skb, delivery, BPF_SKB_TSTAMP_DELIVERY_MONO) < 0) {
			__sync_fetch_and_add(&stats->timestamp_errors, 1);
			return TC_ACT_SHOT;
		}
	}
	/* Continue to the lower-priority mirred filter; direct redirect clears EDT. */
	return TC_ACT_UNSPEC;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

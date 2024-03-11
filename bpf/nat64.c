
/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "headers/vmlinux.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_tracing.h"

#define TC_ACT_OK  0
#define TC_ACT_SHOT		2

#define PACKET_HOST		0		/* To us		*/

#define ETH_P_IP   0x0800 /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD
#define ETH_HLEN	14		/* Total octets in header.	 */

// From kernel:include/net/ip.h
#define IP_DF 0x4000  // Flag: "Don't Fragment"

#define TCP4_CSUM_OFF  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define UDP4_CSUM_OFF  (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))
#define TCP6_CSUM_OFF  (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check))
#define UDP6_CSUM_OFF  (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct udphdr, check))

// From kernel:include/uapi/linux/icmp.h
#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_ECHO		8	/* Echo Request			*/

// From kernel:include/uapi/linux/icmpv6.h
#define ICMPV6_ECHO_REQUEST		128
#define ICMPV6_ECHO_REPLY		129

// rfc6052
# define NAT64_PREFIX_0 0x64
# define NAT64_PREFIX_1 0xff
# define NAT64_PREFIX_2 0x9b
# define NAT64_PREFIX_3 0

// From kernel:include/uapi/asm/errno.h
#define ENOTSUP		252	/* Function not implemented (POSIX.4 / HPUX) */

/* Declare BPF maps */

// Helper forward declarations, so that we can have the most
// important functions code first
static __always_inline bool nat46_valid(const struct __sk_buff *skb);
static __always_inline bool nat64_valid(const struct __sk_buff *skb);
static __always_inline int icmp64_conv_type(__u8 icmp6_type);
static __always_inline int icmp46_conv_type(__u8 icmp4_type);

// Create an IPv4 packets using as destination address the last 4 bytes the
// dst IPv6 address with the NAT64 prefix.
// Use as source address the last digit of the soucre address with the 169.254.64.x prefix
// Assume there are less than 254 pods always in the node and that range is empty
SEC("tc/nat64")
int nat64(struct __sk_buff* skb)
{
	void *data = (void *)(long)skb->data;
	const void *data_end = (void *)(long)skb->data_end;
	const struct ethhdr *const eth = data;
	const struct ipv6hdr *const ip6 = (void *)(eth + 1);

	bpf_printk("NAT64: starting");

	// Forward packet if we can't handle it.
	if (!nat64_valid(skb)) {
		bpf_printk("NAT64 packet forwarded: not valid for nat64");
		return TC_ACT_OK;
	}

	bpf_printk("NAT64 IPv6 packet: saddr: %pI6, daddr: %pI6", &ip6->saddr, &ip6->daddr);

	// Build source ip, last byte of the ipv6 address plus the prefix.
	// 169.254.64.xxx
	__u32 new_src = bpf_htonl(0xA9FE4000 + (bpf_ntohl(ip6->saddr.in6_u.u6_addr32[3]) & 0x000000FF));

	// Extract IPv4 address from the last 4 bytes of IPv6 address.
	__u32 new_dst = ip6->daddr.in6_u.u6_addr32[3];

	// Crafting IPv4 packet out of IPv6 start here. Most of it can be
	// derived from IPv6 packet rather easily. Replacing addresses
	// is the least trivial part.
	__be16 tot_len = bpf_htons(bpf_ntohs(ip6->payload_len) + sizeof(struct iphdr));
	struct iphdr ip4 = {
		.version = 4,                                           // u4
		.ihl = sizeof(struct iphdr) / sizeof(__u32),            // u4
		.tos = (ip6->priority << 4) + (ip6->flow_lbl[0] >> 4),  // u8
		.tot_len = tot_len,                                     // u16
		.id = 0,                                                // u16
		.check = 0,                                             // u16
		.frag_off = 0,                                          // u16
	};

	// For whatever cursed reason, verifier is unhappy if these are part
	// of initializer list above, so I guess we need to set values
	// separately.
	ip4.ttl = ip6->hop_limit;
	ip4.protocol = (ip6->nexthdr == IPPROTO_ICMPV6) ? IPPROTO_ICMP : ip6->nexthdr;
	ip4.saddr = new_src;
	ip4.daddr = new_dst;

	// https://mailarchive.ietf.org/arch/msg/behave/JfxCt1fGT66pEtfXKuEDJ8rdd7w/
	if (bpf_ntohs(ip4.tot_len) > 1280)
		ip4.frag_off = bpf_htons(IP_DF);

	// Calculate the IPv4 one's complement checksum of the IPv4 header.
	__wsum sum4 = 0;
	for (int i = 0; i < sizeof(struct iphdr) / sizeof(__u16); ++i) {
		sum4 += ((__u16*)&ip4)[i];
	}
	// Note that sum4 is guaranteed to be non-zero by virtue of ip.version == 4
	sum4 = (sum4 & 0xFFFF) + (sum4 >> 16);  // collapse u32 into range 1 .. 0x1FFFE
	sum4 = (sum4 & 0xFFFF) + (sum4 >> 16);  // collapse any potential carry into u16
	ip4.check = (__u16)~sum4;               // sum4 cannot be zero, so this is never 0xFFFF

	struct icmphdr icmp4;
	// Initialize header to all zeroes.
	__u16 *p = (void *)&icmp4;
	for (int i = 0; i < sizeof(struct icmphdr) / sizeof(__u16); ++i) {
		p[i] = 0;
	}
	if (ip4.protocol == IPPROTO_ICMP) {
		const struct icmp6hdr *icmp6 = (void *)(ip6 + 1);
		int type = icmp64_conv_type(icmp6->icmp6_type);
		if (type < 0) {
			bpf_printk("NAT64 packet forwarded: cannot convert ICMP type");
			return TC_ACT_OK;
		}
		icmp4.type = (__u8)type;
		// For echo ICMP messages, code is always 0, no need to set it.
		icmp4.un.echo.id = icmp6->icmp6_dataun.u_echo.identifier;
		icmp4.un.echo.sequence = icmp6->icmp6_dataun.u_echo.sequence;

		// TODO: work in progress, implement correct ICMP checksum
                // calculation.
                //
                // Two approaches:
                // 1. Compute diffs between ICMPv6 and ICMPv4 checksums, either
                // manually or with bpf_csum_diff.
                //    Pros:
                //    - We don't need to fetch ICMP payload to calculate checksum
                //      (technically ICMP echo packets can be just headers, but
                //      senders can supply payload if they wish to and most ping
                //      utils do add some and it affects the checksum). Shields us
                //      from nefarious scenarios where someone deliberately provides
                //      big payloads to ICMP packets.
                //    Cons:
                //    - Pretty complex calculations, might be hard to adjust for
                //      more complicated ICMP types in the future.
                //    - Might not be worth it in most cases since ICMP packets are
                //      rather small on average.
                //    Problems:
                //    a. bpf_csum_diff:
                //       - Not clear how to chain diffs (what to pass as seed?
                //         previous diffs? the entire checksum? docs aren't very
                //         clear about this:
                //         https://man7.org/linux/man-pages/man7/bpf-helpers.7.html).
                //       - Not clear how to apply diff without resorting to manual
                //         calculation, bpf_l4_csum_replace could apply diff onto a packet,
                //         so one way is to apply diff when writing icmp to skb, but can
                //         we just get checksum value to assign to icmp4.checksum?
                //    b. Manually:
                //       - ICMPv6 uses pseudo-header for calculation, we would need to
                //         remove data from checksum, normally checksum calculation
                //         is just a sum and it's clear how to fold it, but when removing
                //         data we need to subtract and during that we can obtain
                //         negative value, not clear then how to fold it.
                // 2. Recalculate ICMP checksum from scratch:
                //    Pros:
                //    - Simple to understand.
                //    - Simple to extend to more ICMP types.
                //    Cons:
                //    - Bigger performance hit when someone nefariously supplies big
                //      payloads to ICMP packets.
                //    Problems:
                //    - Failing to access packet data, BPF verifier does not let me.

		// Diffs approach, not working currently, tshark shows bad checksum.
		// Mix of attempts with diffs and manual calcs.
/*
		int sum = 0xFFFF & ~(icmp6->icmp6_cksum);
		bpf_printk("NAT64 ICMP checksum 1: %x, ~%x", sum, ~sum);
		// ICMP headers diffs
		sum -= icmp6->icmp6_type;
		sum += icmp4.type;
		bpf_printk("NAT64 ICMP checksum 2: %x, ~%x", sum, ~sum);
		// Pseudo-header diffs, ICMPv6 uses pseudo-header for checksum calculation, ICMP does not.
		// Subtract all bytes taken from IPv6/ICMPv6 pseudo-header.
		for (int i = 0; i < 2*sizeof(struct in6_addr) / sizeof(__u16); ++i) {
			sum -= ((__u16*)&(ip6->saddr))[i];
		}
		bpf_printk("NAT64 ICMP checksum 3: %x, ~%x", sum, ~sum);
		sum -= ip6->payload_len;
		bpf_printk("NAT64 ICMP checksum 4: %x, ~%x", sum, ~sum);
		sum -= ip6->nexthdr;
		bpf_printk("NAT64 ICMP checksum 5: %x, ~%x", sum, ~sum);

		sum4 = bpf_csum_diff((void *)&(icmp6->icmp6_type), sizeof(__u8), (void *)&(icmp4.type), sizeof(__u8), sum4);
		bpf_printk("NAT64 ICMP checksum 2: %x, ~%x", sum4, ~sum4);
		// Pseudo-header diffs, ICMPv6 uses pseudo-header for checksum calculation, ICMP does not.
		sum4 = bpf_csum_diff((void *)&(ip6->saddr), 2*sizeof(struct in6_addr), 0, 0, sum4);
		bpf_printk("NAT64 ICMP checksum 3: %x, ~%x", sum4, ~sum4);
		sum4 = bpf_csum_diff((void *)&(ip6->payload_len), sizeof(__u16), 0, 0, sum4);
		bpf_printk("NAT64 ICMP checksum 4: %x, ~%x", sum4, ~sum4);
		sum4 = bpf_csum_diff((void *)&(ip6->nexthdr), sizeof(__u8), 0, 0, sum4);
		bpf_printk("NAT64 ICMP checksum 5: %x, ~%x", sum4, ~sum4);
		if (sum < 0)
		
*/

		// Calculate from scratch approach, BPF verifier fails.

		// Calculate the ICMP one's complement checksum of the IPv4 header.
		sum4 = 0;
		for (int i = 0; i < sizeof(struct icmphdr) / sizeof(__u16); ++i) {
			sum4 += ((__u16*)&icmp4)[i];
		}
		const void *icmp6_data = (void *)(icmp6 + 1);
		// It would be lovely it we could just write p < (__u16*)data_end, but
		// verifier is not smart enough to recognize that data is aligned

		// TODO: verifier thinks we're trying to access data outside of the packet here.
		// Few last lines of verifier error:
		// ; for (__u16 *p = (__u16*)(void *)icmp6_data; p + sizeof(__u16) <= (__u16*)data_end; p += sizeof(__u16)) {
		// 194: (07) r2 += 4		     ; R2_w=pkt(off=65538,r=65534,imm=0)
		// ; for (__u16 *p = (__u16*)(void *)icmp6_data; p + sizeof(__u16) <= (__u16*)data_end; p += sizeof(__u16)) {
		// 195: (3d) if r9 >= r2 goto pc-4       ; R0=0 R1_w=scalar(umax=1072939020,var_off=(0x0; 0x3fffffff)) R2_w=pkt(off=65538,r=65534,imm=0) R3_w=scalar(umax=65535,var_off=(0x0; 0xffff)) R4=8 R5=scalar() R6=ctx(off=0,imm=0) R7=9 R8=pkt(off=0,r=65534,imm=0) R9=pkt_end(off=0,imm=0) R10=fp0 fp-8= fp-16=mmmmmmmm fp-24=mmmmmmmm fp-32=mmmmmmmm
		// ; sum4 += *p;
		// 192: (69) r3 = *(u16 *)(r2 -4)
		// invalid access to packet, off=65534 size=2, R2(id=0,off=65534,r=65534)
		// R2 offset is outside of the packet
		// processed 82266 insns (limit 1000000) max_states_per_insn 4 total_states 842 peak_states 842 mark_read 9
		for (__u16 *p = (__u16*)(void *)icmp6_data; p + sizeof(__u16) <= (__u16*)data_end; p += sizeof(__u16)) {
			sum4 += *p;
		}
		sum4 = (sum4 & 0xFFFF) + (sum4 >> 16);  // collapse u32 into range 1 .. 0x1FFFE
		sum4 = (sum4 & 0xFFFF) + (sum4 >> 16);  // collapse any potential carry into u16
		icmp4.checksum = (__u16)~sum4;
		bpf_printk("NAT64 ICMP checksum: %x", icmp4.checksum);
	}

	// Calculate checksum difference for L4 packet inside IP packet before any helpers
	// that modify packet's data are called, because verifier will invalidate all packet pointers.
	__u64 l4_csum_diff = 0;
	switch (ip4.protocol) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		// Both UDP and TCP use pseudo header for checksum
		// calculation, see https://www.rfc-editor.org/rfc/rfc2460.html#section-8.1.

		// This is non-trivial, so some background on TCP/UDP
		// checksum calculation. Checksum is calculated over
		// pseudo-header, which contains some bits from L3
		// header, and L4 payload. L4 payload does not change
		// between input IPv6 packet and output IPv4 packet, but
		// pseudo-header does indeed change. We could feed
		// bpf_csum_diff with the entire pseudo-headers both from
		// input and output packets and calculate checksum
		// difference this way, but we can afford to be a
		// bit smarter here.
		//
		// TCP / UDP pseudo-header for IPv4
		// (see https://www.rfc-editor.org/rfc/rfc793.html#section-3.1)
		// and for IPv6
		// (see https://www.rfc-editor.org/rfc/rfc2460.html#section-8.1)
		// contain the same information for TCP / UDP (protocol
		// is 6 for TCP, 17 for UDP for both IPv4 and IPv6), but
		// structure of pseudo-header differs - fields are
		// ordered differently and have different sizes. For checksum
		// calculation, this does not matter - all bytes of
		// pseudo-header apart from IP addresses contribute the
		// same value to checksum (first step of calculation is
		// summing all bytes, zeroes does not matter),
		// meaning we only need to run bpf_csum_diff over IP
		// addresses instead of the entire pseudo-header.
		//
		// Last neat piece of info that makes it a one-liner is that both
		// ipv6hdr and iphdr structs have src and dst addresses
		// next to each other in memory. That means we can
		// calculate checksum difference with one bpf_csum_diff
		// call using 2 * size of IP address.
		l4_csum_diff = bpf_csum_diff((void *)&(ip6->saddr), 2*sizeof(struct in6_addr), (void *)&(ip4.saddr), 2*sizeof(__u32), 0);
		break;
	}

	// Save L2 header we got from the input packet before any packet
	// modifications. We will copy it later to the output packet.
	struct ethhdr old_eth;
	old_eth = *eth;
	// Replace the ethertype for a correct one for IPv4 packet.
	old_eth.h_proto = bpf_htons(ETH_P_IP);

	// Packet mutations begin - point of no return, but if this first modification fails
	// the packet is probably still pristine, so let clatd handle it.
	// This also takes care of resizing socket buffer to handle different IP
	// header size.
	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0)) {
		bpf_printk("NAT64 packet forwarded: bpf_skb_change_proto failed");
		return TC_ACT_OK;
	}

	// Update checksum of the packet inside IP packet.
	int ret = 0;
	switch (ip4.protocol) {
	case IPPROTO_UDP:
		ret = bpf_l4_csum_replace(skb, UDP4_CSUM_OFF, 0, l4_csum_diff, BPF_F_PSEUDO_HDR);
		break;
	case IPPROTO_TCP:
		ret = bpf_l4_csum_replace(skb, TCP4_CSUM_OFF, 0, l4_csum_diff, BPF_F_PSEUDO_HDR);
		break;
	}

	// If true, updating packet's UDP / TCP checksum failed.
	if (ret < 0) {
		bpf_printk("NAT64 packet dropped: L4 checksum update failed");
		return TC_ACT_SHOT;
	}

	// bpf_skb_change_proto() invalidates all pointers - reload them.
	data = (void*)(long)skb->data;
	data_end = (void*)(long)skb->data_end;
	// I cannot think of any valid way for this error condition to trigger, however I do
	// believe the explicit check is required to keep the in kernel ebpf verifier happy.
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return TC_ACT_SHOT;

	// Copy over the old ethernet header with updated ethertype.
	ret = bpf_skb_store_bytes(skb, 0, &old_eth, sizeof(struct ethhdr), 0);
	if (ret < 0) {
		bpf_printk("NAT64 packet dropped: copy eth header");
		return TC_ACT_SHOT;
	}
	// Copy over the new ipv4 header.
	ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &ip4, sizeof(struct iphdr), 0);
	if (ret < 0) {
		bpf_printk("NAT64 packet dropped: copy ipv4 header");
		return TC_ACT_SHOT;
	}

	if (ip4.protocol == IPPROTO_ICMP) {
		// Copy over the new icmp header
		ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr),
                                          &icmp4, sizeof(struct icmphdr), 0);
		if (ret < 0) {
			bpf_printk("NAT64 packet dropped: copy icmp header");
			return TC_ACT_SHOT;
		}
	}

	bpf_printk("NAT64 IPv4 packet: saddr: %pI4, daddr: %pI4", &ip4.saddr, &ip4.daddr);
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

// Build an IPv6 packet from an IPv4 packet
// destination address is pod prefix plus last digit from 169.254.64.x
// source address is the IPv4 src address embedded on the well known NAT64 prefix
SEC("tc/nat46")
static __always_inline int nat46(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	const void *data_end = (void *)(long)skb->data_end;
	const struct ethhdr *const eth = data;
	const struct iphdr *const ip4 = (void *)(eth + 1);

	bpf_printk("NAT46 IPv4 packet: saddr: %pI4, daddr: %pI4", &ip4->saddr, &ip4->daddr);

	// Forward packet if we can't handle it.
	if (!nat46_valid(skb)) {
		bpf_printk("NAT46 packet forwarded: not valid for nat46");
		return TC_ACT_OK;
	}

	// Build dest ip, last byte of the ipv6 address plus the pod prefix
	// pod_prefix::xxx.
	 __u32 dst_addr = bpf_ntohl(ip4->daddr) & 0x000000FF;

	struct ipv6hdr ip6 = {
		.version = 6,                                            // __u8:4
		.priority = ip4->tos >> 4,                               // __u8:4
		.flow_lbl = {(ip4->tos & 0xF) << 4, 0, 0},               // __u8[3]
		.payload_len = bpf_htons(bpf_ntohs(ip4->tot_len) - 20),  // __be16
		.hop_limit = ip4->ttl,                                   // __u8
	};

	ip6.nexthdr = (ip4->protocol == IPPROTO_ICMP) ? IPPROTO_ICMPV6 : ip4->protocol;
	ip6.saddr.in6_u.u6_addr32[0] = bpf_htonl(0x0064ff9b);
	ip6.saddr.in6_u.u6_addr32[1] = 0;
	ip6.saddr.in6_u.u6_addr32[2] = 0;
	ip6.saddr.in6_u.u6_addr32[3] = ip4->saddr;
	ip6.daddr.in6_u.u6_addr32[0] = bpf_htonl(0xfd000010);  // containers subnet
	ip6.daddr.in6_u.u6_addr32[1] = bpf_htonl(0x02440001);  // containers subnet
	ip6.daddr.in6_u.u6_addr32[2] = 0;
	ip6.daddr.in6_u.u6_addr32[3] = bpf_htonl(dst_addr);

	struct icmp6hdr icmp6;
	// Initialize header to all zeroes.
	__u16 *p = (void *)&icmp6;
	for (int i = 0; i < sizeof(struct icmp6hdr) / sizeof(__u16); ++i) {
		p[i] = 0;
	}
	if (ip6.nexthdr == IPPROTO_ICMPV6) {
		// TODO: work in progress, checksum is not calculated correctly yet.
		const struct icmphdr *icmp4 = (void *)(ip4 + 1);
		int type = icmp46_conv_type(icmp4->type);
		if (type < 0) {
			bpf_printk("NAT46 packet forwarded: cannot convert ICMPV6 type");
			return TC_ACT_OK;
		}
		icmp6.icmp6_type = (__u8)type;
		// For echo ICMP messages, code is always 0, no need to set it.
		icmp6.icmp6_dataun.u_echo.identifier = icmp4->un.echo.id;
		icmp6.icmp6_dataun.u_echo.sequence = icmp4->un.echo.sequence;

		// Calculate the ICMP one's complement checksum of the IPv4 header.
		__wsum sum6 = 0;
		for (int i = 0; i < sizeof(struct icmp6hdr) / sizeof(__u16); ++i) {
			sum6 += ((__u16*)&icmp6)[i];
		}
		// Include pseudo-header as well.
		// Cover both src and dst addresses here.
		for (int i = 0; i < 2*sizeof(struct in6_addr) / sizeof(__u16); ++i) {
			sum6 += ((__u16*)&ip6.saddr.in6_u.u6_addr32)[i];
		}
		sum6 += IPPROTO_ICMPV6;
		sum6 += sizeof(struct icmp6hdr);
		sum6 = (sum6 & 0xFFFF) + (sum6 >> 16);  // collapse u32 into range 1 .. 0x1FFFE
		sum6 = (sum6 & 0xFFFF) + (sum6 >> 16);  // collapse any potential carry into u16
		icmp6.icmp6_cksum = (__u16)~sum6;
	}

	// Calculate checksum difference for L4 packet inside IP packet before any helpers
	// that modify packet's data are called, because verifier will invalidate all packet pointers.
	__u64 l4_csum_diff = 0;
	switch (ip6.nexthdr) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		// See comment for nat64 direction to see reasoning behind this.
		l4_csum_diff = bpf_csum_diff((void *)&(ip4->saddr), 2*sizeof(__u32), (void *)&(ip6.saddr), 2*sizeof(struct in6_addr), 0);
		break;
	}

	// Save L2 header we got from the input packet before any packet
	// modifications. We will copy it later to the output packet.
	struct ethhdr old_eth;
	old_eth = *eth;
	// Replace the ethertype for a correct one for IPv6 packet.
	old_eth.h_proto = bpf_htons(ETH_P_IPV6);

	// Packet mutations begin - point of no return, but if this first modification fails
	// the packet is probably still pristine, so let clatd handle it.
	// This also takes care of resizing socket buffer to handle different IP
	// header size.
	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IPV6), 0)) {
		bpf_printk("NAT46 packet forwarded: bpf_skb_change_proto failed");
		return TC_ACT_OK;
	}

	// Update L4 checksum using the checksum difference we calculated before.
	int ret = 0;
	switch (ip6.nexthdr) {
	case IPPROTO_UDP:
		ret = bpf_l4_csum_replace(skb, UDP6_CSUM_OFF, 0, l4_csum_diff, BPF_F_PSEUDO_HDR);
		break;
	case IPPROTO_TCP:
		ret = bpf_l4_csum_replace(skb, TCP6_CSUM_OFF, 0, l4_csum_diff, BPF_F_PSEUDO_HDR);
		break;
	}

	// If true, updating packet's UDP / TCP checksum failed.
	if (ret < 0) {
		bpf_printk("NAT46 packet dropped: L4 checksum update failed");
		return TC_ACT_SHOT;
	}

	// bpf_skb_change_proto() invalidates all pointers - reload them.
	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;

	// I cannot think of any valid way for this error condition to trigger, however I do
	// believe the explicit check is required to keep the in kernel ebpf verifier happy.
	if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
		return TC_ACT_SHOT;

	// Copy over the old ethernet header with updated ethertype.
	ret = bpf_skb_store_bytes(skb, 0, &old_eth, sizeof(struct ethhdr), 0);
	if (ret < 0) {
		bpf_printk("NAT46 packet dropped: copy eth header");
		return TC_ACT_SHOT;
	}
	// Copy over the new ipv6 header.
	// This takes care of updating the skb->csum field for a CHECKSUM_COMPLETE packet.
	ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &ip6, sizeof(struct ipv6hdr), BPF_F_RECOMPUTE_CSUM);
	if (ret < 0) {
		bpf_printk("NAT46 packet dropped: copy ipv6 header + csum recompute");
		return TC_ACT_SHOT;
	}

	if (ip6.nexthdr == IPPROTO_ICMPV6) {
		// Copy over the new icmpv6 header
		ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct ipv6hdr),
                                          &icmp6, sizeof(struct icmp6hdr), 0);
		if (ret < 0) {
			bpf_printk("NAT46 packet dropped: copy icmpv6 header");
			return TC_ACT_SHOT;
		}
	}

	bpf_printk("NAT46 IPv6 packet: saddr: %pI6, daddr: %pI6", &ip6.saddr, &ip6.daddr);
	return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

static __always_inline bool
nat64_valid(const struct __sk_buff *skb) {
	const void *data = (void *)(long)skb->data;
	const void *data_end = (void *)(long)skb->data_end;

	// Require ethernet dst mac address to be our unicast address.
	if (skb->pkt_type != PACKET_HOST)
		return false;

	// Must be meta-ethernet IPv6 frame.
	if (skb->protocol != bpf_htons(ETH_P_IPV6))
		return false;

	// Must have (ethernet and) ipv6 header.
	if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
		return false;

	const struct ethhdr *eth = data;

	// Ethertype - if present - must be IPv6.
	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return false;

	const struct ipv6hdr *ip6 = (void *)(eth + 1);

	// IP version must be 6.
	if (ip6->version != 6)
		return false;

	// Maximum IPv6 payload length that can be translated to IPv4.
	if (bpf_ntohs(ip6->payload_len) > 0xFFFF - sizeof(struct iphdr))
		return false;

	// Must be inner protocol we can support.
	// TODO: Check what's with IPPROTO_GRE, IPPROTO_ESP, I'm not even sure
	//       what those are.
	switch (ip6->nexthdr) {
	case IPPROTO_TCP:
		// Must have TCP header.
		if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct tcphdr) > data_end)
			return false;
		break;
	case IPPROTO_UDP:
		// Must have UDP header.
		if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr) > data_end)
			return false;
		break;
	case IPPROTO_ICMPV6:
		// Must have ICMPv6 header.
		if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr) > data_end)
			return false;
		const struct icmp6hdr *icmp6 = (void *)(ip6 + 1);
		switch (icmp6->icmp6_type) {
		case ICMPV6_ECHO_REQUEST:
		case ICMPV6_ECHO_REPLY:
			break;
		default:
			// Can't handle other ICMPv6 types.
			return false;
		}

		// Since for now we support only echo request and reply,
		// code 0 is the only valid code.
		if (icmp6->icmp6_code)
			return false;

		break;
	default:  // Do not know how to handle anything else.
		return false;
	}

	return true;
}

static __always_inline bool
nat46_valid(const struct __sk_buff *skb) {
	const void *data = (void *)(long)skb->data;
	const void *data_end = (void *)(long)skb->data_end;

	// Must be meta-ethernet IPv4 frame.
	if (skb->protocol != bpf_htons(ETH_P_IP))
		return false;

	// Must have IPv4 header.
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return false;

	const struct ethhdr *eth = data;

	// Ethertype - if present - must be IPv4.
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return false;

	const struct iphdr *ip4 = (void *)(eth + 1);

	// IP version must be 4.
	if (ip4->version != 4)
		return false;

	// We cannot handle IP options, just standard 20 byte == 5 dword minimal IPv4 header.
	if (ip4->ihl != 5)
		return false;

	// Maximum IPv4 payload length that can be translated to IPv6.
	if (bpf_htons(ip4->tot_len) > 0xFFFF - sizeof(struct ipv6hdr))
		return false;

	// Calculate the IPv4 one's complement checksum of the IPv4 header.
	__wsum sum4 = 0;
	for (uint i = 0; i < sizeof(*ip4) / sizeof(__u16); ++i)
		sum4 += ((__u16 *)ip4)[i];

	// Note that sum4 is guaranteed to be non-zero by virtue of ip4->version == 4
	sum4 = (sum4 & 0xFFFF) + (sum4 >> 16);  // collapse u32 into range 1 .. 0x1FFFE
	sum4 = (sum4 & 0xFFFF) + (sum4 >> 16);  // collapse any potential carry into u16

	// For a correct checksum we should get *a* zero, but sum4 must be positive, ie 0xFFFF
	if (sum4 != 0xFFFF)
		return false;

	// Minimum IPv4 total length is the size of the header
	if (bpf_ntohs(ip4->tot_len) < sizeof(*ip4))
		return false;

	// We are incapable of dealing with IPv4 fragments
	if (ip4->frag_off & ~bpf_htons(IP_DF))
		return false;

	// Must be L4 protocol we can support.
	// TODO: Check what's with IPPROTO_GRE, IPPROTO_ESP, I'm not even sure
	//       what those are.
	switch (ip4->protocol) {
	case IPPROTO_TCP:
		// Must have TCP header.
		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
			return false;
		break;
	case IPPROTO_UDP:
		// Must have UDP header.
		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
			return false;
		break;
	case IPPROTO_ICMP:
		// Must have ICMP header.
		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end)
			return false;
		const struct icmphdr *icmp4 = (void *)(ip4 + 1);
		switch (icmp4->type) {
		case ICMP_ECHOREPLY:
		case ICMP_ECHO:
			break;
		default:
			// Can't handle other ICMP types.
			return false;
		}

		// Since for now we support only echo request and reply,
		// code 0 is the only valid code.
		if (icmp4->code)
			return false;

		break;
	default:  // do not know how to handle anything else
		return false;
	}

	return true;
}

static __always_inline int
icmp64_conv_type(__u8 icmp6_type) {
	switch (icmp6_type) {
	case ICMPV6_ECHO_REQUEST:
		return (int)ICMP_ECHO;
	case ICMPV6_ECHO_REPLY:
		return (int)ICMP_ECHOREPLY;
	default:
		return -ENOTSUP;
	}
}

static __always_inline int
icmp46_conv_type(__u8 icmp4_type) {
	switch (icmp4_type) {
	case ICMP_ECHOREPLY:
		return (int)ICMPV6_ECHO_REPLY;
	case ICMP_ECHO:
		return (int)ICMPV6_ECHO_REQUEST;
	default:
		return -ENOTSUP;
	}
}

char __license[] SEC("license") = "GPL";

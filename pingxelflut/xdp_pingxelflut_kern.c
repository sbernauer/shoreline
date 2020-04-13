#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

#define WIDTH 1024
#define HEIGHT 768

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, WIDTH * HEIGHT);
    //__uint(map_flags, BPF_F_MMAPABLE); // Needed to mmap this map later on in userspace
} pingxelflut_framebuffer SEC(".maps");

SEC("xdp_pingxelflut")
int xdp_prog_pingxelflut(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    u16 h_proto;
    u64 nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return XDP_DROP;

    h_proto = eth->h_proto;

    // parse double vlans
    #pragma unroll
    for (int i=0; i<2; i++) {
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
            struct vlan_hdr *vhdr = data + nh_off;
            nh_off += sizeof(struct vlan_hdr);
            if (data + nh_off > data_end)
                return XDP_DROP;
                h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

    if (h_proto == htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = data + nh_off;

        if (ip6h + 1 > data_end)
            return XDP_DROP;

        struct in6_addr *dst_addr = &ip6h->daddr;

        // TODO: It would be better to make the hton-conversion in userspace when displaying the contents of the framebuffer.
        // There the performance doesn't matter that mutch as here, were the code is executed for every single packet.
        u16 x  = htons(*((u16*)dst_addr + 4));
        u16 y  = htons(*((u16*)dst_addr + 5));
        u32 rgba = (htons(*((u16*)dst_addr + 6)) << 16) + htons(*((u16*)dst_addr + 7)); // There is no htonl here?

        char print[] = "Got packet for x: %x y: %x rgba: %x\n";
        bpf_trace_printk(print, sizeof(print), x, y, rgba);

        if (x >= WIDTH || y >= HEIGHT)
            return XDP_DROP;
        u32 index = x + y * WIDTH;
        bpf_map_update_elem(&pingxelflut_framebuffer, &index, &rgba, BPF_ANY);
    }

    return XDP_PASS; // Change it to XDP_DROP to get maximum performance
}

char _license[] SEC("license") = "GPL";

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <sched.h>
#include <stdarg.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>

#include "network_pingxelflut.h"
#include "framebuffer.h"
#include "llist.h"
#include "util.h"

#define XDP_PROG_FILENAME "./pingxelflut/linux/samples/bpf/xdp_pingxelflut_kern.o"
#define XDP_PROG_MAPNAME "pingxelflut_framebuffer"

static bool do_exit = false;

int net_pingxelflut_alloc(struct net_pingxelflut** network, struct fb* fb, struct llist* fb_list, struct fb_size* fb_size) {
	int err = 0;
	struct net_pingxelflut* net = calloc(1, sizeof(struct net_pingxelflut));
	if(!net) {
		err = -ENOMEM;
		goto fail;
	}

	net->fb = fb;
	net->fb_list = fb_list;
	net->fb_size = fb_size;

	*network = net;

fail:
	return err;
}

void net_pingxelflut_free(struct net_pingxelflut* net) {
	free(net);
}

void net_pingxelflut_shutdown(struct net_pingxelflut* net) {
	printf("Shutting down net_pingxelflut\n");
	do_exit = true;

	__u32 curr_prog_id = 0;

	__u32 xdp_flags = 0;
	if (bpf_get_link_xdp_id(net->ifindex, &curr_prog_id, xdp_flags)) {
		printf("ERROR: bpf_get_link_xdp_id failed\n");
	}
	if (net->prog_id == curr_prog_id) {
		bpf_set_link_xdp_fd(net->ifindex, -1, xdp_flags);
	} else if (!curr_prog_id) {
		printf("couldn't find a prog id on a given interface\n");
	} else {
		printf("program on interface changed, not removing\n");
	}
}

static void* net_pingxelflut_listen_thread(void* args) {
	struct net_pingxelflut_threadargs* threadargs = args;
	struct net_pingxelflut* net = threadargs->net;

	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		goto fail;
	}

	net->ifindex = if_nametoindex(net->interface);
	if (!net->ifindex) {
		printf("Cant get ifindex for interface %s\n", net->interface);
		goto fail;
	}

	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.file = XDP_PROG_FILENAME,
	};

	if (bpf_prog_load_xattr(&prog_load_attr, &net->obj, &net->prog_fd)) {
		goto fail;
	}

	net->map = bpf_object__find_map_by_name(net->obj, XDP_PROG_MAPNAME);
	if (!net->map) {
		printf("finding the map %s in obj file failed\n", XDP_PROG_MAPNAME);
		goto fail;
	}
	net->map_fd = bpf_map__fd(net->map);

	__u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
	if (bpf_set_link_xdp_fd(net->ifindex, net->prog_fd, xdp_flags) < 0) {
		printf("link set xdp fd failed\n");
		goto fail;
	}

	if (bpf_get_link_xdp_id(net->ifindex, &net->prog_id, 0)) {
		printf("ERROR: bpf_get_link_xdp_id failed\n");
		goto fail;
	}

	printf("Pingxelflut listening on interface %s\n", net->interface);

	// TODO check, that size of fb and bpf map are the same
	int map_fd = net->map_fd;
	struct fb* fb = net->fb;
	__u32 value;
	while (!do_exit) {

		printf("LOOP :)\n");

#ifdef FEATURE_PINGXELFLUT_COMPAT_NO_MMAP
		for(__u32 i = 0; i < net->fb_size->width * net->fb_size->height; i++) {
			bpf_map_lookup_elem(map_fd, &i, &value);
			fb->pixels[i].abgr = value;
		}
#else
		// TODO memcp from mmap
#endif
		sleep(1);
	}
fail:
	return NULL;
}

int net_pingxelflut_listen(struct net_pingxelflut* net) {
		int err;

		struct net_pingxelflut_threadargs* threadargs = malloc(sizeof(struct net_pingxelflut_threadargs));
		threadargs->net = net;

		pthread_t net_pingxelflut_listen_pthread;
		err = -pthread_create(&net_pingxelflut_listen_pthread, NULL, net_pingxelflut_listen_thread, threadargs);
		if(err) {
			fprintf(stderr, "Failed to create pthread for network_pingxelflut\n");
			goto fail_pthread_create;
		}

fail_pthread_create:
	return err;
}

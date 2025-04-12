#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>

#include "liburing.h"
#include "helpers.h"

#define PORT	10202
#define HOST	"127.0.0.1"

static int use_port = PORT;

struct io_uring_sqe* get_sqe(struct io_uring* ring)
{
	struct io_uring_sqe* sqe = io_uring_get_sqe(ring);
	if(!sqe) {
		io_uring_submit(ring);
		sqe = io_uring_get_sqe(ring);
	}
	return sqe;
}

#define NUM_CONNS 75
#define NUM_BUFS 64
#define SERVER_BGID 27
#define CLIENT_BGID 72
#define BUF_LEN 64
#define MSG_LEN 1024

struct conn
{
	int fd;
	char* send_buf;
	size_t num_sent;
	size_t num_received;
	bool send_done;
};

struct conn make_conn()
{
	struct conn c =
	{
		.fd = -1,
		.send_buf = NULL,
		.num_sent = 0,
		.num_received = 0,
		.send_done = false
	};
	return c;
}

void set_send_buf(struct conn* c)
{
	c->send_buf = (char*) malloc(MSG_LEN);
	for (int i = 0; i < MSG_LEN; ++i) {
		c->send_buf[i] = rand();
	}
}

void release_conn(struct conn* c)
{
	close(c->fd);
	free(c->send_buf);
}

enum op_type { send_op = 1, recv_op };

void prep_user_data(struct io_uring_sqe* sqe, int idx, enum op_type op)
{
	__u64 user_data = (__u64) idx | ((__u64) op << 32 );
	// printf("prep_user_data => %llu\n", user_data);
	io_uring_sqe_set_data64(sqe, user_data);
}

int user_data_to_idx(__u64 user_data)
{
	return user_data & 0xffffffff;
}

enum op_type user_data_to_op(__u64 user_data)
{
	// printf("user_data_to_op => %llu\n", user_data);
	enum op_type op = user_data >> 32;
	// printf("%d\n", op);
	return op;
}

void prep_recv( struct conn* conn, struct io_uring* ring, int idx)
{
	struct io_uring_sqe* sqe = get_sqe(ring);
	io_uring_prep_recv_multishot(sqe, conn->fd, NULL, 0, 0);
	io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
	sqe->buf_group = SERVER_BGID;
	sqe->ioprio = IORING_RECVSEND_POLL_FIRST | IORING_RECVSEND_BUNDLE;

	prep_user_data(sqe, idx, recv_op);
}

static void *stress_send_fn(void* data)
{
	struct io_uring_params p = { };
	struct io_uring ring;
	struct io_uring_buf_ring *br;
	int ret;
	struct conn conns[NUM_CONNS] = {};

	{
		for (int i = 0; i < NUM_CONNS; ++i)
		{
			conns[i] = make_conn();
			set_send_buf(&conns[i]);
		}
	}

	p.cq_entries = 4096;
	p.flags = IORING_SETUP_CQSIZE;
	ret = t_create_ring_params(256, &ring, &p);
	if (ret < 0) {
		return NULL;
	}

	void** bufs = malloc(NUM_BUFS * sizeof(*bufs));
	{
		br = io_uring_setup_buf_ring(&ring, NUM_BUFS, CLIENT_BGID, 0, &ret);
		if (!br) {
			return NULL;
		}

		for (int i = 0; i < NUM_BUFS; ++i)
		{
			void* buf = malloc(BUF_LEN);
			io_uring_buf_ring_add(br, buf, BUF_LEN, i, io_uring_buf_ring_mask(NUM_BUFS), i);
			bufs[i] = buf;
		}
		io_uring_buf_ring_advance(br, NUM_BUFS);
	}

	{
		struct sockaddr_in saddr;

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_addr.s_addr = htonl(INADDR_ANY);
		saddr.sin_port = htons(use_port);

		for(int i = 0; i < NUM_CONNS; ++i)
		{
			int sockfd = socket(AF_INET, SOCK_STREAM, 0);
			if (sockfd < 0) {
				perror("socket");
				return NULL;
			}

			conns[i].fd = sockfd;
			ret = connect(conns[i].fd, (struct sockaddr const*)&saddr, sizeof(saddr));
			if (ret < 0) {
				perror("connect");
				goto err;
			}
		}
	}

	{
		for (int i = 0; i < NUM_CONNS; ++i)
		{
			struct io_uring_sqe* sqe = get_sqe(&ring);
			io_uring_prep_send_zc(sqe, conns[i].fd, conns[i].send_buf, MSG_LEN, 0, 0);
			prep_user_data(sqe, i, send_op);
		}

		int num_completed = 0;
		while (num_completed < NUM_CONNS)
		{
			io_uring_submit_and_wait(&ring, 1);

			struct io_uring_cqe *cqe = NULL;
			unsigned head = 0;
			int c = 0;
			io_uring_for_each_cqe(&ring, head, cqe)
			{
				++c;

				int idx = user_data_to_idx(io_uring_cqe_get_data64(cqe));
				enum op_type op = user_data_to_op(io_uring_cqe_get_data64(cqe));

				if (op == send_op)
				{
					if (cqe->res < 0)
					{
						perror("send op");
						return NULL;
					}

					struct conn* conn = &conns[idx];
					if (conn->num_sent == 0)
					{
						conn->num_sent += cqe->res;
						// printf("(cqe->res => %d, cqe->flags => %d)\n", cqe->res, cqe->flags);
						if (!(cqe->flags & IORING_CQE_F_MORE))
						{
							perror("broken zc send");
							return NULL;
						}
					}
					else
					{
						conn->send_done = true;
						++num_completed;
						// printf("Send completed for connection %p\n", conn);
					}
				}
				else
				{
					assert(false);
				}

			}
			io_uring_cq_advance(&ring, c);
		}
	}

	{
		for (int i = 0; i < NUM_CONNS; ++i)
		{
			release_conn(&conns[i]);
		}
	}


	for (int i = 0; i < NUM_BUFS; ++i) { free(bufs[i]);}
	free(bufs);

	ret = T_EXIT_PASS;
	return NULL;

err:
	return NULL;
}

static int test_tcp_stress(void)
{
	srand(time(NULL));

	pthread_t stress_send_thread;
	struct io_uring_params p = { };
	struct io_uring ring;
	struct io_uring_buf_ring *br;
	int ret, acceptfd;
	struct conn conns[NUM_CONNS] = {};
	void *retval;

	{
		for (int i = 0; i < NUM_CONNS; ++i)
		{
			conns[i] = make_conn();
			set_send_buf(&conns[i]);
		}
	}

	p.cq_entries = 4096;
	p.flags = IORING_SETUP_CQSIZE | IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;
	ret = t_create_ring_params(256, &ring, &p);
	if (ret < 0) {
		return T_EXIT_FAIL;
	}

	int num_bufs = NUM_BUFS;
	int buf_len = BUF_LEN;
	void** bufs = malloc(num_bufs * sizeof(*bufs));
	{
		br = io_uring_setup_buf_ring(&ring, num_bufs, SERVER_BGID, 0, &ret);
		if (!br) {
			return 1;
		}

		for (int i = 0; i < num_bufs; ++i)
		{
			void* buf = malloc(buf_len);
			io_uring_buf_ring_add(br, buf, buf_len, i, io_uring_buf_ring_mask(num_bufs), i);
			bufs[i] = buf;
		}
		io_uring_buf_ring_advance(br, num_bufs);
	}

	{
		int* sock = &acceptfd;

		struct sockaddr_in saddr;
		int sockfd, val;

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_addr.s_addr = htonl(INADDR_ANY);
		saddr.sin_port = htons(use_port);

		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd < 0) {
			perror("socket");
			return T_EXIT_FAIL;
		}
		*sock = sockfd;

		val = 1;
		setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

		ret = bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
		if (ret < 0) {
			perror("bind");
			goto err;
		}

		ret = listen(sockfd, 1024);
		if (ret < 0) {
			perror("listen");
			goto err;
		}
	}

	ret = pthread_create(&stress_send_thread, NULL, stress_send_fn, NULL);
	if (ret) {
		fprintf(stderr, "Thread create failed: %d\n", ret);
		goto err;
	}


	{
		struct sockaddr_in saddr;
		socklen_t socklen;

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_addr.s_addr = htonl(INADDR_ANY);
		saddr.sin_port = htons(use_port);

		for (int i = 0; i < NUM_CONNS; ++i) {
			conns[i].fd = accept(acceptfd, (struct sockaddr*) &saddr, &socklen);
		}
	}

	{
		for( int i = 0; i < NUM_CONNS; ++i )
		{
			struct conn* conn = &conns[i];
			prep_recv(conn, &ring, i);
		}

		int num_completed = 0;
		while (num_completed < NUM_CONNS)
		{
			io_uring_submit_and_wait(&ring, 1);

			struct io_uring_cqe *cqe = NULL;
			unsigned head = 0;
			int c = 0;
			io_uring_for_each_cqe(&ring, head, cqe)
			{
				++c;

				__u64 userdata = io_uring_cqe_get_data64(cqe);
				int idx = user_data_to_idx(userdata);
				enum op_type op = user_data_to_op(userdata);

				if( op == recv_op )
				{
					struct conn* conn = &conns[idx];
					if( cqe->res == -ENOBUFS )
					{
						prep_recv(conn, &ring, idx);
						io_uring_cq_advance(&ring, c);
						continue;
					}

					if( cqe->res < 0 )
					{
						perror("bad recv");
						return -1;
					}

					if( !(cqe->flags & IORING_CQE_F_MORE) )
					{
						prep_recv(conn, &ring, idx);
					}

					uint16_t bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;

					int num_received = cqe->res;
					int offset = 0;
					while( num_received > 0 )
					{
						int n = buf_len;
						if( num_received < buf_len )
						{
							n = num_received;
						}

						// printf("num_received: %d, conn->send_buf => %p, conn->num_received => %lu, conn->fd => %d\n", num_received, conn->send_buf, conn->num_received, conn->fd);

						memcpy(conn->send_buf + conn->num_received, bufs[bid], n);

						free(bufs[bid]);

						void* buf = malloc(buf_len);
						io_uring_buf_ring_add(br, buf, buf_len, bid, io_uring_buf_ring_mask(num_bufs), offset);

						conn->num_received += n;
						num_received -= n;

						bufs[bid] = buf;

						++bid;
						++offset;
					}
					io_uring_buf_ring_advance(br, offset);

					if( conn->num_received == MSG_LEN )
					{
						printf("recv loop completed\n");
						++num_completed;
					}

				}
				else
				{
					perror("unreachable");
					printf("op: %d\n", op);
					printf("cqe->res: %d\n", cqe->res);
					printf("cqe->user_data: %llu\n", io_uring_cqe_get_data64(cqe));
					printf("cqe->flags: %d\n", cqe->flags);
					return -1;
				}
			}
			io_uring_cq_advance(&ring, c);
		}
	}

	pthread_join(stress_send_thread, &retval);
	close(acceptfd);

	{
		for (int i = 0; i < NUM_CONNS; ++i)
		{
			release_conn(&conns[i]);
		}
	}

	for (int i = 0; i < NUM_BUFS; ++i) { free(bufs[i]);}
	free(bufs);

	ret = T_EXIT_PASS;
	return ret;

err:
	return T_EXIT_FAIL;
}

int main(int argc, char *argv[])
{
	int ret;

	// if (argc > 1)
	// 	return T_EXIT_SKIP;

	// ret = test_tcp();
	// if (ret != T_EXIT_PASS)
	// 	return ret;

	// ret = test_udp();
	// if (ret != T_EXIT_PASS)
	// 	return ret;

	// classic_buffers = 1;

	// ret = test_tcp();
	// if (ret != T_EXIT_PASS)
	// 	return ret;

	// ret = test_udp();
	// if (ret != T_EXIT_PASS)
	// 	return ret;

	ret = test_tcp_stress();
	if (ret != T_EXIT_PASS)
		return ret;

	return T_EXIT_PASS;
}

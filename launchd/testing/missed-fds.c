/*
 * <rdar://problem/4389914> 8G1153: Cannot SSH into machine despite Remote Login being checked
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

static void do_parent(int thefd);
static void do_child(int thefd);

int main(void)
{
	int sp[2];
	pid_t p;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != -1);

	assert((p = fork()) != -1);

	if (p == 0) {
		assert(close(sp[0]) != -1);
		do_child(sp[1]);
	} else {
		assert(close(sp[1]) != -1);
		do_parent(sp[0]);
	}

	exit(EXIT_SUCCESS);
}

static int
alloc_random_fd(void)
{
	struct sockaddr_in ina;
	int fd;

	memset(&ina, 0, sizeof(ina));
	ina.sin_family = AF_INET;
	assert((fd = socket(PF_INET, SOCK_STREAM, 0)) != -1);
	assert(bind(fd, (struct sockaddr *)&ina, sizeof(ina)) != -1);
	assert(listen(fd, SOMAXCONN) != -1);

	return fd;
}

static int total_fds_sent = 0;

void
send_fds(int thefd)
{
	struct cmsghdr *cm = NULL;
	struct msghdr mh;
	struct iovec iov;
	size_t sentctrllen = 0;
	int fdcnt = (rand() % 223) + 1; /* 223 is prime */
	int r, i, fds[fdcnt];

	memset(&mh, 0, sizeof(mh));

	iov.iov_base = &fdcnt;
	iov.iov_len = sizeof(fdcnt);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	for (i = 0; i < fdcnt; i++) {
		fds[i] = alloc_random_fd();
	}

	sentctrllen = mh.msg_controllen = CMSG_SPACE(fdcnt * sizeof(int));

	mh.msg_control = cm = alloca(mh.msg_controllen);

	memset(cm, 0, mh.msg_controllen);

	cm->cmsg_len = CMSG_LEN(fdcnt * sizeof(int));
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;

	memcpy(CMSG_DATA(cm), fds, fdcnt * sizeof(int));

	if (sendmsg(thefd, &mh, 0) == -1) {
		fprintf(stderr, "Child: sendmsg(): %s\n", strerror(errno));
		fprintf(stderr, "Child: Tried to send %d fds\n", fdcnt);
		fprintf(stderr, "Child: Total FDs sent: %d\n", total_fds_sent);
		sleep(1);
		exit(EXIT_FAILURE);
	}
	total_fds_sent += fdcnt;

	assert(sentctrllen == mh.msg_controllen);

	r = read(thefd, &i, sizeof(i));
	assert(r != -1);
	assert(r != 0);

	for (i = 0; i < fdcnt; i++) {
		assert(close(fds[i]) != -1);
	}
}

void
do_child(int thefd)
{
	for (;;) {
		send_fds(thefd);
	}
}

static int total_fds_received = 0;

static bool
fetch_and_check_fds(int thefd)
{
	struct cmsghdr *cm = alloca(4096);
	struct msghdr mh;       
	struct iovec iov;
	int r, i, *fds, fdcnt = 0, sentfds;

	memset(&mh, 0, sizeof(mh));

	iov.iov_base = &fdcnt;
	iov.iov_len = sizeof(fdcnt);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = cm;
	mh.msg_controllen = 4096;

	r = recvmsg(thefd, &mh, 0);
	assert(r != -1);
	assert(r != 0);
	assert(!(mh.msg_flags & MSG_CTRUNC));
	assert(mh.msg_controllen > 0);

	fds = (int *)CMSG_DATA(cm);
	sentfds = (mh.msg_controllen - sizeof(struct cmsghdr)) / sizeof(int);

	if (sentfds != fdcnt) {
		fprintf(stderr, "%d FDs sent, %d actually received.\n", fdcnt, sentfds);
		return false;
	}

	total_fds_received += fdcnt;

	for (i = 0; i < fdcnt; i++) {
		assert(close(fds[i]) != -1);
	}

	r = write(thefd, &fdcnt, sizeof(fdcnt));
	assert(r != -1);
	assert(r != 0);

	return true;
}

void
do_parent(int thefd)
{
	struct kevent kev;
	int kq, iter = 0;

	EV_SET(&kev, thefd, EVFILT_READ, EV_ADD, 0, 0, NULL);

	assert((kq = kqueue()) != -1);
	assert(kevent(kq, &kev, 1, NULL, 0, NULL) != -1);

	for (iter = 0; ; iter++) {
		assert(kevent(kq, NULL, 0, &kev, 1, NULL) == 1);
		assert(kev.filter == EVFILT_READ);
		if (!fetch_and_check_fds(thefd))
			break;
	}

	fprintf(stderr, "After %d iterations and %d FDs received, bug 4389914 still exists!\n", iter, total_fds_received);
	exit(EXIT_FAILURE);
}

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "launch.h"
#include "launch_priv.h"

struct _launch {
	void	*sendbuf;
	int	*sendfds;   
	void	*recvbuf;
	int	*recvfds;   
	size_t	sendlen;                
	size_t	sendfdcnt;                    
	size_t	recvlen;                                
	size_t	recvfdcnt;                                    
	int	fd;                                                     
};

static void make_msg_and_cmsg(launch_data_t, void **, size_t *, int **, size_t *);
static launch_data_t make_data(launch_t, size_t *, size_t *);

static pthread_once_t _lc_once = PTHREAD_ONCE_INIT;

static struct _launch_client {
	pthread_mutex_t mtx;
	launch_t	l;
	launch_data_t	async_resp;
} *_lc = NULL;

static void launch_client_init(void)
{
	struct sockaddr_un sun;
	char *where = getenv(LAUNCHD_SOCKET_ENV);
	char *_launchd_fd = getenv(LAUNCHD_TRUSTED_FD_ENV);
	int dfd, lfd = -1;
	
	_lc = calloc(1, sizeof(struct _launch_client));

	if (!_lc)
		return;

	pthread_mutex_init(&_lc->mtx, NULL);

	if (_launchd_fd) {
		lfd = strtol(_launchd_fd, NULL, 10);
		if ((dfd = dup(lfd)) >= 0) {
			close(dfd);
		} else {
			lfd = -1;
		}
	}
	if (lfd == -1) {
		if (!where)
			where = LAUNCHD_DEFAULT_SOCK_PATH;

		memset(&sun, 0, sizeof(sun));
		sun.sun_family = AF_UNIX;

		strncpy(sun.sun_path, where, sizeof(sun.sun_path));

		if ((lfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
			goto out_bad;
		if (connect(lfd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
			close(lfd);
			goto out_bad;
		}
	}
	if (!(_lc->l = launchd_fdopen(lfd))) {
		close(lfd);
		goto out_bad;
	}
	if (!(_lc->async_resp = launch_data_alloc(LAUNCH_DATA_ARRAY)))
		goto out_bad;

	return;
out_bad:
	if (_lc->l)
		launchd_close(_lc->l);
	if (_lc)
		free(_lc);
	_lc = NULL;
}

struct _launch_data {
	launch_data_type_t type;
	union {
		struct {
			launch_data_t *_array;
			size_t _array_cnt;
		};
		struct {
			char *string;
			size_t string_len;
		};
		struct {
			void *opaque;
			size_t opaque_size;
		};
		int fd;
		long long number;
		bool boolean;
		double float_num;
	};
};

launch_data_t launch_data_alloc(launch_data_type_t t)
{
	launch_data_t d = calloc(1, sizeof(struct _launch));

	if (d) {
		d->type = t;
		switch (t) {
		case LAUNCH_DATA_DICTIONARY:
		case LAUNCH_DATA_ARRAY:
			d->_array = malloc(0);
			break;
		default:
			break;
		}
	}

	return d;
}

launch_data_type_t launch_data_get_type(launch_data_t d)
{
	return d->type;
}

void launch_data_free(launch_data_t d)
{
	size_t i;

	switch (d->type) {
	case LAUNCH_DATA_DICTIONARY:
	case LAUNCH_DATA_ARRAY:
		for (i = 0; i < d->_array_cnt; i++)
			launch_data_free(d->_array[i]);
		free(d->_array);
		break;
	case LAUNCH_DATA_STRING:
		if (d->string)
			free(d->string);
		break;
	case LAUNCH_DATA_OPAQUE:
		if (d->opaque)
			free(d->opaque);
		break;
	default:
		break;
	}
	free(d);
}

bool launch_data_dict_insert(launch_data_t dict, launch_data_t what, const char *key)
{
	size_t i;
	launch_data_t thekey = launch_data_alloc(LAUNCH_DATA_STRING);

	launch_data_set_string(thekey, key);

	for (i = 0; i < dict->_array_cnt; i += 2) {
		if (!strcmp(key, dict->_array[i]->string)) {
			launch_data_array_set_index(dict, thekey, i);
			launch_data_array_set_index(dict, what, i + 1);
			return true;
		}
	}
	launch_data_array_set_index(dict, thekey, i);
	launch_data_array_set_index(dict, what, i + 1);
	return true;
}

launch_data_t launch_data_dict_lookup(launch_data_t dict, const char *key)
{
	size_t i;

	if (LAUNCH_DATA_DICTIONARY != dict->type)
		return NULL;

	for (i = 0; i < dict->_array_cnt; i += 2) {
		if (!strcmp(key, dict->_array[i]->string))
			return dict->_array[i + 1];
	}

	return NULL;
}

bool launch_data_dict_remove(launch_data_t dict, const char *key)
{
	size_t i;

	for (i = 0; i < dict->_array_cnt; i += 2) {
		if (!strcmp(key, dict->_array[i]->string))
			break;
	}
	if (i == dict->_array_cnt)
		return false;
	launch_data_free(dict->_array[i]);
	launch_data_free(dict->_array[i + 1]);
	memmove(dict->_array + i, dict->_array + i + 2, (dict->_array_cnt - (i + 2)) * sizeof(launch_data_t));
	dict->_array_cnt -= 2;
	return true;
}

void launch_data_dict_iterate(launch_data_t dict, void (*cb)(launch_data_t, const char *, void *), void *context)
{
	size_t i;

	if (LAUNCH_DATA_DICTIONARY != dict->type)
		return;

	for (i = 0; i < dict->_array_cnt; i += 2)
		cb(dict->_array[i + 1], dict->_array[i]->string, context);
}

bool launch_data_array_set_index(launch_data_t where, launch_data_t what, size_t ind)
{
	if ((ind + 1) >= where->_array_cnt) {
		where->_array = realloc(where->_array, (ind + 1) * sizeof(launch_data_t));
		memset(where->_array + where->_array_cnt, 0, (ind + 1 - where->_array_cnt) * sizeof(launch_data_t));
		where->_array_cnt = ind + 1;
	}

	if (where->_array[ind])
		launch_data_free(where->_array[ind]);
	where->_array[ind] = what;
	return true;
}

launch_data_t launch_data_array_get_index(launch_data_t where, size_t ind)
{
	if (LAUNCH_DATA_ARRAY != where->type)
		return NULL;
	if (ind < where->_array_cnt)
		return where->_array[ind];
	return NULL;
}

launch_data_t launch_data_array_pop_first(launch_data_t where)
{
	launch_data_t r = NULL;
       
	if (where->_array_cnt > 0) {
		r = where->_array[0];
		memmove(where->_array, where->_array + 1, (where->_array_cnt - 1) * sizeof(launch_data_t));
		where->_array_cnt--;
	}
	return r;
}

size_t launch_data_array_get_count(launch_data_t where)
{
	if (LAUNCH_DATA_ARRAY != where->type)
		return 0;
	return where->_array_cnt;
}

bool launch_data_set_fd(launch_data_t d, int fd)
{
	d->fd = fd;
	return true;
}

bool launch_data_set_integer(launch_data_t d, long long n)
{
	d->number = n;
	return true;
}

bool launch_data_set_bool(launch_data_t d, bool b)
{
	d->boolean = b;
	return true;
}

bool launch_data_set_real(launch_data_t d, double n)
{
	d->float_num = n;
	return true;
}

bool launch_data_set_string(launch_data_t d, const char *s)
{
	if (d->string)
		free(d->string);
	d->string = strdup(s);
	if (d->string) {
		d->string_len = strlen(d->string);
		return true;
	}
	return false;
}

bool launch_data_set_opaque(launch_data_t d, void *o, size_t os)
{
	d->opaque_size = os;
	if (d->opaque)
		free(d->opaque);
	d->opaque = malloc(os);
	if (d->opaque) {
		memcpy(d->opaque, o, os);
		return true;
	}
	return false;
}

int launch_data_get_fd(launch_data_t d)
{
	return d->fd;
}

long long launch_data_get_integer(launch_data_t d)
{
	return d->number;
}

bool launch_data_get_bool(launch_data_t d)
{
	return d->boolean;
}

double launch_data_get_real(launch_data_t d)
{
	return d->float_num;
}

const char *launch_data_get_string(launch_data_t d)
{
	if (LAUNCH_DATA_STRING != d->type)
		return NULL;
	return d->string;
}

void *launch_data_get_opaque(launch_data_t d)
{
	if (LAUNCH_DATA_OPAQUE != d->type)
		return NULL;
	return d->opaque;
}

size_t launch_data_get_opaque_size(launch_data_t d)
{
	return d->opaque_size;
}

int launchd_getfd(launch_t l)
{
	return l->fd;
}

launch_t launchd_fdopen(int fd)
{
        launch_t c;

        c = calloc(1, sizeof(struct _launch));
	if (!c)
		return NULL;

        c->fd = fd;

        if ((c->sendbuf = malloc(0)) == NULL)
		goto out_bad;
        if ((c->sendfds = malloc(0)) == NULL)
		goto out_bad;
        if ((c->recvbuf = malloc(0)) == NULL)
		goto out_bad;
        if ((c->recvfds = malloc(0)) == NULL)
		goto out_bad;

	return c;

out_bad:
	if (c->sendbuf)
		free(c->sendbuf);
	if (c->sendfds)
		free(c->sendfds);
	if (c->recvbuf)
		free(c->recvbuf);
	if (c->recvfds)
		free(c->recvfds);
	free(c);
	return NULL;
}

void launchd_close(launch_t lh)
{
	if (lh->sendbuf)
		free(lh->sendbuf);
	if (lh->sendfds)
		free(lh->sendfds);
	if (lh->recvbuf)
		free(lh->recvbuf);
	if (lh->recvfds)
		free(lh->recvfds);
	close(lh->fd);
	free(lh);
}

static void make_msg_and_cmsg(launch_data_t d, void **where, size_t *len, int **fd_where, size_t *fdcnt)
{
	size_t i;

	*where = realloc(*where, *len + sizeof(struct _launch_data));
	memcpy(*where + *len, d, sizeof(struct _launch_data));
	*len += sizeof(struct _launch_data);

	switch (d->type) {
	case LAUNCH_DATA_FD:
		*fd_where = realloc(*fd_where, (*fdcnt + 1) * sizeof(int));
		(*fd_where)[*fdcnt] = d->fd;
		(*fdcnt)++;
		break;
	case LAUNCH_DATA_STRING:
		*where = realloc(*where, *len + strlen(d->string) + 1);
		memcpy(*where + *len, d->string, strlen(d->string) + 1);
		*len += strlen(d->string) + 1;
		break;
	case LAUNCH_DATA_OPAQUE:
		*where = realloc(*where, *len + d->opaque_size);
		memcpy(*where + *len, d->opaque, d->opaque_size);
		*len += d->opaque_size;
		break;
	case LAUNCH_DATA_DICTIONARY:
	case LAUNCH_DATA_ARRAY:
		*where = realloc(*where, *len + (d->_array_cnt * sizeof(launch_data_t)));
		memcpy(*where + *len, d->_array, d->_array_cnt * sizeof(launch_data_t));
		*len += d->_array_cnt * sizeof(launch_data_t);

		for (i = 0; i < d->_array_cnt; i++)
			make_msg_and_cmsg(d->_array[i], where, len, fd_where, fdcnt);
		break;
	default:
		break;
	}
}

static launch_data_t make_data(launch_t conn, size_t *data_offset, size_t *fdoffset)
{
	launch_data_t r = conn->recvbuf + *data_offset;
	size_t i;

	if ((conn->recvlen - *data_offset) < sizeof(struct _launch_data))
		return NULL;
	*data_offset += sizeof(struct _launch_data);

	switch (r->type) {
	case LAUNCH_DATA_DICTIONARY:
	case LAUNCH_DATA_ARRAY:
		if ((conn->recvlen - *data_offset) < (r->_array_cnt * sizeof(launch_data_t))) {
			errno = EAGAIN;
			return NULL;
		}
		r->_array = conn->recvbuf + *data_offset;
		*data_offset += r->_array_cnt * sizeof(launch_data_t);
		for (i = 0; i < r->_array_cnt; i++) {
			r->_array[i] = make_data(conn, data_offset, fdoffset);
			if (r->_array[i] == NULL)
				return NULL;
		}
		break;
	case LAUNCH_DATA_STRING:
		if ((conn->recvlen - *data_offset) < (r->string_len + 1)) {
			errno = EAGAIN;
			return NULL;
		}
		r->string = conn->recvbuf + *data_offset;
		*data_offset += r->string_len + 1;
		break;
	case LAUNCH_DATA_OPAQUE:
		if ((conn->recvlen - *data_offset) < r->opaque_size) {
			errno = EAGAIN;
			return NULL;
		}
		r->opaque = conn->recvbuf + *data_offset;
		*data_offset += r->opaque_size;
		break;
	case LAUNCH_DATA_FD:
		r->fd = conn->recvfds[*fdoffset];
		*fdoffset += 1;
		break;
	case LAUNCH_DATA_INTEGER:
	case LAUNCH_DATA_REAL:
	case LAUNCH_DATA_BOOL:
		break;
	default:
		errno = EINVAL;
		return NULL;
		break;
	}

	return r;
}

int launchd_msg_send(launch_t lh, launch_data_t d)
{
	struct cmsghdr *cm = NULL;
	struct msghdr mh;
	struct iovec iov;
	int r;
	size_t sentctrllen = 0;

	memset(&mh, 0, sizeof(mh));

	mh.msg_iov = &iov;
        mh.msg_iovlen = 1;

	make_msg_and_cmsg(d, &lh->sendbuf, &lh->sendlen, &lh->sendfds, &lh->sendfdcnt);

	if (lh->sendfdcnt > 0) {
		sentctrllen = mh.msg_controllen = CMSG_SPACE(lh->sendfdcnt * sizeof(int));
		cm = alloca(mh.msg_controllen);
		mh.msg_control = cm;

		memset(cm, 0, mh.msg_controllen);

		cm->cmsg_len = CMSG_LEN(lh->sendfdcnt * sizeof(int));
		cm->cmsg_level = SOL_SOCKET;
		cm->cmsg_type = SCM_RIGHTS;

		memcpy(CMSG_DATA(cm), lh->sendfds, lh->sendfdcnt * sizeof(int));
	}

	iov.iov_base = lh->sendbuf;
	iov.iov_len = lh->sendlen;

	if ((r = sendmsg(lh->fd, &mh, 0)) == -1) {
		return -1;
	} else if (r == 0) {
		errno = ECONNRESET;
		return -1;
	} else if (sentctrllen != mh.msg_controllen) {
		errno = ECONNRESET;
		return -1;
	}

	lh->sendlen -= r;
	memmove(lh->sendbuf, lh->sendbuf + r, lh->sendlen);
	lh->sendbuf = realloc(lh->sendbuf, lh->sendlen);

	lh->sendfdcnt = 0;
	lh->sendfds = realloc(lh->sendfds, 0);

	if (lh->sendlen > 0) {
		errno = EAGAIN;
		return -1;
	}

	return 0;
}


int launch_get_fd(void)
{
	pthread_once(&_lc_once, launch_client_init);

	if (!_lc) {
		errno = ENOTCONN;
		return -1;
	}

	return _lc->l->fd;
}

static void launch_msg_getmsgs(launch_data_t m, void *context)
{
	launch_data_t async_resp, *sync_resp = context;
	
	if ((LAUNCH_DATA_DICTIONARY == launch_data_get_type(m)) && (async_resp = launch_data_dict_lookup(m, LAUNCHD_ASYNC_MSG_KEY))) {
		launch_data_array_set_index(_lc->async_resp, launch_data_copy(async_resp), launch_data_array_get_count(_lc->async_resp));
	} else {
		*sync_resp = launch_data_copy(m);
	}
}

launch_data_t launch_msg(launch_data_t d)
{
	launch_data_t resp = NULL;

	pthread_once(&_lc_once, launch_client_init);

	if (!_lc) {
		errno = ENOTCONN;
		return NULL;
	}

	pthread_mutex_lock(&_lc->mtx);

	if (d) {
		if (launchd_msg_send(_lc->l, d) == -1)
			goto out;
	} else if (launch_data_array_get_count(_lc->async_resp) > 0) {
		resp = launch_data_array_pop_first(_lc->async_resp);
		goto out;
	}

	while (resp == NULL) {
		if (launchd_msg_recv(_lc->l, launch_msg_getmsgs, &resp) == -1 && errno != EAGAIN)
			goto out;
	}

out:
	pthread_mutex_unlock(&_lc->mtx);

	return resp;
}

int launchd_msg_recv(launch_t lh, void (*cb)(launch_data_t, void *), void *context)
{
	struct cmsghdr *cm = alloca(4096); 
	launch_data_t rmsg;
	size_t data_offset = 0, fd_offset = 0;
        struct msghdr mh;
        struct iovec iov;
	int r;

        memset(&mh, 0, sizeof(mh));
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;

	lh->recvbuf = realloc(lh->recvbuf, lh->recvlen + 8*1024);

	iov.iov_base = lh->recvbuf + lh->recvlen;
	iov.iov_len = 8*1024;
	mh.msg_control = cm;
	mh.msg_controllen = 4096;

	if ((r = recvmsg(lh->fd, &mh, 0)) == -1)
		return -1;
	if (r == 0) {
		errno = ECONNRESET;
		return -1;
	}
	if (mh.msg_flags & MSG_CTRUNC) {
		errno = ECONNABORTED;
		return -1;
	}
	lh->recvlen += r;
	if (mh.msg_controllen > 0) {
		lh->recvfds = realloc(lh->recvfds, lh->recvfdcnt * sizeof(int) + mh.msg_controllen - sizeof(struct cmsghdr));
		memcpy(lh->recvfds + lh->recvfdcnt, CMSG_DATA(cm), mh.msg_controllen - sizeof(struct cmsghdr));
		lh->recvfdcnt += (mh.msg_controllen - sizeof(struct cmsghdr)) / sizeof(int);
	}

parse_more:
	rmsg = make_data(lh, &data_offset, &fd_offset);

	if (rmsg) {
		cb(rmsg, context);

		lh->recvlen -= data_offset;
		memmove(lh->recvbuf, lh->recvbuf + data_offset, lh->recvlen);
		lh->recvbuf = realloc(lh->recvbuf, lh->recvlen);

		lh->recvfdcnt -= fd_offset;
		memmove(lh->recvfds, lh->recvfds + fd_offset, lh->recvfdcnt * sizeof(int));
		lh->recvfds = realloc(lh->recvfds, lh->recvfdcnt * sizeof(int));

		if (lh->recvlen > 0)
			goto parse_more;
		else
			r = 0;
	} else {
		errno = EAGAIN;
		r = -1;
	}

	return r;
}

launch_data_t launch_data_copy(launch_data_t o)
{
	launch_data_t r = launch_data_alloc(o->type);
	size_t i;

	memcpy(r, o, sizeof(struct _launch_data));

	switch (o->type) {
	case LAUNCH_DATA_DICTIONARY:
	case LAUNCH_DATA_ARRAY:
		r->_array = calloc(1, o->_array_cnt * sizeof(launch_data_t));
		for (i = 0; i < o->_array_cnt; i++) {
			if (o->_array[i])
				r->_array[i] = launch_data_copy(o->_array[i]);
		}
		break;
	case LAUNCH_DATA_STRING:
		r->string = strdup(o->string);
		break;
	case LAUNCH_DATA_OPAQUE:
		r->opaque = malloc(o->opaque_size);
		memcpy(r->opaque, o->opaque, o->opaque_size);
		break;
	default:
		break;
	}

	return r;
}

void launchd_batch_enable(bool val)
{
	launch_data_t resp, tmp, msg;

	tmp = launch_data_alloc(LAUNCH_DATA_BOOL);
	launch_data_set_bool(tmp, val);

	msg = launch_data_alloc(LAUNCH_DATA_DICTIONARY);
	launch_data_dict_insert(msg, tmp, LAUNCH_KEY_BATCHCONTROL);

	resp = launch_msg(msg);

	launch_data_free(msg);

	if (resp)
		launch_data_free(resp);
}

bool launchd_batch_query(void)
{
	launch_data_t resp, msg = launch_data_alloc(LAUNCH_DATA_STRING);
	bool rval = true;

	launch_data_set_string(msg, LAUNCH_KEY_BATCHQUERY);

	resp = launch_msg(msg);

	launch_data_free(msg);

	if (resp) {
		if (launch_data_get_type(resp) == LAUNCH_DATA_BOOL)
			rval = launch_data_get_bool(resp);
		launch_data_free(resp);
	}
	return rval;
}

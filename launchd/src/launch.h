#ifndef _LAUNCH_H_
#define _LAUNCH_H_

#include <stddef.h>
#include <stdbool.h>

typedef struct _launch_data *launch_data_t;

typedef enum {
	LAUNCH_DATA_DICTIONARY = 1,
	LAUNCH_DATA_ARRAY,
	LAUNCH_DATA_FD,
	LAUNCH_DATA_INTEGER,
	LAUNCH_DATA_REAL,
	LAUNCH_DATA_BOOL,
	LAUNCH_DATA_STRING,
	LAUNCH_DATA_OPAQUE,
} launch_data_type_t;

launch_data_t		launch_data_alloc(launch_data_type_t);
launch_data_type_t	launch_data_get_type(launch_data_t);
void			launch_data_free(launch_data_t);

/* kLaunchDataDictionary */
/* the value should not be changed while iterating */
bool		launch_data_dict_insert(launch_data_t, launch_data_t, const char *);
launch_data_t	launch_data_dict_lookup(launch_data_t, const char *);
bool		launch_data_dict_remove(launch_data_t, const char *);
void		launch_data_dict_iterate(launch_data_t, void (*)(launch_data_t, const char *, void *), void *);

/* kLaunchDataArray */
bool		launch_data_array_set_index(launch_data_t, launch_data_t, size_t);
launch_data_t	launch_data_array_get_index(launch_data_t, size_t);
size_t		launch_data_array_get_count(launch_data_t);

bool		launch_data_set_fd(launch_data_t, int);
bool		launch_data_set_integer(launch_data_t, long long);
bool		launch_data_set_bool(launch_data_t, bool);
bool		launch_data_set_real(launch_data_t, double);
bool		launch_data_set_string(launch_data_t, const char *);
bool		launch_data_set_opaque(launch_data_t, void *, size_t);

int		launch_data_get_fd(launch_data_t);
long long	launch_data_get_integer(launch_data_t);
bool		launch_data_get_bool(launch_data_t);
double		launch_data_get_real(launch_data_t);
const char *	launch_data_get_string(launch_data_t);
void *		launch_data_get_opaque(launch_data_t);
size_t		launch_data_get_opaque_size(launch_data_t);


/* launch_get_fd()
 *
 * Use this to get the FD if you're doing asynchronous I/O with select(),
 * poll() or kevent().
 */
int launch_get_fd(void);

/* launch_msg()
 *
 * Use this API to send and receive messages.
 * Calling launch_msg() with no message to send is a valid way to get
 * asynchronously received messages.
 *
 * If a message was to be sent, it returns NULL and errno on failure.
 *
 * If no messages were to be sent, it returns NULL and errno is set to zero if
 * no more asynchronous messages are available.
 */
launch_data_t launch_msg(launch_data_t);

#endif

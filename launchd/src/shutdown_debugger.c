#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach_debug/ipc_info.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/event.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>

extern char **environ;

struct hproc {
	TAILQ_ENTRY(hproc) tqe;
	pid_t stuck_p;
	pid_t sample_p;
};

static void hproc_new(pid_t p, const char *pname);

static TAILQ_HEAD(hproc_head, hproc) hprocs = TAILQ_HEAD_INITIALIZER(hprocs);

static void populate_proc_list(void);
static void debug_machports(pid_t pid, const char *pname);
static void debug_machports2(pid_t pid, FILE *where);
static void do_stackshot(void);

static int kq;

#define SHUTDOWN_LOG_DIR "/var/log/shutdown"

int
main(void)
{
	struct kevent kev;
	struct stat sb;
	struct hproc *hp;
	struct dirent *de;
	DIR *thedir;
	int wstatus;

	mkdir(SHUTDOWN_LOG_DIR, S_IRWXU);

	assert(lstat(SHUTDOWN_LOG_DIR, &sb) != -1);

	assert(S_ISDIR(sb.st_mode));

	assert(chdir(SHUTDOWN_LOG_DIR) != -1);

	assert((thedir = opendir(".")) != NULL);

	while ((de = readdir(thedir))) {
		if (strcmp(de->d_name, ".") == 0) {
			continue;
		} else if (strcmp(de->d_name, "..") == 0) {
			continue;
		} else {
			remove(de->d_name);
		}
	}

	closedir(thedir);

	do_stackshot();

	assert((kq = kqueue()) != -1);

	debug_machports(1, "launchd");

	populate_proc_list();

	while (!TAILQ_EMPTY(&hprocs)) {
		assert(kevent(kq, NULL, 0, &kev, 1, NULL) != -1);
		
		hp = kev.udata;

		assert(waitpid(hp->sample_p, &wstatus, 0) != -1);

		TAILQ_REMOVE(&hprocs, hp, tqe);
	}

	exit(EXIT_SUCCESS);
}

void
populate_proc_list(void)
{
	int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
	struct kinfo_proc *kp = NULL;
	size_t i, len = 0;

	assert(sysctl(mib, 3, kp, &len, NULL, 0) != -1);

	assert((kp = malloc(len * 2)) != NULL);

	assert(sysctl(mib, 3, kp, &len, NULL, 0) != -1);

	for (i = 0; i < (len / sizeof(struct kinfo_proc)); i++) {
		pid_t p_iter = kp[i].kp_proc.p_pid;

		if (p_iter == 0 || p_iter == 1 || p_iter == getpid()) {
			continue;
		}

		hproc_new(p_iter, kp[i].kp_proc.p_comm);
	}

	free(kp);
}

void
hproc_new(pid_t p, const char *pname)
{
	char pidstr[100], logfile[PATH_MAX];
	char *sample_args[] = { "sample", pidstr, "1", "-mayDie", "-file", logfile, NULL };
	posix_spawnattr_t spattr;
	struct kevent kev;
	struct hproc *hp;
	pid_t sp;

	debug_machports(p, pname);

	assert((hp = calloc(1, sizeof(struct hproc))) != NULL);

	assert(posix_spawnattr_init(&spattr) == 0);

	assert(posix_spawnattr_setflags(&spattr, POSIX_SPAWN_START_SUSPENDED) == 0);

	snprintf(pidstr, sizeof(pidstr), "%u", p);
	snprintf(logfile, sizeof(logfile), "%s-%u.sample.txt", pname, p);

	assert(posix_spawnp(&sp, sample_args[0], NULL, &spattr, sample_args, environ) == 0);

	assert(posix_spawnattr_destroy(&spattr) == 0);

	EV_SET(&kev, sp, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, hp);

	assert(kevent(kq, &kev, 1, NULL, 0, NULL) != -1);

	assert(kill(sp, SIGCONT) != -1);

	hp->stuck_p = p;
	hp->sample_p = sp;

	TAILQ_INSERT_TAIL(&hprocs, hp, tqe);
}

void
debug_machports(pid_t pid, const char *pname)
{
	char logfilepath[PATH_MAX];
	FILE *mplogfile;

	snprintf(logfilepath, sizeof(logfilepath), "%s-%u.machports.txt", pname, pid);

	assert((mplogfile = fopen(logfilepath, "a")) != NULL);

	debug_machports2(pid, mplogfile);

	fclose(mplogfile);
}


/*
 * WARNING - these types are copied from xnu/osfmk/kern/ipc_kobject.h
 * Need to stay in sync to print accurate results.
 */
#define	IKOT_NONE				0
#define IKOT_THREAD				1
#define	IKOT_TASK				2
#define	IKOT_HOST				3
#define	IKOT_HOST_PRIV			4
#define	IKOT_PROCESSOR			5
#define	IKOT_PSET				6
#define	IKOT_PSET_NAME			7
#define	IKOT_TIMER				8
#define	IKOT_PAGING_REQUEST		9
#define	IKOT_MIG				10
#define	IKOT_MEMORY_OBJECT		11
#define	IKOT_XMM_PAGER			12
#define	IKOT_XMM_KERNEL			13
#define	IKOT_XMM_REPLY			14
#define IKOT_UND_REPLY			15
#define IKOT_HOST_NOTIFY		16
#define IKOT_HOST_SECURITY		17
#define	IKOT_LEDGER				18
#define IKOT_MASTER_DEVICE		19
#define IKOT_TASK_NAME			20
#define IKOT_SUBSYSTEM			21
#define IKOT_IO_DONE_QUEUE		22
#define IKOT_SEMAPHORE			23
#define IKOT_LOCK_SET			24
#define IKOT_CLOCK				25
#define IKOT_CLOCK_CTRL			26
#define IKOT_IOKIT_SPARE		27
#define IKOT_NAMED_ENTRY		28
#define IKOT_IOKIT_CONNECT		29
#define IKOT_IOKIT_OBJECT		30
#define IKOT_UPL				31

static const char *
kobject_name(natural_t kotype)
{
	switch (kotype) {
	case IKOT_NONE: return "message-queue";
	case IKOT_THREAD: return "kobject(THREAD)";
	case IKOT_TASK: return "kobject(TASK)";
	case IKOT_HOST: return "kobject(HOST)";
	case IKOT_HOST_PRIV: return "kobject(HOST-PRIV)";
	case IKOT_PROCESSOR: return "kobject(PROCESSOR)";
	case IKOT_PSET: return "kobject(PROCESSOR-SET)";
	case IKOT_PSET_NAME: return "kobject(PROCESSOR-SET-NAME)";
	case IKOT_TIMER: return "kobject(TIMER)";
	case IKOT_PAGING_REQUEST: return "kobject(PAGER-REQUEST)";
	case IKOT_MIG: return "kobject(MIG)";
	case IKOT_MEMORY_OBJECT: return "kobject(MEMORY-OBJECT)";
	case IKOT_XMM_PAGER: return "kobject(XMM-PAGER)";
	case IKOT_XMM_KERNEL: return "kobject(XMM-KERNEL)";
	case IKOT_XMM_REPLY: return "kobject(XMM-REPLY)";
	case IKOT_UND_REPLY: return "kobject(UND-REPLY)";
	case IKOT_HOST_NOTIFY: return "message-queue";
	case IKOT_HOST_SECURITY: return "kobject(HOST-SECURITY)";
	case IKOT_LEDGER: return "kobject(LEDGER)";
	case IKOT_MASTER_DEVICE: return "kobject(MASTER-DEVICE)";
	case IKOT_TASK_NAME: return "kobject(TASK-NAME)";
	case IKOT_SUBSYSTEM: return "kobject(SUBSYSTEM)";
	case IKOT_IO_DONE_QUEUE: return "kobject(IO-QUEUE-DONE)";
	case IKOT_SEMAPHORE: return "kobject(SEMAPHORE)";
	case IKOT_LOCK_SET: return "kobject(LOCK-SET)";
	case IKOT_CLOCK: return "kobject(CLOCK)";
	case IKOT_CLOCK_CTRL: return "kobject(CLOCK-CONTROL)";
	case IKOT_IOKIT_SPARE: return "kobject(IOKIT-SPARE)";
	case IKOT_NAMED_ENTRY: return "kobject(NAMED-MEMORY)";
	case IKOT_IOKIT_CONNECT: return "kobject(IOKIT-CONNECT)";
	case IKOT_IOKIT_OBJECT: return "kobject(IOKIT-OBJECT)";
	case IKOT_UPL: return "kobject(UPL)";
	default: return "kobject(UNKNOWN)";
	}
}

/* private structure to wrap up per-task info */
typedef struct my_per_task_info {
		task_t task;
		pid_t pid;
		ipc_info_space_t info;
		ipc_info_name_array_t table;
		mach_msg_type_number_t tableCount;
		ipc_info_tree_name_array_t tree;
		mach_msg_type_number_t treeCount;
} my_per_task_info_t;

void
debug_machports2(pid_t pid, FILE *where)
{
	kern_return_t ret;
	my_per_task_info_t aTask;
	my_per_task_info_t *taskinfo = NULL;
	my_per_task_info_t *psettaskinfo;
	mach_msg_type_number_t i, j, k, taskCount;
	int emptycount = 0, portsetcount = 0, sendcount = 0, receivecount = 0, sendoncecount = 0, deadcount = 0, dncount = 0;

	/* if priviledged, get the info for all tasks so we can match ports up */
	if (geteuid() == 0) {
		processor_set_name_array_t psets;
		mach_msg_type_number_t psetCount;
		mach_port_t pset_priv;
		task_array_t tasks;
		
		ret = host_processor_sets(mach_host_self(), &psets, &psetCount);
		if (ret != KERN_SUCCESS) {
			fprintf(where, "host_processor_sets() failed: %s\n", mach_error_string(ret));
			return;
		}
		if (psetCount != 1) {
			fprintf(where, "Assertion Failure: pset count greater than one (%d)\n", psetCount);
			return;
		}

		/* convert the processor-set-name port to a privileged port */
		ret = host_processor_set_priv(mach_host_self(), psets[0], &pset_priv);
		if (ret != KERN_SUCCESS) {
			fprintf(where, "host_processor_set_priv() failed: %s\n", mach_error_string(ret));
			return;
		}
		mach_port_deallocate(mach_task_self(), psets[0]);
		vm_deallocate(mach_task_self(), (vm_address_t)psets, (vm_size_t)psetCount * sizeof(mach_port_t));

		/* convert the processor-set-priv to a list of tasks for the processor set */
		ret = processor_set_tasks(pset_priv, &tasks, &taskCount);
		if (ret != KERN_SUCCESS) {
			fprintf(where, "processor_set_tasks() failed: %s\n", mach_error_string(ret));
			return;
		}
		mach_port_deallocate(mach_task_self(), pset_priv);

		/* convert each task to structure of pointer for the task info */
		psettaskinfo = (my_per_task_info_t *)malloc(taskCount * sizeof(my_per_task_info_t));
		for (i = 0; i < taskCount; i++) {
			psettaskinfo[i].task = tasks[i];
			pid_for_task(tasks[i], &psettaskinfo[i].pid);
			ret = mach_port_space_info(tasks[i], &psettaskinfo[i].info,
									   &psettaskinfo[i].table, &psettaskinfo[i].tableCount,
									   &psettaskinfo[i].tree, &psettaskinfo[i].treeCount);
			if (ret != KERN_SUCCESS) {
				fprintf(where, "mach_port_space_info() failed: %s\n", mach_error_string(ret));
				return;
			}
			if (psettaskinfo[i].pid == pid)
				taskinfo = &psettaskinfo[i];
		}
		vm_deallocate(mach_task_self(), (vm_address_t)tasks, (vm_size_t)taskCount * sizeof(mach_port_t));
	}
	else
	{
		/* just the one process */
		ret = task_for_pid((mach_task_self)(), pid, &aTask.task);
		if (ret != KERN_SUCCESS) {
			fprintf(where, "task_for_pid() failed: %s\n", mach_error_string(ret));
			return;
		}
		ret = mach_port_space_info(aTask.task, &aTask.info,
								   &aTask.table, &aTask.tableCount,
								   &aTask.tree, &aTask.treeCount);
		if (ret != KERN_SUCCESS) {
			fprintf(where, "mach_port_space_info() failed: %s\n", mach_error_string(ret));
			return;
		}
		taskinfo = &aTask;
		psettaskinfo = taskinfo;
		taskCount = 1;
	}

	fprintf(where, "set-name    ipc-object  rights      ");
	fprintf(where, "                  member-cnt\n");
	fprintf(where, "recv-name   ipc-object  rights      ");
	fprintf(where, "reqs urefs orefs  qlimit      msgcount\n");
	fprintf(where, "send-name   ipc-object  rights      ");
	fprintf(where, "reqs urefs orefs  kern-object type\n");
	fprintf(where, "--------where, -   ----------  ----------  ");
	fprintf(where, "---where, - ----- -----  ----------- ------------\n");

	for (i = 0; i < taskinfo->tableCount; i++) {
		boolean_t found = FALSE;
		boolean_t sendr = FALSE;
		boolean_t sendonce = FALSE;
		boolean_t dnreq = FALSE;
		int sendrights = 0;
		unsigned int kotype = 0;
		vm_offset_t kobject = (vm_offset_t)0;

		/* skip empty slots in the table */
		if (taskinfo->table[i].iin_object == 0) {
			emptycount++;
			continue;
		}

		if (taskinfo->table[i].iin_type == MACH_PORT_TYPE_PORT_SET) {
			mach_port_name_array_t members;
			mach_msg_type_number_t membersCnt;
			
			ret = mach_port_get_set_status(taskinfo->task, 
										   taskinfo->table[i].iin_name,
										   &members, &membersCnt);
			if (ret != KERN_SUCCESS) {
				fprintf(where, "mach_port_get_set_status(0x%08x) failed: %s\n",
						taskinfo->table[i].iin_name,
						mach_error_string(ret));
				continue;
			}
			fprintf(where, "0x%08x  0x%08x  port-set    ---      1 %5d  members\n",
				   taskinfo->table[i].iin_name,
				   taskinfo->table[i].iin_object,
				   membersCnt);
			/* get some info for each portset member */
			for (j = 0; j < membersCnt; j++) {
				for (k = 0; k < taskinfo->tableCount; k++) {
					if (taskinfo->table[k].iin_name == members[j]) {
						fprintf(where, "            0x%08x  %s  ---               0x%08x  process(%d)\n",
							   taskinfo->table[k].iin_object,
							   (taskinfo->table[k].iin_type & MACH_PORT_TYPE_SEND) ? "recv,send ":"recv      ",
							   taskinfo->table[k].iin_name,
							   pid);
						break;
					}
				}
			}

			ret = vm_deallocate(mach_task_self(), (vm_address_t)members,
								membersCnt * sizeof(mach_port_name_t));
			if (ret != KERN_SUCCESS) {
				fprintf(where, "vm_deallocate() failed: %s\n",
						mach_error_string(ret));
				return;
			}
			portsetcount++;
			continue;
		}

		if (taskinfo->table[i].iin_type & MACH_PORT_TYPE_SEND) {
			sendr = TRUE;
			sendrights = taskinfo->table[i].iin_urefs;
			sendcount++;
		}
		
		if (taskinfo->table[i].iin_type & MACH_PORT_TYPE_SEND_ONCE) {
			sendonce = TRUE;
			sendoncecount++;
		}
		
		if (taskinfo->table[i].iin_type & MACH_PORT_TYPE_DNREQUEST) {
			dnreq = TRUE;
			dncount++;
		}
			   
		if (taskinfo->table[i].iin_type & MACH_PORT_TYPE_RECEIVE) {
			mach_port_status_t status;
			mach_msg_type_number_t statusCnt;
			
			statusCnt = MACH_PORT_RECEIVE_STATUS_COUNT;
			ret = mach_port_get_attributes(taskinfo->task,
										   taskinfo->table[i].iin_name,
										   MACH_PORT_RECEIVE_STATUS,
										   (mach_port_info_t)&status,
										   &statusCnt);
			if (ret != KERN_SUCCESS) {
				fprintf(where, "mach_port_get_attributes(0x%08x) failed: %s\n",
						taskinfo->table[i].iin_name,
						mach_error_string(ret));
				continue;
			}

			fprintf(where, "0x%08x  0x%08x  %s  %s%s%s  %5d %s(%02d)  0x%08x  0x%08x\n",
				   taskinfo->table[i].iin_name,
				   taskinfo->table[i].iin_object,
				   (sendr) ? "recv,send ":"recv      ",
				   (dnreq) ? "D":"-",
				   (status.mps_nsrequest) ? "N":"-",
				   (status.mps_pdrequest) ? "P":"-",
				   sendrights + 1,
				   (status.mps_srights) ? "Y":"N",
				   status.mps_sorights,
				   status.mps_qlimit,
				   status.mps_msgcount);
			receivecount++;

			/* show other rights (in this and other tasks) for the port */
			for (j = 0; j < taskCount; j++) {
				for (k = 0; k < psettaskinfo->tableCount; k++) {
					if (&psettaskinfo[j].table[k] == &taskinfo->table[i] ||
						psettaskinfo[j].table[k].iin_object != taskinfo->table[i].iin_object)
						continue;
					fprintf(where, "            0x%08x  %s  ---  %5d        0x%08x  process(%d)\n",
						   psettaskinfo[j].table[k].iin_object,
						   (psettaskinfo[j].table[k].iin_type & MACH_PORT_TYPE_SEND_ONCE) ?
					       "send-once " : "send      ",
						   psettaskinfo[j].table[k].iin_urefs,
						   psettaskinfo[j].table[k].iin_name,
						   psettaskinfo[j].pid);
				}
			}
			continue;
		} 
		else if (taskinfo->table[i].iin_type & MACH_PORT_TYPE_DEAD_NAME)
		{
			fprintf(where, "0x%08x  0x%08x  dead-name   --- %5d\n",
				   taskinfo->table[i].iin_name,
				   taskinfo->table[i].iin_object,
				   taskinfo->table[i].iin_urefs);
			deadcount++;
			continue;
		}

		fprintf(where, "0x%08x  0x%08x  %s  %s%s%s  %5d        ",
			   taskinfo->table[i].iin_name,
			   taskinfo->table[i].iin_object,
			   (sendr) ? "send      ":"send-once ",
			   (dnreq) ? "D":"-",
			   "-",
			   "-",
			   (sendr) ? sendrights : 1);
		
		/* converting to kobjects is not always supported */
		ret = mach_port_kernel_object(taskinfo->task,
									  taskinfo->table[i].iin_name,
									  &kotype, &kobject);
		if (kotype != 0) {
			fprintf(where, "0x%08x  %s\n", kobject, kobject_name(kotype));
			continue;
		}

		/* not kobject - find the receive right holder */
		for (j = 0; j < taskCount && !found; j++) {
			for (k = 0; k < psettaskinfo[j].tableCount && !found; k++) {
				if ((psettaskinfo[j].table[k].iin_type & MACH_PORT_TYPE_RECEIVE) &&
					psettaskinfo[j].table[k].iin_object == taskinfo->table[i].iin_object ) {
					fprintf(where, "0x%08x  process(%d)\n", 
						   psettaskinfo[j].table[k].iin_name,
						   psettaskinfo[j].pid);
					found = TRUE;
				}
			}
		}
		if (!found)
			fprintf(where, "0x00000000  process(unknown)\n");
	}
	fprintf(where, "total     = %d\n", taskinfo->tableCount + taskinfo->treeCount - emptycount);
	fprintf(where, "SEND      = %d\n", sendcount);
	fprintf(where, "RECEIVE   = %d\n", receivecount);
	fprintf(where, "SEND_ONCE = %d\n", sendoncecount);
	fprintf(where, "PORT_SET  = %d\n", portsetcount);
	fprintf(where, "DEAD_NAME = %d\n", deadcount);
	fprintf(where, "DNREQUEST = %d\n", dncount);

	if (taskCount > 1)
		free(psettaskinfo);

	fprintf(where, "Finished.\n");
	return;
}

void
do_stackshot(void)
{
	/* yes, we really mean to exec without fork at this point in time */
	execl("/usr/libexec/stackshot", "/usr/libexec/stackshot", "-i", "-f", "./shutdown-stackshot.log", NULL);
	_exit(EXIT_FAILURE);
}

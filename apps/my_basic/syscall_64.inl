static char syscall_0_334[][24] = {
    "read",                  // 0	common	read			sys_read
    "write",                 // 1	common	write			sys_write
    "open",                  // 2	common	open			sys_open
    "close",                 // 3	common	close			sys_close
    "stat",                  // 4	common	stat			sys_newstat
    "fstat",                 // 5	common	fstat			sys_newfstat
    "lstat",                 // 6	common	lstat			sys_newlstat
    "poll",                  // 7	common	poll			sys_poll
    "lseek",                 // 8	common	lseek			sys_lseek
    "mmap",                  // 9	common	mmap			sys_mmap
    "mprotect",              // 10	common	mprotect		sys_mprotect
    "munmap",                // 11	common	munmap			sys_munmap
    "brk",                   // 12	common	brk			sys_brk
    "rt_sigaction",          // 13	64	rt_sigaction		sys_rt_sigaction
    "rt_sigprocmask",        // 14	common	rt_sigprocmask		sys_rt_sigprocmask
    "rt_sigreturn",          // 15	64	rt_sigreturn		sys_rt_sigreturn
    "ioctl",                 // 16	64	ioctl			sys_ioctl
    "pread64",               // 17	common	pread64			sys_pread64
    "pwrite64",              // 18	common	pwrite64		sys_pwrite64
    "readv",                 // 19	64	readv			sys_readv
    "writev",                // 20	64	writev			sys_writev
    "access",                // 21	common	access			sys_access
    "pipe",                  // 22	common	pipe			sys_pipe
    "select",                // 23	common	select			sys_select
    "sched_yield",           // 24	common	sched_yield		sys_sched_yield
    "mremap",                // 25	common	mremap			sys_mremap
    "msync",                 // 26	common	msync			sys_msync
    "mincore",               // 27	common	mincore			sys_mincore
    "madvise",               // 28	common	madvise			sys_madvise
    "shmget",                // 29	common	shmget			sys_shmget
    "shmat",                 // 30	common	shmat			sys_shmat
    "shmctl",                // 31	common	shmctl			sys_shmctl
    "dup",                   // 32	common	dup			sys_dup
    "dup2",                  // 33	common	dup2			sys_dup2
    "pause",                 // 34	common	pause			sys_pause
    "nanosleep",             // 35	common	nanosleep		sys_nanosleep
    "getitimer",             // 36	common	getitimer		sys_getitimer
    "alarm",                 // 37	common	alarm			sys_alarm
    "setitimer",             // 38	common	setitimer		sys_setitimer
    "getpid",                // 39	common	getpid			sys_getpid
    "sendfile",              // 40	common	sendfile		sys_sendfile64
    "socket",                // 41	common	socket			sys_socket
    "connect",               // 42	common	connect			sys_connect
    "accept",                // 43	common	accept			sys_accept
    "sendto",                // 44	common	sendto			sys_sendto
    "recvfrom",              // 45	64	recvfrom		sys_recvfrom
    "sendmsg",               // 46	64	sendmsg			sys_sendmsg
    "recvmsg",               // 47	64	recvmsg			sys_recvmsg
    "shutdown",              // 48	common	shutdown		sys_shutdown
    "bind",                  // 49	common	bind			sys_bind
    "listen",                // 50	common	listen			sys_listen
    "getsockname",           // 51	common	getsockname		sys_getsockname
    "getpeername",           // 52	common	getpeername		sys_getpeername
    "socketpair",            // 53	common	socketpair		sys_socketpair
    "setsockopt",            // 54	64	setsockopt		sys_setsockopt
    "getsockopt",            // 55	64	getsockopt		sys_getsockopt
    "clone",                 // 56	common	clone			sys_clone
    "fork",                  // 57	common	fork			sys_fork
    "vfork",                 // 58	common	vfork			sys_vfork
    "execve",                // 59	64	execve			sys_execve
    "exit",			         // 60	common	exit			sys_exit			-			noreturn
    "wait4",                 // 61	common	wait4			sys_wait4
    "kill",                  // 62	common	kill			sys_kill
    "uname",                 // 63	common	uname			sys_newuname
    "semget",                // 64	common	semget			sys_semget
    "semop",                 // 65	common	semop			sys_semop
    "semctl",                // 66	common	semctl			sys_semctl
    "shmdt",                 // 67	common	shmdt			sys_shmdt
    "msgget",                // 68	common	msgget			sys_msgget
    "msgsnd",                // 69	common	msgsnd			sys_msgsnd
    "msgrcv",                // 70	common	msgrcv			sys_msgrcv
    "msgctl",                // 71	common	msgctl			sys_msgctl
    "fcntl",                 // 72	common	fcntl			sys_fcntl
    "flock",                 // 73	common	flock			sys_flock
    "fsync",                 // 74	common	fsync			sys_fsync
    "fdatasync",             // 75	common	fdatasync		sys_fdatasync
    "truncate",              // 76	common	truncate		sys_truncate
    "ftruncate",             // 77	common	ftruncate		sys_ftruncate
    "getdents",              // 78	common	getdents		sys_getdents
    "getcwd",                // 79	common	getcwd			sys_getcwd
    "chdir",                 // 80	common	chdir			sys_chdir
    "fchdir",                // 81	common	fchdir			sys_fchdir
    "rename",                // 82	common	rename			sys_rename
    "mkdir",                 // 83	common	mkdir			sys_mkdir
    "rmdir",                 // 84	common	rmdir			sys_rmdir
    "creat",                 // 85	common	creat			sys_creat
    "link",                  // 86	common	link			sys_link
    "unlink",                // 87	common	unlink			sys_unlink
    "symlink",               // 88	common	symlink			sys_symlink
    "readlink",              // 89	common	readlink		sys_readlink
    "chmod",                 // 90	common	chmod			sys_chmod
    "fchmod",                // 91	common	fchmod			sys_fchmod
    "chown",                 // 92	common	chown			sys_chown
    "fchown",                // 93	common	fchown			sys_fchown
    "lchown",                // 94	common	lchown			sys_lchown
    "umask",                 // 95	common	umask			sys_umask
    "gettimeofday",          // 96	common	gettimeofday		sys_gettimeofday
    "getrlimit",             // 97	common	getrlimit		sys_getrlimit
    "getrusage",             // 98	common	getrusage		sys_getrusage
    "sysinfo",               // 99	common	sysinfo			sys_sysinfo
    "times",                 // 100	common	times			sys_times
    "ptrace",                // 101	64	ptrace			sys_ptrace
    "getuid",                // 102	common	getuid			sys_getuid
    "syslog",                // 103	common	syslog			sys_syslog
    "getgid",                // 104	common	getgid			sys_getgid
    "setuid",                // 105	common	setuid			sys_setuid
    "setgid",                // 106	common	setgid			sys_setgid
    "geteuid",               // 107	common	geteuid			sys_geteuid
    "getegid",               // 108	common	getegid			sys_getegid
    "setpgid",               // 109	common	setpgid			sys_setpgid
    "getppid",               // 110	common	getppid			sys_getppid
    "getpgrp",               // 111	common	getpgrp			sys_getpgrp
    "setsid",                // 112	common	setsid			sys_setsid
    "setreuid",              // 113	common	setreuid		sys_setreuid
    "setregid",              // 114	common	setregid		sys_setregid
    "getgroups",             // 115	common	getgroups		sys_getgroups
    "setgroups",             // 116	common	setgroups		sys_setgroups
    "setresuid",             // 117	common	setresuid		sys_setresuid
    "getresuid",             // 118	common	getresuid		sys_getresuid
    "setresgid",             // 119	common	setresgid		sys_setresgid
    "getresgid",             // 120	common	getresgid		sys_getresgid
    "getpgid",               // 121	common	getpgid			sys_getpgid
    "setfsuid",              // 122	common	setfsuid		sys_setfsuid
    "setfsgid",              // 123	common	setfsgid		sys_setfsgid
    "getsid",                // 124	common	getsid			sys_getsid
    "capget",                // 125	common	capget			sys_capget
    "capset",                // 126	common	capset			sys_capset
    "rt_sigpending",         // 127	64	rt_sigpending		sys_rt_sigpending
    "rt_sigtimedwait",       // 128	64	rt_sigtimedwait		sys_rt_sigtimedwait
    "rt_sigqueueinfo",       // 129	64	rt_sigqueueinfo		sys_rt_sigqueueinfo
    "rt_sigsuspend",         // 130	common	rt_sigsuspend		sys_rt_sigsuspend
    "sigaltstack",           // 131	64	sigaltstack		sys_sigaltstack
    "utime",                 // 132	common	utime			sys_utime
    "mknod",                 // 133	common	mknod			sys_mknod
    "uselib",                // 134	64	uselib
    "personality",           // 135	common	personality		sys_personality
    "ustat",                 // 136	common	ustat			sys_ustat
    "statfs",                // 137	common	statfs			sys_statfs
    "fstatfs",               // 138	common	fstatfs			sys_fstatfs
    "sysfs",                 // 139	common	sysfs			sys_sysfs
    "getpriority",           // 140	common	getpriority		sys_getpriority
    "setpriority",           // 141	common	setpriority		sys_setpriority
    "sched_setparam",        // 142	common	sched_setparam		sys_sched_setparam
    "sched_getparam",        // 143	common	sched_getparam		sys_sched_getparam
    "sched_setscheduler",    // 144	common	sched_setscheduler	sys_sched_setscheduler
    "sched_getscheduler",    // 145	common	sched_getscheduler	sys_sched_getscheduler
    "sched_get_priority_max",// 146	common	sched_get_priority_max	sys_sched_get_priority_max
    "sched_get_priority_min",// 147	common	sched_get_priority_min	sys_sched_get_priority_min
    "sched_rr_get_interval", // 148	common	sched_rr_get_interval	sys_sched_rr_get_interval
    "mlock",                 // 149	common	mlock			sys_mlock
    "munlock",               // 150	common	munlock			sys_munlock
    "mlockall",              // 151	common	mlockall		sys_mlockall
    "munlockall",            // 152	common	munlockall		sys_munlockall
    "vhangup",               // 153	common	vhangup			sys_vhangup
    "modify_ldt",            // 154	common	modify_ldt		sys_modify_ldt
    "pivot_root",            // 155	common	pivot_root		sys_pivot_root
    "_sysctl",               // 156	64	_sysctl			sys_ni_syscall
    "prctl",                 // 157	common	prctl			sys_prctl
    "arch_prctl",            // 158	common	arch_prctl		sys_arch_prctl
    "adjtimex",              // 159	common	adjtimex		sys_adjtimex
    "setrlimit",             // 160	common	setrlimit		sys_setrlimit
    "chroot",                // 161	common	chroot			sys_chroot
    "sync",                  // 162	common	sync			sys_sync
    "acct",                  // 163	common	acct			sys_acct
    "settimeofday",          // 164	common	settimeofday		sys_settimeofday
    "mount",                 // 165	common	mount			sys_mount
    "umount2",               // 166	common	umount2			sys_umount
    "swapon",                // 167	common	swapon			sys_swapon
    "swapoff",               // 168	common	swapoff			sys_swapoff
    "reboot",                // 169	common	reboot			sys_reboot
    "sethostname",           // 170	common	sethostname		sys_sethostname
    "setdomainname",         // 171	common	setdomainname		sys_setdomainname
    "iopl",                  // 172	common	iopl			sys_iopl
    "ioperm",                // 173	common	ioperm			sys_ioperm
    "create_module",         // 174	64	create_module
    "init_module",           // 175	common	init_module		sys_init_module
    "delete_module",         // 176	common	delete_module		sys_delete_module
    "get_kernel_syms",       // 177	64	get_kernel_syms
    "query_module",          // 178	64	query_module
    "quotactl",              // 179	common	quotactl		sys_quotactl
    "nfsservctl",            // 180	64	nfsservctl
    "getpmsg",               // 181	common	getpmsg
    "putpmsg",               // 182	common	putpmsg
    "afs_syscall",           // 183	common	afs_syscall
    "tuxcall",               // 184	common	tuxcall
    "security",              // 185	common	security
    "gettid",                // 186	common	gettid			sys_gettid
    "readahead",             // 187	common	readahead		sys_readahead
    "setxattr",              // 188	common	setxattr		sys_setxattr
    "lsetxattr",             // 189	common	lsetxattr		sys_lsetxattr
    "fsetxattr",             // 190	common	fsetxattr		sys_fsetxattr
    "getxattr",              // 191	common	getxattr		sys_getxattr
    "lgetxattr",             // 192	common	lgetxattr		sys_lgetxattr
    "fgetxattr",             // 193	common	fgetxattr		sys_fgetxattr
    "listxattr",             // 194	common	listxattr		sys_listxattr
    "llistxattr",            // 195	common	llistxattr		sys_llistxattr
    "flistxattr",            // 196	common	flistxattr		sys_flistxattr
    "removexattr",           // 197	common	removexattr		sys_removexattr
    "lremovexattr",          // 198	common	lremovexattr		sys_lremovexattr
    "fremovexattr",          // 199	common	fremovexattr		sys_fremovexattr
    "tkill",                 // 200	common	tkill			sys_tkill
    "time",                  // 201	common	time			sys_time
    "futex",                 // 202	common	futex			sys_futex
    "sched_setaffinity",     // 203	common	sched_setaffinity	sys_sched_setaffinity
    "sched_getaffinity",     // 204	common	sched_getaffinity	sys_sched_getaffinity
    "set_thread_area",       // 205	64	set_thread_area
    "io_setup",              // 206	64	io_setup		sys_io_setup
    "io_destroy",            // 207	common	io_destroy		sys_io_destroy
    "io_getevents",          // 208	common	io_getevents		sys_io_getevents
    "io_submit",             // 209	64	io_submit		sys_io_submit
    "io_cancel",             // 210	common	io_cancel		sys_io_cancel
    "get_thread_area",       // 211	64	get_thread_area
    "lookup_dcookie",        // 212	common	lookup_dcookie
    "epoll_create",          // 213	common	epoll_create		sys_epoll_create
    "epoll_ctl_old",         // 214	64	epoll_ctl_old
    "epoll_wait_old",        // 215	64	epoll_wait_old
    "remap_file_pages",      // 216	common	remap_file_pages	sys_remap_file_pages
    "getdents64",            // 217	common	getdents64		sys_getdents64
    "set_tid_address",       // 218	common	set_tid_address		sys_set_tid_address
    "restart_syscall",       // 219	common	restart_syscall		sys_restart_syscall
    "semtimedop",            // 220	common	semtimedop		sys_semtimedop
    "fadvise64",             // 221	common	fadvise64		sys_fadvise64
    "timer_create",          // 222	64	timer_create		sys_timer_create
    "timer_settime",         // 223	common	timer_settime		sys_timer_settime
    "timer_gettime",         // 224	common	timer_gettime		sys_timer_gettime
    "timer_getoverrun",      // 225	common	timer_getoverrun	sys_timer_getoverrun
    "timer_delete",          // 226	common	timer_delete		sys_timer_delete
    "clock_settime",         // 227	common	clock_settime		sys_clock_settime
    "clock_gettime",         // 228	common	clock_gettime		sys_clock_gettime
    "clock_getres",          // 229	common	clock_getres		sys_clock_getres
    "clock_nanosleep",       // 230	common	clock_nanosleep		sys_clock_nanosleep
    "exit_group",			   // 231	common	exit_group		sys_exit_group			-			noreturn
    "epoll_wait",            // 232	common	epoll_wait		sys_epoll_wait
    "epoll_ctl",             // 233	common	epoll_ctl		sys_epoll_ctl
    "tgkill",                // 234	common	tgkill			sys_tgkill
    "utimes",                // 235	common	utimes			sys_utimes
    "vserver",               // 236	64	vserver
    "mbind",                 // 237	common	mbind			sys_mbind
    "set_mempolicy",         // 238	common	set_mempolicy		sys_set_mempolicy
    "get_mempolicy",         // 239	common	get_mempolicy		sys_get_mempolicy
    "mq_open",               // 240	common	mq_open			sys_mq_open
    "mq_unlink",             // 241	common	mq_unlink		sys_mq_unlink
    "mq_timedsend",          // 242	common	mq_timedsend		sys_mq_timedsend
    "mq_timedreceive",       // 243	common	mq_timedreceive		sys_mq_timedreceive
    "mq_notify",             // 244	64	mq_notify		sys_mq_notify
    "mq_getsetattr",         // 245	common	mq_getsetattr		sys_mq_getsetattr
    "kexec_load",            // 246	64	kexec_load		sys_kexec_load
    "waitid",                // 247	64	waitid			sys_waitid
    "add_key",               // 248	common	add_key			sys_add_key
    "request_key",           // 249	common	request_key		sys_request_key
    "keyctl",                // 250	common	keyctl			sys_keyctl
    "ioprio_set",            // 251	common	ioprio_set		sys_ioprio_set
    "ioprio_get",            // 252	common	ioprio_get		sys_ioprio_get
    "inotify_init",          // 253	common	inotify_init		sys_inotify_init
    "inotify_add_watch",     // 254	common	inotify_add_watch	sys_inotify_add_watch
    "inotify_rm_watch",      // 255	common	inotify_rm_watch	sys_inotify_rm_watch
    "migrate_pages",         // 256	common	migrate_pages		sys_migrate_pages
    "openat",                // 257	common	openat			sys_openat
    "mkdirat",               // 258	common	mkdirat			sys_mkdirat
    "mknodat",               // 259	common	mknodat			sys_mknodat
    "fchownat",              // 260	common	fchownat		sys_fchownat
    "futimesat",             // 261	common	futimesat		sys_futimesat
    "newfstatat",            // 262	common	newfstatat		sys_newfstatat
    "unlinkat",              // 263	common	unlinkat		sys_unlinkat
    "renameat",              // 264	common	renameat		sys_renameat
    "linkat",                // 265	common	linkat			sys_linkat
    "symlinkat",             // 266	common	symlinkat		sys_symlinkat
    "readlinkat",            // 267	common	readlinkat		sys_readlinkat
    "fchmodat",              // 268	common	fchmodat		sys_fchmodat
    "faccessat",             // 269	common	faccessat		sys_faccessat
    "pselect6",              // 270	common	pselect6		sys_pselect6
    "ppoll",                 // 271	common	ppoll			sys_ppoll
    "unshare",               // 272	common	unshare			sys_unshare
    "set_robust_list",       // 273	64	set_robust_list		sys_set_robust_list
    "get_robust_list",       // 274	64	get_robust_list		sys_get_robust_list
    "splice",                // 275	common	splice			sys_splice
    "tee",                   // 276	common	tee			sys_tee
    "sync_file_range",       // 277	common	sync_file_range		sys_sync_file_range
    "vmsplice",              // 278	64	vmsplice		sys_vmsplice
    "move_pages",            // 279	64	move_pages		sys_move_pages
    "utimensat",             // 280	common	utimensat		sys_utimensat
    "epoll_pwait",           // 281	common	epoll_pwait		sys_epoll_pwait
    "signalfd",              // 282	common	signalfd		sys_signalfd
    "timerfd_create",        // 283	common	timerfd_create		sys_timerfd_create
    "eventfd",               // 284	common	eventfd			sys_eventfd
    "fallocate",             // 285	common	fallocate		sys_fallocate
    "timerfd_settime",       // 286	common	timerfd_settime		sys_timerfd_settime
    "timerfd_gettime",       // 287	common	timerfd_gettime		sys_timerfd_gettime
    "accept4",               // 288	common	accept4			sys_accept4
    "signalfd4",             // 289	common	signalfd4		sys_signalfd4
    "eventfd2",              // 290	common	eventfd2		sys_eventfd2
    "epoll_create1",         // 291	common	epoll_create1		sys_epoll_create1
    "dup3",                  // 292	common	dup3			sys_dup3
    "pipe2",                 // 293	common	pipe2			sys_pipe2
    "inotify_init1",         // 294	common	inotify_init1		sys_inotify_init1
    "preadv",                // 295	64	preadv			sys_preadv
    "pwritev",               // 296	64	pwritev			sys_pwritev
    "rt_tgsigqueueinfo",     // 297	64	rt_tgsigqueueinfo	sys_rt_tgsigqueueinfo
    "perf_event_open",       // 298	common	perf_event_open		sys_perf_event_open
    "recvmmsg",              // 299	64	recvmmsg		sys_recvmmsg
    "fanotify_init",         // 300	common	fanotify_init		sys_fanotify_init
    "fanotify_mark",         // 301	common	fanotify_mark		sys_fanotify_mark
    "prlimit64",             // 302	common	prlimit64		sys_prlimit64
    "name_to_handle_at",     // 303	common	name_to_handle_at	sys_name_to_handle_at
    "open_by_handle_at",     // 304	common	open_by_handle_at	sys_open_by_handle_at
    "clock_adjtime",         // 305	common	clock_adjtime		sys_clock_adjtime
    "syncfs",                // 306	common	syncfs			sys_syncfs
    "sendmmsg",              // 307	64	sendmmsg		sys_sendmmsg
    "setns",                 // 308	common	setns			sys_setns
    "getcpu",                // 309	common	getcpu			sys_getcpu
    "process_vm_readv",      // 310	64	process_vm_readv	sys_process_vm_readv
    "process_vm_writev",     // 311	64	process_vm_writev	sys_process_vm_writev
    "kcmp",                  // 312	common	kcmp			sys_kcmp
    "finit_module",          // 313	common	finit_module		sys_finit_module
    "sched_setattr",         // 314	common	sched_setattr		sys_sched_setattr
    "sched_getattr",         // 315	common	sched_getattr		sys_sched_getattr
    "renameat2",             // 316	common	renameat2		sys_renameat2
    "seccomp",               // 317	common	seccomp			sys_seccomp
    "getrandom",             // 318	common	getrandom		sys_getrandom
    "memfd_create",          // 319	common	memfd_create		sys_memfd_create
    "kexec_file_load",       // 320	common	kexec_file_load		sys_kexec_file_load
    "bpf",                   // 321	common	bpf			sys_bpf
    "execveat",              // 322	64	execveat		sys_execveat
    "userfaultfd",           // 323	common	userfaultfd		sys_userfaultfd
    "membarrier",            // 324	common	membarrier		sys_membarrier
    "mlock2",                // 325	common	mlock2			sys_mlock2
    "copy_file_range",       // 326	common	copy_file_range		sys_copy_file_range
    "preadv2",               // 327	64	preadv2			sys_preadv2
    "pwritev2",              // 328	64	pwritev2		sys_pwritev2
    "pkey_mprotect",         // 329	common	pkey_mprotect		sys_pkey_mprotect
    "pkey_alloc",            // 330	common	pkey_alloc		sys_pkey_alloc
    "pkey_free",             // 331	common	pkey_free		sys_pkey_free
    "statx",                 // 332	common	statx			sys_statx
    "io_pgetevents",         // 333	common	io_pgetevents		sys_io_pgetevents
    "rseq",                  // 334	common	rseq			sys_rseq
};

static char syscall_424_467[][24] = {
    "pidfd_send_signal",         // 424	common	pidfd_send_signal	sys_pidfd_send_signal
    "io_uring_setup",            // 425	common	io_uring_setup		sys_io_uring_setup
    "io_uring_enter",            // 426	common	io_uring_enter		sys_io_uring_enter
    "io_uring_register",         // 427	common	io_uring_register	sys_io_uring_register
    "open_tree",                 // 428	common	open_tree		sys_open_tree
    "move_mount",                // 429	common	move_mount		sys_move_mount
    "fsopen",                    // 430	common	fsopen			sys_fsopen
    "fsconfig",                  // 431	common	fsconfig		sys_fsconfig
    "fsmount",                   // 432	common	fsmount			sys_fsmount
    "fspick",                    // 433	common	fspick			sys_fspick
    "pidfd_open",                // 434	common	pidfd_open		sys_pidfd_open
    "clone3",                    // 435	common	clone3			sys_clone3
    "close_range",               // 436	common	close_range		sys_close_range
    "openat2",                   // 437	common	openat2			sys_openat2
    "pidfd_getfd",               // 438	common	pidfd_getfd		sys_pidfd_getfd
    "faccessat2",                // 439	common	faccessat2		sys_faccessat2
    "process_madvise",           // 440	common	process_madvise		sys_process_madvise
    "epoll_pwait2",              // 441	common	epoll_pwait2		sys_epoll_pwait2
    "mount_setattr",             // 442	common	mount_setattr		sys_mount_setattr
    "quotactl_fd",               // 443	common	quotactl_fd		sys_quotactl_fd
    "landlock_create_ruleset",   // 444	common	landlock_create_ruleset	sys_landlock_create_ruleset
    "landlock_add_rule",         // 445	common	landlock_add_rule	sys_landlock_add_rule
    "landlock_restrict_self",    // 446	common	landlock_restrict_self	sys_landlock_restrict_self
    "memfd_secret",              // 447	common	memfd_secret		sys_memfd_secret
    "process_mrelease",          // 448	common	process_mrelease	sys_process_mrelease
    "futex_waitv",               // 449	common	futex_waitv		sys_futex_waitv
    "set_mempolicy_home_node",   // 450	common	set_mempolicy_home_node	sys_set_mempolicy_home_node
    "cachestat",                 // 451	common	cachestat		sys_cachestat
    "fchmodat2",                 // 452	common	fchmodat2		sys_fchmodat2
    "map_shadow_stack",          // 453	common	map_shadow_stack	sys_map_shadow_stack
    "futex_wake",                // 454	common	futex_wake		sys_futex_wake
    "futex_wait",                // 455	common	futex_wait		sys_futex_wait
    "futex_requeue",             // 456	common	futex_requeue		sys_futex_requeue
    "statmount",                 // 457	common	statmount		sys_statmount
    "listmount",                 // 458	common	listmount		sys_listmount
    "lsm_get_self_attr",         // 459	common	lsm_get_self_attr	sys_lsm_get_self_attr
    "lsm_set_self_attr",         // 460	common	lsm_set_self_attr	sys_lsm_set_self_attr
    "lsm_list_modules",          // 461	common	lsm_list_modules	sys_lsm_list_modules
    "mseal",                     // 462 	common  mseal			sys_mseal
    "uretprobe",                 // 467	common	uretprobe		sys_uretprobe
};

static const char* syscall_name( int syscall_num )
{
    if( 0 <= syscall_num && syscall_num <= 334 )
        return syscall_0_334[syscall_num];
    else if( 424 <= syscall_num && syscall_num <= 467 )
        return syscall_424_467[syscall_num-424];
    return "";
}

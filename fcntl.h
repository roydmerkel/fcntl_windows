#ifndef FCNTL_H
#define FCNTL_H

#include <windows.h>

/* FCNTL ops */
#define F_LINUX_SPECIFIC_BASE        1024

#define F_DUPFD         0       /* dup */
#define F_GETFD         1       /* get close_on_exec */
#define F_SETFD         2       /* set/clear close_on_exec */
#define F_GETFL         3       /* get file->f_flags */
#define F_SETFL         4       /* set file->f_flags */
#ifndef F_GETLK
#define F_GETLK         5
#define F_SETLK         6
#define F_SETLKW        7
#endif
//#ifndef F_SETOWN
//#define F_SETOWN        8       /* for sockets. */
//#define F_GETOWN        9       /* for sockets. */
//#endif
//#ifndef F_SETSIG
//#define F_SETSIG        10      /* for sockets. */
//#define F_GETSIG        11      /* for sockets. */
//#endif

#ifndef F_GETLK64
#define F_GETLK64       12      /*  using 'struct flock64' */
#define F_SETLK64       13
#define F_SETLKW64      14
#endif

//#ifndef F_SETOWN_EX
//#define F_SETOWN_EX     15
//#define F_GETOWN_EX     16
//#endif

/*
 * Open File Description Locks
 *
 * Usually record locks held by a process are released on *any* close and are
 * not inherited across a fork().
 *
 * These cmd values will set locks that conflict with process-associated
 * record  locks, but are "owned" by the open file description, not the
 * process. This means that they are inherited across fork() like BSD (flock)
 * locks, and they are only released automatically when the last reference to
 * the the open file against which they were acquired is put.
 */
#define F_OFD_GETLK     36
#define F_OFD_SETLK     37
#define F_OFD_SETLKW    38

//#define F_SETLEASE      (F_LINUX_SPECIFIC_BASE + 0)
//#define F_GETLEASE      (F_LINUX_SPECIFIC_BASE + 1)

/*
 * Request nofications on a directory.
 * See below for events that may be notified.
 */
//#define F_NOTIFY        (F_LINUX_SPECIFIC_BASE + 2)

#define F_DUPFD_CLOEXEC (F_LINUX_SPECIFIC_BASE + 6)

/*
 * Set and get of pipe page size array
 */
//#define F_SETPIPE_SZ    (F_LINUX_SPECIFIC_BASE + 7)
//#define F_GETPIPE_SZ    (F_LINUX_SPECIFIC_BASE + 8)

/*
 * Set/Get seals
 */
//#define F_ADD_SEALS     (F_LINUX_SPECIFIC_BASE + 9)
//#define F_GET_SEALS     (F_LINUX_SPECIFIC_BASE + 10)

/*
 * Set/Get write life time hints. {GET,SET}_RW_HINT operate on the
 * underlying inode, while {GET,SET}_FILE_RW_HINT operate only on
 * the specific file.
 */
//#define F_GET_RW_HINT           (F_LINUX_SPECIFIC_BASE + 11)
//#define F_SET_RW_HINT           (F_LINUX_SPECIFIC_BASE + 12)
//#define F_GET_FILE_RW_HINT      (F_LINUX_SPECIFIC_BASE + 13)
//#define F_SET_FILE_RW_HINT      (F_LINUX_SPECIFIC_BASE + 14)

/* FCNTL enum constants. */
//#define F_OWNER_TID     0
//#define F_OWNER_PID     1
//#define F_OWNER_PGRP    2

//struct f_owner_ex {
//        int     type;
//        __kernel_pid_t  pid;
//};

/* for F_[GET|SET]FL */
#define FD_CLOEXEC      1       /* actually anything with low bit set goes */

/* for posix fcntl() and lockf() */
#ifndef F_RDLCK
#define F_RDLCK         0
#define F_WRLCK         1
#define F_UNLCK         2
#endif

/* for old implementation of bsd flock () */
#ifndef F_EXLCK
#define F_EXLCK         4       /* or 3 */
#define F_SHLCK         8       /* or 4 */
#endif

/*
 * Types of seals
 */
//#define F_SEAL_SEAL     0x0001  /* prevent further seals from being set */
//#define F_SEAL_SHRINK   0x0002  /* prevent file from shrinking */
//#define F_SEAL_GROW     0x0004  /* prevent file from growing */
//#define F_SEAL_WRITE    0x0008  /* prevent writes */
//#define F_SEAL_FUTURE_WRITE     0x0010  /* prevent future writes while mapped */
/* (1U << 31) is reserved for signed error codes */

/*
 * Valid hint values for F_{GET,SET}_RW_HINT. 0 is "not set", or can be
 * used to clear any hints previously set.
 */
//#define RWH_WRITE_LIFE_NOT_SET  0
//#define RWH_WRITE_LIFE_NONE     1
//#define RWH_WRITE_LIFE_SHORT    2
//#define RWH_WRITE_LIFE_MEDIUM   3
//#define RWH_WRITE_LIFE_LONG     4
//#define RWH_WRITE_LIFE_EXTREME  5

/*
 * The originally introduced spelling is remained from the first
 * versions of the patch set that introduced the feature, see commit
 * v4.13-rc1~212^2~51.
 */
//#define RWF_WRITE_LIFE_NOT_SET  RWH_WRITE_LIFE_NOT_SET

/*
 * Types of directory notifications that may be requested.
 */
//#define DN_ACCESS       0x00000001      /* File accessed */
//#define DN_MODIFY       0x00000002      /* File modified */
//#define DN_CREATE       0x00000004      /* File created */
//#define DN_DELETE       0x00000008      /* File removed */
//#define DN_RENAME       0x00000010      /* File renamed */
//#define DN_ATTRIB       0x00000020      /* File changed attibutes */
//#define DN_MULTISHOT    0x80000000      /* Don't remove notifier */


#define _O_RDONLY       0x0000  /* open for reading only */
#define _O_WRONLY       0x0001  /* open for writing only */
#define _O_RDWR         0x0002  /* open for reading and writing */
#define _O_APPEND       0x0008  /* writes done at eof */

#define _O_CREAT        0x0100  /* create and open file */
#define _O_TRUNC        0x0200  /* open and truncate */
#define _O_EXCL         0x0400  /* open only if file doesn't already exist */

/* O_TEXT files have <cr><lf> sequences translated to <lf> on read()'s,
** and <lf> sequences translated to <cr><lf> on write()'s
*/

#define _O_TEXT         0x4000  /* file mode is text (translated) */
#define _O_BINARY       0x8000  /* file mode is binary (untranslated) */

/* macro to translate the C 2.0 name used to force binary mode for files */

#define _O_RAW  _O_BINARY

/* Open handle inherit bit */

#define _O_NOINHERIT    0x0080  /* child process doesn't inherit file */

/* Temporary file bit - file is deleted when last handle is closed */

#define _O_TEMPORARY    0x0040  /* temporary file bit */

/* temporary access hint */

#define _O_SHORT_LIVED  0x1000  /* temporary storage file, try not to flush */

/* sequential/random access hints */

#define _O_SEQUENTIAL   0x0020  /* file access is primarily sequential */
#define _O_RANDOM       0x0010  /* file access is primarily random */

#if !defined _O_CLOEXEC && defined _O_NOINHERIT
/* Mingw spells it 'O_NOINHERIT'.  */
# define _O_CLOEXEC _O_NOINHERIT
#endif

#define _O_ASYNC         0x2000

int fcntl(int fd, int cmd, ... /* arg */ );

typedef struct _QWORD _QWORD;
struct _QWORD {
	DWORD	ddLower;
	DWORD	ddUpper;
}; /* _QWORD */


#if defined(_MSC_VER)
typedef unsigned int pid_t;			/* process ID of requesting task */
typedef LONG off_t;
#endif

struct flock
  {
    short int l_type;   /* Type of lock: F_RDLCK, F_WRLCK, or F_UNLCK.  */
    short int l_whence; /* Where `l_start' is relative to (like `lseek').  */
    off_t l_start;    /* Offset where the lock begins.  */
    off_t l_len;      /* Size of the locked area; zero means until EOF.  */
    pid_t l_pid;      /* Process holding the lock.  */
  };

struct flock64
  {
    short int l_type;   /* Type of lock: F_RDLCK, F_WRLCK, or F_UNLCK.  */
    short int l_whence; /* Where `l_start' is relative to (like `lseek').  */
    _QWORD l_start;  /* Offset where the lock begins.  */
    _QWORD l_len;    /* Size of the locked area; zero means until EOF.  */
    DWORD l_pid;      /* Process holding the lock.  */
  };

typedef struct flock flock;
typedef struct flock64 flock64;

#endif
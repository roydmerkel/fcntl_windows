#include "fcntl.h"
#include "ioinfo.h"
#include <windows.h>
#include <stdarg.h>
#include <io.h>
#include <errno.h>

#ifndef INVALID_SET_FILE_POINTER
#define INVALID_SET_FILE_POINTER ((DWORD)-1)
#endif

#if (defined _WIN64 || defined __WIN64__ || defined _WIN32 || defined __WIN32__) && ! defined __CYGWIN__

# include <stdio.h>

typedef enum _OBJECT_INFORMATION_CLASS {
  ObjectBasicInformation,
  ObjectTypeInformation
} OBJECT_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PUBLIC_OBJECT_BASIC_INFORMATION {
  ULONG       Attributes;
  ACCESS_MASK GrantedAccess;
  ULONG       HandleCount;
  ULONG       PointerCount;
  ULONG       Reserved[10];
} PUBLIC_OBJECT_BASIC_INFORMATION, *PPUBLIC_OBJECT_BASIC_INFORMATION;

typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
  UNICODE_STRING TypeName;
  ULONG          Reserved[22];
} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;

#ifndef NTSTATUS
#define NTSTATUS DWORD
#endif

typedef NTSTATUS (WINAPI *PNtQueryObject)(
  HANDLE                   Handle,
  OBJECT_INFORMATION_CLASS ObjectInformationClass,
  PVOID                    ObjectInformation,
  ULONG                    ObjectInformationLength,
  PULONG                   ReturnLength
);
typedef NTSTATUS (FAR WINAPI * LPNtQueryObject)(
  HANDLE                   Handle,
  OBJECT_INFORMATION_CLASS ObjectInformationClass,
  PVOID                    ObjectInformation,
  ULONG                    ObjectInformationLength,
  PULONG                   ReturnLength
);

static int dtableSize = 0;

#if !_MSC_VER || _MSC_VER >= 1010
static int getdtablesizesearch(int min, int max);

static int getdtablesizesearch(int min, int max)
{
	int pivot;
	int setstdioval;

	if(min >= max)
	{
		return 0;
	}
	pivot = (max - min) / 2 + min;
	setstdioval = _setmaxstdio(pivot);

	if(setstdioval >= 0)
	{
		if(pivot == max || pivot == min)
		{
			return pivot;
		}
		else
		{
			return getdtablesizesearch(pivot, max);
		}
	}
	else
	{
		return getdtablesizesearch(min, pivot - 1);
	}
}
#endif

int getdtablesize (void)
{
#if _MSC_VER < 1000
	return 64;
#elif _MSC_VER < 1010
	return 2048;
#else
	int curMaxStdio;

	if(dtableSize != 0)
	{
		return dtableSize;
	}

	curMaxStdio = _getmaxstdio();

	dtableSize = getdtablesizesearch(0, 0x7FFFFFFF);

	_setmaxstdio(curMaxStdio);

	return dtableSize;
#endif
	return 0;
}

#endif

/************************************************************************************
 *                                                                                  *
 * TODO pulled from https://github.com/digitalocean/gnulib/blob/master/lib/fcntl.c  *
 *                                                                                  *
 ************************************************************************************/
/* Duplicate OLDFD into the first available slot of at least NEWFD,
   which must be positive, with FLAGS determining whether the duplicate
   will be inheritable.  */
#define OPEN_MAX_MAX 0x10000
#define CHAR_BIT 8

static int dupfd (int oldfd, int newfd, int flags)
{
	/* Mingw has no way to create an arbitrary fd.  Iterate until all
	   file descriptors less than newfd are filled up.  */
	HANDLE curr_process = GetCurrentProcess ();
	HANDLE old_handle = (HANDLE) _get_osfhandle (oldfd);
	unsigned char fds_to_close[OPEN_MAX_MAX / CHAR_BIT];
	unsigned int fds_to_close_bound = 0;
	int result;
	BOOL inherit = flags & _O_CLOEXEC ? FALSE : TRUE;
	int mode;

	if (getdtablesize () <= newfd)
	{
		errno = EINVAL;
		return -1;
	}
	if (old_handle == INVALID_HANDLE_VALUE || (mode = setmode (oldfd, _O_BINARY)) == -1)
	{
		/* oldfd is not open, or is an unassigned standard file
		   descriptor.  */
		errno = EBADF;
		return -1;
	}
	setmode (oldfd, mode);
	flags |= mode;

	for (;;)
	{
		HANDLE new_handle;
		int duplicated_fd;
		unsigned int index;
		
		if (!DuplicateHandle (curr_process,           /* SourceProcessHandle */
							  old_handle,             /* SourceHandle */
							  curr_process,           /* TargetProcessHandle */
							  (PHANDLE) &new_handle,  /* TargetHandle */
							  (DWORD) 0,              /* DesiredAccess */
							  inherit,                /* InheritHandle */
							  DUPLICATE_SAME_ACCESS)) /* Options */
		{
			switch (GetLastError ())
			{
				case ERROR_TOO_MANY_OPEN_FILES:
					errno = EMFILE;
					break;
				case ERROR_INVALID_HANDLE:
				case ERROR_INVALID_TARGET_HANDLE:
				case ERROR_DIRECT_ACCESS_HANDLE:
					errno = EBADF;
					break;
				case ERROR_INVALID_PARAMETER:
				case ERROR_INVALID_FUNCTION:
				case ERROR_INVALID_ACCESS:
					errno = EINVAL;
					break;
				default:
					errno = EACCES;
					break;
			}
			result = -1;
			break;
		}
		duplicated_fd = _open_osfhandle ((intptr_t) new_handle, flags);
		if (duplicated_fd < 0)
		{
			CloseHandle (new_handle);
			result = -1;
			break;
		}
		if (newfd <= duplicated_fd)
		{
			result = duplicated_fd;
			break;
		}

		/* Set the bit duplicated_fd in fds_to_close[].  */
		index = (unsigned int) duplicated_fd / CHAR_BIT;
		if (fds_to_close_bound <= index)
		{
			if (sizeof fds_to_close <= index)
				/* Need to increase OPEN_MAX_MAX.  */
				abort ();
			memset (fds_to_close + fds_to_close_bound, '\0', index + 1 - fds_to_close_bound);
			fds_to_close_bound = index + 1;
		}
		fds_to_close[index] |= 1 << ((unsigned int) duplicated_fd % CHAR_BIT);
	}

	/* Close the previous fds that turned out to be too small.  */
	{
		int saved_errno = errno;
		unsigned int duplicated_fd;

		for (duplicated_fd = 0;
			duplicated_fd < fds_to_close_bound * CHAR_BIT;
			duplicated_fd++)
			if ((fds_to_close[duplicated_fd / CHAR_BIT]
				>> (duplicated_fd % CHAR_BIT))
				& 1)
				close (duplicated_fd);

		errno = saved_errno;
	}

	return result;
}
/************************************************************************************
 *                                                                                  *
 * END TODO                                                                         *
 *                                                                                  *
 ************************************************************************************/


static HMODULE hNtDll = NULL;
static BOOL hCheckedNtDll = FALSE;
static LPNtQueryObject lpNtQueryObject = NULL;

_QWORD GetFilePos(HANDLE h, DWORD whence, _QWORD off)
{
	_QWORD ret;

	ret.ddLower = 0xFFFFFFFF;
	ret.ddUpper = 0xFFFFFFFF;

	if(h == 0 || h == INVALID_HANDLE_VALUE)
	{
		SetLastError(ERROR_INVALID_HANDLE);
		return ret;
	}
	else
	{
		DWORD high = 0;
		DWORD low = 0;
		DWORD lastError = 0;
		DWORD offHigh = 0;
		DWORD offLow = 0;

		lastError = ERROR_SUCCESS;
		switch(whence)
		{
			case SEEK_SET:
				low = 0;
				high = 0;
				break;
			case SEEK_CUR:
				SetLastError(ERROR_SUCCESS);
				low = SetFilePointer(h, low, &high, FILE_CURRENT);

				lastError = GetLastError();
				break;
			case SEEK_END:
				SetLastError(ERROR_SUCCESS);
				low = GetFileSize(h, &high);

				lastError = GetLastError();

				if(lastError == ERROR_SUCCESS && off.ddUpper <= 0x7FFFFFFF)
				{
					// turn positive offset into negative one instead of erroring or doing "unspecified behavoir" as per fseek.
					off.ddUpper = ~off.ddUpper;
					off.ddLower = ~off.ddLower;
					if(off.ddLower == 0xFFFFFFFF)
					{
						off.ddUpper++;
						off.ddLower = 0x00000000;
					}
					else
					{
						off.ddLower++;
					}
				}
				break;
			default:
				SetLastError(ERROR_INVALID_PARAMETER);
				lastError = ERROR_INVALID_PARAMETER;
				break;
		}

		if(lastError == ERROR_SUCCESS)
		{
			BOOL carry = FALSE;
			offLow = low;
			offHigh = high;

			offLow += off.ddLower;
			if(offLow <= low)
			{
				carry = TRUE;
			}
			offHigh += off.ddUpper;
			if(carry)
			{
				offHigh++;
			}

			if(offHigh > 0x7FFFFFFF)
			{
				SetLastError(ERROR_NEGATIVE_SEEK);
				lastError = ERROR_NEGATIVE_SEEK;
			}
			else
			{
				ret.ddLower = offLow;
				ret.ddUpper = offHigh;
			}
		}

		return ret;
	}
}

int fcntl(int fd, int cmd, ... /* arg */ )
{
	int ret = 0;
	va_list list;

	va_start(list, cmd);

	switch(cmd)
	{
		case F_DUPFD:
		case F_DUPFD_CLOEXEC:
			{
				int newfd = va_arg(list, int);
				int flags = fcntl(fd, F_GETFL);
				if(cmd == F_DUPFD_CLOEXEC)
				{
					flags |= _O_CLOEXEC;
				}
				ret = dupfd (fd, newfd, flags);
			}
			break;
		case F_GETFD:
			{
				HANDLE hnd = (HANDLE)_get_osfhandle(fd);
				BOOL success = FALSE;
				DWORD dwFlags = 0;

				errno = 0;
				if(hnd == INVALID_HANDLE_VALUE)
				{
					errno = EBADF;
					ret = -1;
				}
				else
				{
					success = GetHandleInformation(hnd, &dwFlags);

					if(success)
					{
						ret = ((dwFlags & HANDLE_FLAG_INHERIT) != 0) ? FD_CLOEXEC: 0;
					}
					else
					{
						errno = EBADF;
						ret = -1;
					}
				}
			}
			break;
		case F_SETFD:
			{
				int setfd_flags = va_arg(list, int);
				int flags;
				int newfd;
				int err = 0;
				flags = fcntl(fd, F_GETFL);

				if(flags >= 0)
				{
					flags &= ~_O_NOINHERIT;
					if(setfd_flags & FD_CLOEXEC)
					{
						flags |= _O_NOINHERIT;
					}

					newfd = dupfd (fd, -1, flags);

					if(newfd >= 0)
					{
						if(dup2(fd, newfd) >= 0)
						{
							ret = 0;
						}
						else
						{
							err = errno;
							close(newfd);
							ret = -1;
							errno = err;
						}
					}
					else
					{
						ret = -1;
					}
				}
				else
				{
					ret = -1;
					errno = EINVAL;
				}
			}
			break;
		case F_GETFL:
			{
				if(fd > getdtablesize())
				{
					errno = EBADF;
					ret = -1;
				}
				else
				{
					#if _MSC_VER && _MSC_VER >= 1300
					intptr_t handle;/* underlying OS file HANDLE */
					#else
					long handle;    /* underlying OS file HANDLE */
					#endif
					DWORD dummy, dummy2;
					BOOL writeOk = FALSE;
					BOOL readOk = FALSE;
					DWORD dwFlags = 0;
					BOOL success = FALSE;
					unsigned char flags = 0;

					handle = _osfhnd(fd);
					if(handle)
					{
						flags = _osfile(fd);

						if(flags & FAPPEND)
						{
							ret |= _O_APPEND;
						}
						if(flags & FTEXT)
						{
							ret |= _O_TEXT;
						}
						else
						{
							ret |= _O_BINARY;
						}
						if(flags & FNOINHERIT)
						{
							ret |= _O_NOINHERIT;
						}
						writeOk = WriteFile((HANDLE)handle, &dummy2, 0, &dummy, 0);
						readOk = ReadFile((HANDLE)handle, &dummy2, 0, &dummy, NULL);
						if (writeOk && readOk)
							ret |= _O_RDWR;
						else if (readOk)
							ret |= _O_RDONLY;
						else
							ret |= _O_WRONLY;

						success = GetHandleInformation((HANDLE)handle, &dwFlags);

						if(success)
						{
							ret |= ((dwFlags & HANDLE_FLAG_INHERIT) != 0) ? 0: _O_NOINHERIT;
						}
						else
						{
							errno = EBADF;
							ret = -1;
						}
					}
					else
					{
						errno = EBADF;
						ret = -1;
					}
				}

			}
			break;
		case F_SETFL:
			{
				int flags = fcntl(fd, F_GETFL);
				int setfl_flags = va_arg(list, int);

				ret = 0;

				if(flags < 0)
				{
					ret = -1;
					errno = EINVAL;
				}

				// only works on NT as Windows 9X only supports GENERIC_READ and GENERIC_WRITE as flags for files.
				// docs seem to say: if not supported do nothing so in case of windows 95 nothing will be done.
				if(!hCheckedNtDll)
				{
					hCheckedNtDll = TRUE;
					hNtDll = LoadLibrary(TEXT("NTDLL"));
					if(hNtDll)
					{
						lpNtQueryObject = (LPNtQueryObject)GetProcAddress(hNtDll, "NtQueryObject");

						if(!lpNtQueryObject)
						{
							lpNtQueryObject = (LPNtQueryObject)GetProcAddress(hNtDll, "ZwQueryObject");
						}
					}
				}
				if(!ret && lpNtQueryObject)
				{
					HANDLE hnd = (HANDLE)_get_osfhandle(fd);
					HANDLE hnd2 = NULL;

					// only attempt to perform changes to valid file types.
					if(hnd && hnd != INVALID_HANDLE_VALUE && GetFileType(hnd) != FILE_TYPE_UNKNOWN)
					{
						PUBLIC_OBJECT_BASIC_INFORMATION objectInformation;
						ULONG length = 0;
						NTSTATUS ntStatus = (*lpNtQueryObject)(hnd, ObjectBasicInformation, &objectInformation, sizeof objectInformation, &length);
						if(ntStatus == 0)
						{
							// only flags that same to work with duplicate handle are append and async, others will cause duplicateHandle failure, so ignored.
							BOOL changed = FALSE;
							ACCESS_MASK accessMode = objectInformation.GrantedAccess;
							BYTE osFileFlags = _osfile(fd);
							DWORD newFlags = flags;

							if((flags & _O_APPEND) != (setfl_flags & _O_APPEND))
							{
								if(setfl_flags & _O_APPEND)
								{
									osFileFlags |= FAPPEND;
									accessMode |= FILE_APPEND_DATA;
									newFlags |= _O_APPEND;
								}
								else
								{
									osFileFlags &= ~FAPPEND;
									accessMode &= ~FILE_APPEND_DATA;
									newFlags &= _O_APPEND;
								}
								changed = TRUE;
							}
							if((setfl_flags & _O_ASYNC) && !(accessMode & FILE_FLAG_OVERLAPPED))
							{
								accessMode |= FILE_FLAG_OVERLAPPED;
								changed = TRUE;
							}
							else if(!(setfl_flags & _O_ASYNC) && (accessMode & FILE_FLAG_OVERLAPPED))
							{
								accessMode &= ~FILE_FLAG_OVERLAPPED;
								changed = TRUE;
							}

							if(changed)
							{
								BOOL dupRes = FALSE;
								HANDLE curr_process = GetCurrentProcess ();

								//_set_osfile(fd, osFileFlags);
								dupRes = DuplicateHandle(curr_process, hnd, curr_process, &hnd2, accessMode, !(flags & _O_NOINHERIT),0);

								if(dupRes)
								{
									int newfd = _open_osfhandle((DWORD)hnd2, newFlags);


									if(newfd != -1)
									{
										if(dup2(fd, newfd) >= 0)
										{
											ret = 0;
											_set_osfile(fd, osFileFlags);
										}
										else
										{
											close(newfd);
											ret = -1;
										}
									}
									else
									{
										CloseHandle(hnd2);
									}
								}
							}
						}
					}
				}
			}
			break;
		case F_GETLK:
		case F_OFD_GETLK:
			{
				struct flock * lockInfo = va_arg(list, struct flock *);
				HANDLE hnd = (HANDLE)_get_osfhandle(fd);
				_QWORD pos;
				pos.ddLower = lockInfo->l_start;
				pos.ddUpper = (lockInfo->l_start < 0) ? 0xFFFFFFFF : 0;

				errno = 0;
				ret = 0;
				if(lockInfo == NULL)
				{
					ret = -1;
					errno = EINVAL;
				}
				else if(hnd == INVALID_HANDLE_VALUE)
				{
					errno = EBADF;
					ret = -1;
				}
				else
				{
					BOOL lockRet;

					pos = GetFilePos(hnd, lockInfo->l_whence, pos);

					if(ret == 0 && GetLastError() == ERROR_SUCCESS)
					{
						lockRet = LockFile(hnd, pos.ddLower, pos.ddUpper, lockInfo->l_len, 0);

						if(lockRet)
						{
							ret = 0;
							UnlockFile(hnd, pos.ddLower, pos.ddUpper, lockInfo->l_len, 0);
							lockInfo->l_type = F_UNLCK;
						}
						else
						{
							switch(GetLastError())
							{
								case ERROR_LOCK_VIOLATION:
									lockInfo->l_type = F_RDLCK | F_WRLCK;
									lockInfo->l_pid = -1;
									ret = 0;
									break;
								case ERROR_NOT_ENOUGH_MEMORY:
									ret = -1;
									errno = ENOMEM;
									break;
								case ERROR_BAD_COMMAND:
									ret = -1;
									errno = EINVAL;
									break;
								default:
									ret = -1;
									break;
							}
						}
					}
				}
			}
			break;
		case F_SETLK:
		case F_OFD_SETLK:
			{
				struct flock * lockInfo = va_arg(list, struct flock *);
				HANDLE hnd = (HANDLE)_get_osfhandle(fd);
				errno = 0;
				if(lockInfo == NULL)
				{
					ret = -1;
					errno = EINVAL;
				}
				else if(hnd == INVALID_HANDLE_VALUE)
				{
					errno = EBADF;
					ret = -1;
				}
				else
				{
					_QWORD pos;
					pos.ddLower = lockInfo->l_start;
					pos.ddUpper = (lockInfo->l_start < 0) ? 0xFFFFFFFF : 0;

					pos = GetFilePos(hnd, lockInfo->l_whence, pos);

					if(GetLastError() == ERROR_SUCCESS)
					{
						BOOL lockRet = LockFile(hnd, pos.ddLower, pos.ddUpper, lockInfo->l_len, 0);

						if(lockRet)
						{
							ret = 0;
						}
						else
						{
							switch(GetLastError())
							{
								case ERROR_LOCK_VIOLATION:
									errno = EAGAIN;
									ret = -1;
									break;
								case ERROR_NOT_ENOUGH_MEMORY:
									ret = -1;
									errno = ENOMEM;
									break;
								case ERROR_BAD_COMMAND:
									ret = -1;
									errno = EINVAL;
									break;
								default:
									ret = -1;
									break;
							}
						}
					}
				}
			}
			break;
		case F_SETLKW:
		case F_OFD_SETLKW:
			{
				struct flock * lockInfo = va_arg(list, struct flock *);
				HANDLE hnd = (HANDLE)_get_osfhandle(fd);
				errno = 0;
				if(lockInfo == NULL)
				{
					ret = -1;
					errno = EINVAL;
				}
				else if(hnd == INVALID_HANDLE_VALUE)
				{
					errno = EBADF;
					ret = -1;
				}
				else
				{
					DWORD lastError;
					BOOL lockRet = 0;

					_QWORD pos;
					pos.ddLower = lockInfo->l_start;
					pos.ddUpper = (lockInfo->l_start < 0) ? 0xFFFFFFFF : 0;

					SetLastError(ERROR_SUCCESS);
					pos = GetFilePos(hnd, lockInfo->l_whence, pos);

					if(GetLastError() == ERROR_SUCCESS)
					{
						do
						{
							lastError = 0;
							lockRet = FALSE;

							lockRet = LockFile(hnd, pos.ddLower, pos.ddUpper, lockInfo->l_len, 0);

							if(!lockRet)
							{
								lastError = GetLastError();

								if(lastError == ERROR_LOCK_VIOLATION)
								{
									Sleep(10);
								}
							}
						}
						while(!lockRet && lastError == ERROR_LOCK_VIOLATION);
					}

					if(lockRet)
					{
						ret = 0;
					}
					else
					{
						switch(GetLastError())
						{
							case ERROR_LOCK_VIOLATION:
								errno = EAGAIN;
								ret = -1;
								break;
							case ERROR_NOT_ENOUGH_MEMORY:
								ret = -1;
								errno = ENOMEM;
								break;
							case ERROR_BAD_COMMAND:
								ret = -1;
								errno = EINVAL;
								break;
							default:
								ret = -1;
								break;
						}
					}
				}
			}
			break;
		case F_GETLK64:
			{
				struct flock64 * lockInfo = va_arg(list, struct flock64 *);
				HANDLE hnd = (HANDLE)_get_osfhandle(fd);
				_QWORD pos;
				pos = lockInfo->l_start;

				errno = 0;
				ret = 0;
				if(lockInfo == NULL)
				{
					ret = -1;
					errno = EINVAL;
				}
				else if(hnd == INVALID_HANDLE_VALUE)
				{
					errno = EBADF;
					ret = -1;
				}
				else
				{
					BOOL lockRet;

					pos = GetFilePos(hnd, lockInfo->l_whence, pos);

					if(ret == 0 && GetLastError() == ERROR_SUCCESS)
					{
						lockRet = LockFile(hnd, pos.ddLower, pos.ddUpper, lockInfo->l_len.ddLower, lockInfo->l_len.ddUpper);

						if(lockRet)
						{
							ret = 0;
							UnlockFile(hnd, pos.ddLower, pos.ddUpper, lockInfo->l_len.ddLower, lockInfo->l_len.ddUpper);
							lockInfo->l_type = F_UNLCK;
						}
						else
						{
							switch(GetLastError())
							{
								case ERROR_LOCK_VIOLATION:
									lockInfo->l_type = F_RDLCK | F_WRLCK;
									lockInfo->l_pid = -1;
									ret = 0;
									break;
								case ERROR_NOT_ENOUGH_MEMORY:
									ret = -1;
									errno = ENOMEM;
									break;
								case ERROR_BAD_COMMAND:
									ret = -1;
									errno = EINVAL;
									break;
								default:
									ret = -1;
									break;
							}
						}
					}
				}
			}
			break;
		case F_SETLK64:
			{
				struct flock64 * lockInfo = va_arg(list, struct flock64 *);
				HANDLE hnd = (HANDLE)_get_osfhandle(fd);
				errno = 0;
				if(lockInfo == NULL)
				{
					ret = -1;
					errno = EINVAL;
				}
				else if(hnd == INVALID_HANDLE_VALUE)
				{
					errno = EBADF;
					ret = -1;
				}
				else
				{
					_QWORD pos;
					pos = lockInfo->l_start;

					pos = GetFilePos(hnd, lockInfo->l_whence, pos);

					if(GetLastError() == ERROR_SUCCESS)
					{
						BOOL lockRet = LockFile(hnd, pos.ddLower, pos.ddUpper, lockInfo->l_len.ddLower, lockInfo->l_len.ddUpper);

						if(lockRet)
						{
							ret = 0;
						}
						else
						{
							switch(GetLastError())
							{
								case ERROR_LOCK_VIOLATION:
									errno = EAGAIN;
									ret = -1;
									break;
								case ERROR_NOT_ENOUGH_MEMORY:
									ret = -1;
									errno = ENOMEM;
									break;
								case ERROR_BAD_COMMAND:
									ret = -1;
									errno = EINVAL;
									break;
								default:
									ret = -1;
									break;
							}
						}
					}
				}
			}
			break;
		case F_SETLKW64:
			{
				struct flock64 * lockInfo = va_arg(list, struct flock64 *);
				HANDLE hnd = (HANDLE)_get_osfhandle(fd);
				errno = 0;
				if(lockInfo == NULL)
				{
					ret = -1;
					errno = EINVAL;
				}
				else if(hnd == INVALID_HANDLE_VALUE)
				{
					errno = EBADF;
					ret = -1;
				}
				else
				{
					DWORD lastError;
					BOOL lockRet = 0;

					_QWORD pos;
					pos = lockInfo->l_start;

					SetLastError(ERROR_SUCCESS);
					pos = GetFilePos(hnd, lockInfo->l_whence, pos);

					if(GetLastError() == ERROR_SUCCESS)
					{
						do
						{
							lastError = 0;
							lockRet = FALSE;

							lockRet = LockFile(hnd, pos.ddLower, pos.ddUpper, lockInfo->l_len.ddLower, lockInfo->l_len.ddUpper);

							if(!lockRet)
							{
								lastError = GetLastError();

								if(lastError == ERROR_LOCK_VIOLATION)
								{
									Sleep(10);
								}
							}
						}
						while(!lockRet && lastError == ERROR_LOCK_VIOLATION);
					}

					if(lockRet)
					{
						ret = 0;
					}
					else
					{
						switch(GetLastError())
						{
							case ERROR_LOCK_VIOLATION:
								errno = EAGAIN;
								ret = -1;
								break;
							case ERROR_NOT_ENOUGH_MEMORY:
								ret = -1;
								errno = ENOMEM;
								break;
							case ERROR_BAD_COMMAND:
								ret = -1;
								errno = EINVAL;
								break;
							default:
								ret = -1;
								break;
						}
					}
				}
			}
			break;
	}

	va_end(list);
	return ret;
}
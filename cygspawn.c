/* Hacky non-forking posix_spawn implementation for Cygwin -*- c-file-style: "qgnu" -*- */
#define _WIN32_WINNT 0x500
#include <sys/param.h>

#undef FD_SETSIZE
#define FD_SETSIZE NOFILE

#include <windows.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <process.h>
#include <assert.h>
#include <sys/cygwin.h>
#include <sys/mman.h>
#include "cygspawn.h"

/* VERIFY(x) is like assert, except that in NDEBUG builds, VERIFY
   evaluates x anyway.  The value of VERIFY(x) is 1 if x is true and 0
   otherwise.  */

#ifdef NDEBUG
#define VERIFY(x) (!!(x))
#else
#define VERIFY(x) (assert (x), 1)
#endif /* NDEBUG */

int
cygwin_spawn_file_actions_adddup3 (
  posix_spawn_file_actions_t *file_actions,
  int filedes,
  int newdes,
  int flags);

struct spawn_fdop
{
  enum { FDOP_CLOSE, FDOP_OPEN, FDOP_DUP } type;
  union {
    struct {
      int filedes;
    } close;

    struct {
      int filedes;
      int newdes;
      int flags;
    } dup;

    struct {
      int filedes;
      char *path;
      int oflag;
      mode_t mode;
    } open;
  };
};

struct cygwin_spawn_info
{
  struct sched_param schedparam;
  sigset_t sigdefault;
  sigset_t sigmask;
  pid_t pgroup;
  int schedpolicy;
  short flags;
};

struct cygwin_spawn_ops
{
  struct cygwin_spawn_info info;
  unsigned nr;
  unsigned capacity;
  unsigned use_execvpe : 1;
  char *args; /* Relative to struct base.  */
  struct spawn_fdop ops[];
};

static size_t
ops_size (unsigned capacity)
{
  struct cygwin_spawn_ops *so;
  return sizeof (*so) + sizeof (so->ops[0]) * capacity;
}

/* The sequence of file operations given us a small program.
   Partially evaluate this program, giving us the set of file
   descriptors in the parent that we need to allow the child to
   inherit.  Add entries to rollback to restore the parent's
   state.  */
static int
prepare_ops (
  const struct cygwin_spawn_ops *orig,
  struct cygwin_spawn_ops **child,
  struct cygwin_spawn_ops **rollback)
{
  unsigned i;
  fd_set opened_fds;
  fd_set closed_fds;
  int ret = -1;

  FD_ZERO (&opened_fds);
  FD_ZERO (&closed_fds);

  for (i = 0; i < orig->nr; ++i)
    {
      const struct spawn_fdop *op = &orig->ops[i];
      int input_fd = -1;

      if (op->type == FDOP_CLOSE)
        input_fd = op->close.filedes;
      else if (op->type == FDOP_DUP)
        input_fd = op->dup.filedes;

      if (input_fd != -1 && FD_ISSET (input_fd, &closed_fds))
        {
          errno = EBADF; /* Oops.  */
          goto out;
        }

      if (input_fd != -1 && !FD_ISSET (input_fd, &opened_fds))
        {
          /* We haven't seen the input file file descriptor before, so
             it must come from the parent.  If the file descriptor
             doesn't exist there, die early.  Otherwise, make sure the
             child gets the FD across exec.  */
          int flags = fcntl (input_fd, F_GETFD);
          if (flags < 0)
            goto out;

          if (op->type == FDOP_CLOSE && (flags & FD_CLOEXEC))
            {
              /* We're supposed to close this descriptor, but the
                 system will have closed it for us in the exec.  Skip
                 this descriptor entirely, but remember it's supposed
                 to be closed.  */
              FD_SET (input_fd, &closed_fds);
              continue;
            }

          if (op->type == FDOP_CLOSE && !(flags & FD_CLOEXEC))
            {
              /* We're supposed to close this file descriptor, but
                 it's marked as inheritable.  Instead of making the
                 child close it, temporarily mark is CLOEXEC so the
                 child doesn't have to deal with it at all.  Remember
                 that it's supposed to be closed.  */
              if (cygwin_spawn_file_actions_adddup3 (
                    rollback, input_fd, input_fd, flags) < 0)
                goto out;

              if (fcntl (input_fd, F_SETFD, flags | FD_CLOEXEC) < 0)
                goto out;

              FD_SET (input_fd, &closed_fds);
              continue;
            }

          if (flags & FD_CLOEXEC)
            {
              /* Turn off CLOEXEC in parent so the child can get at
                 the file descriptor.  Remember to restore flags
                 later.  */
              if (cygwin_spawn_file_actions_adddup3 (
                    rollback, input_fd, input_fd, flags) < 0)
                goto out;

              if (fcntl (input_fd, F_SETFD, flags &~ FD_CLOEXEC) < 0)
                goto out;
            }

          /* input_fd is now available to the child.  Remember that
             it's supposed to be open.  */
          FD_SET (input_fd, &opened_fds);
        }

      if (op->type == FDOP_CLOSE)
        {
          assert (op->close.filedes == input_fd);
          if (posix_spawn_file_actions_addclose (
                child, op->close.filedes) < 0)
            goto out;

          FD_CLR (op->close.filedes, &opened_fds);
          FD_SET (op->close.filedes, &closed_fds);
          continue;
        }

      if (op->type == FDOP_DUP)
        {
          assert (op->dup.filedes == input_fd);
          if (cygwin_spawn_file_actions_adddup3 (
                child,
                op->dup.filedes,
                op->dup.newdes,
                op->dup.flags) < 0)
            goto out;

          FD_CLR (op->dup.newdes, &closed_fds);
          FD_SET (op->dup.newdes, &opened_fds);
          continue;
        }

      if (op->type == FDOP_OPEN)
        {
          assert (input_fd == -1);
          if (posix_spawn_file_actions_addopen (
                child,
                op->open.filedes,
                op->open.path,
                op->open.oflag,
                op->open.mode) < 0)
            goto out;

          FD_CLR (op->open.filedes, &closed_fds);
          FD_SET (op->open.filedes, &opened_fds);
          continue;
        }

      assert (!"unknown operation type");
    }

  ret = 0;

 out:
  return ret;
}

/* Count how many additional bytes are needed to encode the pointed-to
   information in so.  */
static size_t
sum_string_sizes (const struct cygwin_spawn_ops *so)
{
  unsigned i;
  size_t sum = 0;

  for (i = 0; i < so->nr; ++i)
    {
      const struct spawn_fdop *op = &so->ops[i];
      if (op->type == FDOP_OPEN)
        sum += strlen (op->open.path) + 1;
    }

  return sum;
}

/* If BLOCK is non-NULL, copy each string in SO to BLOCK and change
   its pointer to match, freeing the original string.  In any case,
   add OFF to all string pointers after doing any other work.  */
static void
rewrite_strings (struct cygwin_spawn_ops *so,
                 void *block,
                 ptrdiff_t off)
{
  char *pos = block;
  unsigned i;

  for (i = 0; i < so->nr; ++i)
    {
      struct spawn_fdop *op = &so->ops[i];
      if (op->type == FDOP_OPEN)
        {
          if (pos)
            {
              const char *path = op->open.path;
              ptrdiff_t len;

              do {
                *pos++ = *path++;
              } while (*path);

              len = path - op->open.path;
              free (op->open.path);
              op->open.path = (pos - len);
            }

          op->open.path += off;
        }
    }
}

static char *
get_this_module_path ()
{
  HMODULE module;
  DWORD winpath_length;
  DWORD nc;
  wchar_t *new_winpath;
  int saved_errno;

  wchar_t *winpath = NULL;
  char *path = NULL;
  char *ret = NULL;

  if (GetModuleHandleExW (
        (GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
         GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT),
        (wchar_t*) &get_this_module_path,
        &module)
      == FALSE)
    {
      errno = ENOENT;
      goto out;
    }

  winpath_length = 128;

 embiggen_buffer:

  winpath_length *= 2;

  new_winpath = realloc (winpath, winpath_length * sizeof (*winpath));
  if (!new_winpath)
    goto out;

  winpath = new_winpath;
  new_winpath = NULL;

  nc = GetModuleFileNameW (module, winpath, winpath_length);
  if (nc == winpath_length)
    goto embiggen_buffer;

  if (nc == 0)
    {
      errno = ENOENT;
      goto out;
    }

  path = cygwin_create_path (CCP_WIN_W_TO_POSIX, winpath);
  if (!path)
    goto out;

  ret = path;
  path = NULL;

 out:

  saved_errno = errno;
  free (winpath);
  free (path);
  errno = saved_errno;

  return ret;
}

static int
copy_strvec (
  const char *const *vec,
  char ***out,
  size_t extra_before,
  size_t extra_after)
{
  size_t nr;
  char **newvec = NULL;
  const char *const *pos;

  for (pos = vec; *pos; ++pos)
    ++nr;

  newvec = malloc (sizeof (*newvec) *
                   (nr + extra_before + extra_after + 1));
  if (!newvec)
    return -1;

  memcpy (newvec + extra_before, vec, sizeof (*newvec) * (nr + 1));
  *out = &newvec[0];
  return 0;
}

static void
xputenv (char **envp, const char *var)
{
  const char *var_val = strchr (var, '=') + 1;
  for (; *envp; ++envp)
    if (strncmp (*envp, var, var_val - var) == 0)
      break;

  if (*envp)
    *envp = (char *) var;
  else
    {
      *envp++ = (char *) var;
      *envp = NULL;
    }
}

static const char *
xgetenv (char **envp, const char *var_name)
{
  for (; *envp; ++envp)
    {
      const char *b = strchr (*envp, '=');
      if (b && strncmp (*envp, var_name, b - *envp) == 0)
        {
          return b + 1;
        }
    }

  return NULL;
}

static char *
prepend_preload (const char *module,
                 const char *old_preload)
{
  const char *prefix = "LD_PRELOAD=";
  const char *sep;

  if (old_preload)
    sep = ":";
  else
    {
      sep = "";
      old_preload = "";
    }

  char *new_preload = malloc (
    1 + strlen (prefix) +
    strlen (module) + strlen (sep) +
    strlen (old_preload));

  if (new_preload)
    sprintf (new_preload, "%s%s%s%s", prefix, module, sep, old_preload);

  return new_preload;
}

static int
run_ops (const struct cygwin_spawn_ops *so, int fd_flag_mask)
{
  unsigned i;
  for (i = 0; i < so->nr; ++i)
    {
      const struct spawn_fdop *op = &so->ops[i];
      if (op->type == FDOP_OPEN)
        {
          int opened;
          int oflag = op->open.oflag;
          if (fd_flag_mask & FD_CLOEXEC)
            oflag &= ~O_CLOEXEC;

          if ((opened = open (op->open.path, oflag, op->open.mode)) < 0)
            return -1;

          if (opened != op->open.filedes)
            {
              int flags = fcntl (opened, F_GETFD);

              if (flags < 0)
                {
                  close (opened);
                  return -1;
                }

              if (dup3 (opened, op->open.filedes, flags) < 0)
                {
                  close (opened);
                  return -1;
                }

              if (close (opened) < 0)
                return -1;
            }
        }
      else if (op->type == FDOP_DUP)
        {
          int flags = op->dup.flags & fd_flag_mask;
          if (op->dup.filedes == op->dup.newdes)
            {
              if (fcntl (op->dup.filedes, F_SETFD, flags) < 0)
                return -1;
            }
          else
            if (dup3 (op->dup.filedes, op->dup.newdes, flags) < 0)
              return -1;
        }
      else if (op->type == FDOP_CLOSE)
        {
          if (close (op->close.filedes) < 0)
            return -1;
        }
      else
        {
          assert ("!unknown operation type");
          errno = EINVAL;
          return -1;
        }
    }

  return 0;
}

static int
search_path (const char *path, const char *base,
             int *exefd_out, char **name_out)
{
  char *candidate = NULL;
  size_t name_length = 0;
  int exefd;
  size_t component_length;
  const char *component;
  size_t base_length = strlen (base);

  while (*path)
    {
      component = path;
      component_length = strcspn(component, ":");
      path += component_length;
      if (*path) ++path;

      if (component_length == 0)
        {
          /* An empty path component means the current directory.  */
          component = ".";
          component_length = 1;
        }

      if (name_length < base_length + component_length + 2)
        {
          char *new_candidate;
          name_length = base_length + component_length + 2;
          if (!(new_candidate = realloc (candidate, name_length)))
            goto err;
          candidate = new_candidate;
        }

      {
        char *name_pos = candidate;
        memcpy (name_pos, component, component_length);
        name_pos += component_length;
        *name_pos = '/';
        name_pos += 1;
        memcpy (name_pos, base, base_length);
        name_pos += base_length;
        *name_pos = '\0';
      }

      if ((exefd = open (candidate, O_RDONLY | O_CLOEXEC)) >= 0)
        break;
    }

  if (exefd == -1)
    {
      errno = ENOENT;
      goto err;
    }

  *name_out = candidate;
  *exefd_out = exefd;
  return 0;

 err:
  free (candidate);
  return -1;
}

static int
is_cygwin_executable (int opt_exefd, const char *exepath)
{
  int ret = -1;
  int exefd = opt_exefd;
  char *img;
  off_t imgsz;
  IMAGE_DOS_HEADER *dh;
  IMAGE_NT_HEADERS32 *nth;
  IMAGE_OPTIONAL_HEADER32 *opt;
  IMAGE_IMPORT_DESCRIPTOR *import;

  if (exefd == -1 &&
      (exefd = open (exepath, O_RDONLY | O_CLOEXEC)) < 0)
    goto out;

  imgsz = lseek (exefd, 0, SEEK_END);
  if (imgsz == (off_t) -1)
    goto out;

  if (imgsz > (size_t) -1) imgsz = (size_t) -1;
  if ((img = mmap (NULL, (size_t) imgsz,
                   PROT_READ, MAP_PRIVATE, exefd, 0)) == NULL)
    goto out;

#define C(pred) ({if (!(pred)) { ret = 0; goto out; }})
#define V(sptr, sz)                                                     \
  C (img <= (char *) (sptr) && (char *) (sptr) + (sz) <= img + imgsz)
#define A(rva) ({                                                       \
      char *x = (char *) (rva);                                         \
      char *sb = NULL;                                                  \
      IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION (nth);              \
      IMAGE_SECTION_HEADER *se = s + nth->FileHeader.NumberOfSections;  \
      for (; s < se; ++s)                                               \
        {                                                               \
          V (s, sizeof (*s));                                           \
          sb = (char *) s->VirtualAddress;                              \
          if ( sb <= x && x < sb + s->Misc.VirtualSize)                 \
            break;                                                      \
        }                                                               \
                                                                        \
      C (s != se);                                                      \
      (void *)(img + s->PointerToRawData + (x - sb));                   \
    })

  if (imgsz >= 2 && img[0] == '#' && img[1] == '!')
    {
      ret = 1;
      goto out;
    }

  dh = (void *) img;
  V (dh, sizeof (*dh));
  C (dh->e_magic == IMAGE_DOS_SIGNATURE);
  nth = (void *) (img + dh->e_lfanew);
  V (nth, sizeof (*nth));

  C (nth->Signature == IMAGE_NT_SIGNATURE);
  C (nth->FileHeader.Machine == IMAGE_FILE_MACHINE_I386);
  opt = &nth->OptionalHeader;

  C (opt->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
  C (opt->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI);

  import = A (opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
              .VirtualAddress);

  for (;; ++import)
    {
      char *name;
      char *name_end;

      V (import, sizeof (*import));
      if (import->Name == 0)
        break;

      name = name_end = A (import->Name);
      do
        V (name_end, 1);
      while (*name_end++);

      if (!strcmp (name, "cygwin1.dll"))
        {
          ret = 1;
          goto out;
        }
    }

#undef A
#undef V
#undef C

  ret = 0;

 out:

  if (ret == -1 && errno == ENODATA)
      ret = 0; /* Ran off end of file */

  if (img)
    VERIFY (munmap (img, imgsz) == 0);

  if (exefd != -1 && exefd != opt_exefd)
    VERIFY (close (exefd) == 0);

  return ret;
}

static void
encode_strvec (const char *prgname,
               char *const restrict *restrict argv,
               char *out,
               size_t *bytes_out)
{
  const char *item;
  char *start = out;

#define OUTC(c) ({ char t = (c); if (start) *out = t; ++out; })

  item = prgname;
  do
    {
      if (*item == '\0') OUTC ('!');
      if (*item == '!' ) OUTC ('!');

      do
        OUTC (*item++);
      while (item[-1]);

      item = *argv++;
    }
  while (item);

  if (bytes_out)
    *bytes_out = (out - start);

#undef OUTC
}

/* Build an array of pointers to strings.  Each element in the array
   points to a string in the doubly-null-terminated list of strings
   BUF.  Store the array, which must be freed, into *VEC_OUT.  */
static int
decode_strvec (const char *buf, const char ***vec_out)
{
  size_t nrstr;
  size_t i;
  const char *pos;
  const char **vec;

  pos = buf;
  while (*pos)
    {
      ++nrstr;
      pos += strlen (pos) + 1;
    }

  vec = malloc (sizeof (*vec) * (nrstr + 1));
  if (!vec)
    return -1;

  for (i = 0, pos = buf; *pos; ++i, pos += strlen (pos) + 1)
    {
      vec[i] = pos;
      if (vec[i][0] == '!') vec[i] += 1;
    }

  vec[i] = NULL;
  *vec_out = vec;
  return 0;
}

static int
cygspawn (
  int exefd,
  const char *restrict exepath,
  int use_spawnvpe,
  pid_t *restrict pid,
  const posix_spawn_file_actions_t *file_actions,
  const posix_spawnattr_t *restrict attrp,
  char *const restrict *restrict argv,
  char *const restrict *restrict envp)
{
  /* N.B. This code is slightly racy because we temporary turn off
     O_CLOEXEC on some file descriptors in order to allow them to be
     inherited across exec.  If another thread creates a process, it
     might unintentionally cause some files to be inherited there.

     We also race if POSIX_SPAWN_RESETIDS is used: we use seteuid and
     setegid in the parent so that the child starts with the
     appropriate token.  We can't call these functions in the child
     because NT doesn't allow a process token to change after
     creation, so we switch UID and GID in the parent, then switch
     back after the spawn call.

     If another thread creates a process in window during which we've
     changed our eUIDs, its child will have the wrong credentials.  We
     ameliorate the race to some degree by blocking all signals [1]
     around the credential manipulation, but we really should somehow
     block the execution of other threads too.

     [1] Amazingly, execve and fork are async-signal-safe according to
     POSIX.
  */

  HANDLE section = NULL;
  DWORD section_base_size;
  size_t argv_extra = 0;
  DWORD section_size;
  SECURITY_ATTRIBUTES section_sa =
      { sizeof (section_sa), NULL /* descriptor */, TRUE /* inherit */};

  int ret = -1;
  int saved_errno;

  sigset_t orig_sigmask;
  sigset_t all_signals;
  int changed_sigmask = 0;

  int switched_ids = 0;
  int orig_euid = 0;
  int orig_egid = 0;

  const struct cygwin_spawn_ops *orig_so = NULL;
  struct cygwin_spawn_ops *shared_so = NULL;
  struct cygwin_spawn_ops *rollback_so = NULL;
  char handle_desc[64];
  char *module_path = NULL;
  char *ld_preload = NULL;
  char **new_envp = NULL;

  if (!is_cygwin_executable (exefd, exepath))
    {
      /* It looks like we're about to run a non-Cygwin program, run
         /bin/false first as a minimal LD_PRELOAD host.  The
         LD_PRELOAD code there execs the caller's program.  (We can't
         just use /usr/bin/env because we need to be able to set
         argv[0] separately from the program name.)  */
      encode_strvec (exepath, argv, NULL, &argv_extra);
    }

  if (file_actions)
    orig_so = *file_actions;

  if (orig_so)
    /* Size for worst-case expansion.  */
    section_base_size = ops_size (orig_so->nr * 2);
  else
    section_base_size = ops_size (0);

  /* Make room for strings we'll have to copy as well.  */
  section_size = section_base_size;

  if (orig_so)
    section_size += sum_string_sizes (orig_so);

  /* The child inherits a HANDLE pointing to a shared memory segment
     telling it what to do.  Create the segment.  */

  section = CreateFileMapping (INVALID_HANDLE_VALUE /*pagefile*/,
                               &section_sa,
                               PAGE_READWRITE | SEC_COMMIT,
                               0, section_size + argv_extra,
                               NULL /*anonymous*/);

  if (section == NULL)
    {
      errno = cygwin_internal (CW_GET_ERRNO_FROM_WINERROR,
                               GetLastError (), ENOMEM);
      goto out;
    }

  shared_so = MapViewOfFile (section, FILE_MAP_WRITE, 0, 0, 0);
  if (shared_so == NULL)
    {
      errno = cygwin_internal (CW_GET_ERRNO_FROM_WINERROR,
                               GetLastError (), ENOMEM);
      goto out;
    }

  /* shared_so is zero-initialized by the OS. */

  if (attrp)
    shared_so->info = **attrp;

  if (orig_so)
    {
      shared_so->capacity = orig_so->nr * 2;

      if (posix_spawn_file_actions_init (&rollback_so) < 0)
        goto out;

      if (prepare_ops (orig_so, &shared_so, &rollback_so) < 0)
        goto out;
    }

  /* Make all strings point into the shared section.  Make all
     pointers relative to the shared section base.  */
  rewrite_strings (shared_so,
                   (char *) shared_so + section_base_size,
                   -1 * (ptrdiff_t) shared_so);

  /* Set up the environment so that Cygwin loads this DLL in the
     spawned child.  */

  if ((module_path = get_this_module_path ()) == NULL)
    goto out;

  if (!envp)
    envp = environ;

  if (copy_strvec ((const char *const *)envp, &new_envp, 0, 2) < 0)
    goto out;

  /* Tell the child where to find more information.  */
  sprintf (handle_desc, "_CYGSPAWN_SECTION=%lx",
           (unsigned long) section);
  xputenv (new_envp, handle_desc);

  /* Tell Cygwin to load us in the child.  */
  ld_preload = prepend_preload (module_path,
                                xgetenv (new_envp, "LD_PRELOAD"));
  if (!ld_preload)
    goto out;

  xputenv (new_envp, ld_preload);

  if (shared_so->info.flags & (POSIX_SPAWN_SETSIGMASK |
                               POSIX_SPAWN_SETSIGDEF |
                               /* see race comment above */
                               POSIX_SPAWN_RESETIDS  ))
    {
      if (sigfillset (&all_signals) < 0)
        goto out;

      if (sigprocmask (SIG_BLOCK, &all_signals, &orig_sigmask) < 0)
        goto out;

      changed_sigmask = 1;

      if (!(shared_so->info.flags & POSIX_SPAWN_SETSIGMASK))
        {
          shared_so->info.sigmask = orig_sigmask;
          shared_so->info.flags |= POSIX_SPAWN_SETSIGMASK;
        }
    }

  if (shared_so->info.flags & POSIX_SPAWN_RESETIDS)
    {
      orig_euid = geteuid ();
      orig_egid = getegid ();
      VERIFY (seteuid (getuid ()));
      VERIFY (setegid (getgid ()));
      switched_ids = 1;
    }

  if (argv_extra)
    {
      char *buf = (char *) shared_so + section_size;
      shared_so->args = (buf - (ptrdiff_t) shared_so);
      shared_so->use_execvpe = use_spawnvpe;

      encode_strvec (exepath, argv, buf, NULL);
      ret = spawnle (_P_NOWAIT, "/bin/false", "false", NULL, new_envp);
    }
  else
    ret = (use_spawnvpe ? spawnvpe : spawnve) (
      _P_NOWAIT, exepath,
      (const char * const *) argv,
      (const char * const *) new_envp);

  if (ret < 0)
    goto out;

  *pid = (pid_t) ret;
  ret = 0;

 out:

  saved_errno = errno;

  if (switched_ids)
    {
      VERIFY (seteuid (orig_euid));
      VERIFY (setegid (orig_egid));
    }

  if (changed_sigmask)
    VERIFY (sigprocmask (SIG_SETMASK, &orig_sigmask, NULL) == 0);

  if (section)
    VERIFY (CloseHandle (section));

  if (shared_so)
    VERIFY (UnmapViewOfFile (shared_so));

  if (rollback_so)
    {
      VERIFY (run_ops (rollback_so, 0) == 0);
      VERIFY (posix_spawn_file_actions_destroy (&rollback_so) == 0);
    }

  close (exefd);
  free (new_envp);
  free (ld_preload);
  free (module_path);
  errno = saved_errno;
  return ret;
}

/* NV is a colon-separated list of paths.  ENTRY_TO_REMOVE is an
   element that might be in NV.  Modify NV in-place to remove up to
   MAX_TO_REMOVE instances of ENTRY_TO_REMOVE.  */
static void
remove_from_path_list (char *nv,
                       const char *entry_to_remove,
                       unsigned max_to_remove
                       )
{
  size_t slen = strlen (nv);
  size_t rlen = strlen (entry_to_remove);
  char *pos = nv;

  while (max_to_remove > 0 && (pos = strstr (pos, entry_to_remove)))
    if ((pos[rlen] == '\0' || pos[rlen] == ':') &&
        (pos == nv || pos[-1] == ':'))
      {
        size_t elen = rlen + (pos[rlen] == ':');
        memmove (pos, pos + elen, 1 + slen - elen - (pos - nv));
        --max_to_remove;
      }
    else
      pos += rlen;
}

static int
apply_spawn_info (const struct cygwin_spawn_info *si)
{
  /* We don't need to worry about rolling back any of
     these changes because we just exit if something goes wrong.  */
  int schedpolicy = si->schedpolicy;
  struct sched_param schedparam = si->schedparam;
  short flags = si->flags;
  int signo;

  if (flags & (POSIX_SPAWN_SETSCHEDPARAM | POSIX_SPAWN_SETSCHEDULER))
    {
      if (!(flags & POSIX_SPAWN_SETSCHEDULER) &&
          (schedpolicy = sched_getscheduler (0)) < 0)
        return -1;

      if (!(flags & POSIX_SPAWN_SETSCHEDPARAM) &&
          sched_getparam (0, &schedparam) < 0)
        return -1;

      if (sched_setscheduler (0, schedpolicy, &schedparam) < 0)
        return -1;
    }

  if ((flags & POSIX_SPAWN_SETPGROUP) &&
      setpgid (0, si->pgroup) < 0)
    return -1;

  /* To prevent race, reset signal actions before unblocking signals.
     If POSIX_SPAWN_SETSIGMASK was used, the parent also set
     POSIX_SPAWN_SETSIGDEF.  */

  if (flags & POSIX_SPAWN_SETSIGDEF)
    for (signo = 1; signo < NSIG; ++signo)
      if (sigismember (&si->sigdefault, signo) &&
            signal (signo, SIG_DFL) == SIG_ERR)
        return -1;

  if ((flags & POSIX_SPAWN_SETSIGMASK) &&
      sigprocmask (SIG_SETMASK, &si->sigmask, NULL) < 0)
    return -1;

  /* POSIX_SPAWN_RESETIDS was handled in parent.  */

  return 0;
}

__attribute__((constructor))
static void
init ()
{
  HANDLE section = NULL;
  struct cygwin_spawn_ops *so = NULL;
  char *module_path = NULL;
  char *new_ld_preload = NULL;
  const char *section_str;
  const char *ld_preload;

  /* Were we created by posix_spawn?  */
  if ((section_str = getenv ("_CYGSPAWN_SECTION")) == NULL)
    return; /* No.  */

  /* Read instructions from our parent.  */
  section = (HANDLE) strtoul (section_str, NULL, 16);

  /* Remove our contribution to the environment.  */
  unsetenv ("_CYGSPAWN_SECTION");
  if ((module_path = get_this_module_path ())
      && (ld_preload = getenv ("LD_PRELOAD"))
      && (new_ld_preload = strdup (ld_preload)))
    {
      /* Remove only one instance of this module from LD_PRELOAD
         because our parent only added it once.  */
      remove_from_path_list (new_ld_preload, module_path, 1);

      if (new_ld_preload[0])
        setenv ("LD_PRELOAD", new_ld_preload, 1);
      else
        unsetenv ("LD_PRELOAD");
    }

  if (section == NULL)
    _exit (127);

  so = MapViewOfFile (section, FILE_MAP_WRITE, 0, 0, 0);
  if (so == NULL)
    _exit (127);

  VERIFY (CloseHandle (section));
  rewrite_strings (so, NULL, (ptrdiff_t) so);

  /* Do what our parent told us to do.  If we're about to exec again,
     turn off FD_CLOEXEC on file descriptors we make so that the
     non-Cygwin child will inherit them.  */
  if (apply_spawn_info (&so->info) < 0 ||
      run_ops (so, so->args ? FD_CLOEXEC : 0) < 0)
    _exit (127); /* Exit code specified by POSIX. */

  if (so->args)
    {
      /* Parent told us to exec.  args below points to a
         doubly-null-terminated list.  The first element is the
         program to execute; the rest form argv.  */
      const char ** exec_args;
      if (decode_strvec (so->args + (ptrdiff_t) so, &exec_args) < 0)
        _exit (127);

      if (so->use_execvpe)
        execvpe (exec_args[0], (char *const *) exec_args + 1, NULL);
      else
        execve (exec_args[0],  (char *const *) exec_args + 1, NULL);

      _exit (127);
    }

  free (module_path);
  free (new_ld_preload);
  VERIFY (UnmapViewOfFile (so));
}

int
posix_spawn (
  pid_t *restrict pid,
  const char *restrict path,
  const posix_spawn_file_actions_t *file_actions,
  const posix_spawnattr_t *restrict attrp,
  char *const restrict argv[restrict],
  char *const restrict envp[restrict])
{
  return cygspawn (-1, path, 0, pid, file_actions, attrp, argv, envp);
}

int
posix_spawnp (
  pid_t *restrict pid,
  const char *restrict path,
  const posix_spawn_file_actions_t *file_actions,
  const posix_spawnattr_t *restrict attrp,
  char *const restrict argv[restrict],
  char *const restrict envp[restrict])
{
  int ret;
  int exefd;
  char *exepath;
  char *is_absolute = strchr (path, '/');

  if (is_absolute)
    {
      exepath = (char *) path;
      exefd = -1;
    }
  else
    if (search_path ((getenv ("PATH") ?: "/bin:/usr/bin"),
                     path, &exefd, &exepath) < 0)
      return -1;

  ret = cygspawn (exefd, exepath, 1, pid, file_actions, attrp, argv, envp);

  if (exefd != -1)
    VERIFY (close (exefd));

  if (!is_absolute)
    free (exepath);

  return ret;
}

int
posix_spawn_file_actions_init (
  posix_spawn_file_actions_t *file_actions)
{
  static const unsigned initial_capacity = 512;
  struct cygwin_spawn_ops *so = malloc (ops_size (initial_capacity));
  if (!so)
    return -1;

  so->nr = 0;
  so->capacity = initial_capacity;
  *file_actions = so;
  return 0;
}

int
posix_spawn_file_actions_destroy (
  posix_spawn_file_actions_t *file_actions)
{
  struct cygwin_spawn_ops *so = *file_actions;
  unsigned i;

  for (i = 0; i < so->nr; ++i)
    {
      if (so->ops[i].type == FDOP_OPEN)
        {
          free (so->ops[i].open.path);
        }
    }

  free (so);
  *file_actions = NULL;
  return 0;
}

static struct spawn_fdop *
alloc_fdop (struct cygwin_spawn_ops **sop)
{
  struct cygwin_spawn_ops *so = *sop;

  if (so->nr == so->capacity)
    {
      unsigned newcap = so->capacity * 2;
      so = realloc (so, ops_size (newcap));

      if (!so)
        return NULL;

      so->capacity = newcap;
      *sop = so;
    }

  return &so->ops[so->nr++];
}

int
posix_spawn_file_actions_addclose (
  posix_spawn_file_actions_t *file_actions,
  int filedes)
{
  struct spawn_fdop *op;

  if (! (0 <= filedes && filedes < FD_SETSIZE))
    {
      errno = EBADF; /* posix */
      return -1;
    }

  if ((op = alloc_fdop (file_actions)) == NULL)
    return -1;

  op->type = FDOP_CLOSE;
  op->close.filedes = filedes;
  return 0;
}

int
cygwin_spawn_file_actions_adddup3 (
  posix_spawn_file_actions_t *file_actions,
  int filedes,
  int newdes,
  int flags)
{
  struct spawn_fdop *op;

  if (! (0 <= filedes && filedes < FD_SETSIZE) ||
      ! (0 <= newdes && newdes < FD_SETSIZE)   )
    {
      errno = EBADF; /* POSIX */
      return -1;
    }

  if (!(op = alloc_fdop (file_actions)))
    return -1;

  op->type = FDOP_DUP;
  op->dup.filedes = filedes;
  op->dup.newdes = newdes;
  op->dup.flags = flags;
  return 0;
}

int
posix_spawn_file_actions_adddup2 (
  posix_spawn_file_actions_t *file_actions,
  int filedes,
  int newdes)
{
  return cygwin_spawn_file_actions_adddup3 (
    file_actions, filedes, newdes, 0);
}

int
posix_spawn_file_actions_addopen (
  posix_spawn_file_actions_t *file_actions,
  int filedes,
  const char *restrict path,
  int oflag,
  mode_t mode)
{
  char *pathcopy;
  struct spawn_fdop *op;

  if (! (0 <= filedes && filedes < FD_SETSIZE))
    {
      errno = EBADF; /* posix */
      return -1;
    }

  if (!(pathcopy = strdup (path)))
    return -1;

  op = alloc_fdop (file_actions);
  if (!op)
    {
      free (pathcopy);
      return -1;
    }

  op->type = FDOP_OPEN;
  op->open.filedes = filedes;
  op->open.path = pathcopy;
  op->open.oflag = oflag;
  op->open.mode = mode;
  return 0;
}

int
posix_spawnattr_init (posix_spawnattr_t *attr)
{
  *attr = calloc (1, sizeof (**attr));
  return (*attr == NULL) ? -1 : 0;
}

int
posix_spawnattr_destroy (
  posix_spawnattr_t *attr)
{
  free (*attr);
  *attr = NULL;
  return 0;
}

int
posix_spawnattr_getflags (
  const posix_spawnattr_t *restrict attr,
  short *restrict flags)
{
  *flags = (*attr)->flags;
  return 0;
}

int
posix_spawnattr_setflags (
  posix_spawnattr_t *attr,
  short flags)
{
  if ((flags & CYGWIN_SPAWN_VALID_FLAGS) != flags)
    {
      errno = EINVAL;
      return -1;
    }

  (*attr)->flags = flags;
  return 0;
}

int
posix_spawnattr_getpgroup (
  const posix_spawnattr_t *restrict attr,
  pid_t *restrict pgroup)
{
  *pgroup = (*attr)->pgroup;
  return 0;
}

int
posix_spawnattr_setpgroup (
  posix_spawnattr_t *attr,
  pid_t pgroup)
{
  (*attr)->pgroup = pgroup;
  return 0;
}

int
posix_spawnattr_getsigdefault (
  const posix_spawnattr_t *restrict attr,
  sigset_t *restrict sigdefault)
{
  *sigdefault = (*attr)->sigdefault;
  return 0;
}

int
posix_spawnattr_setsigdefault (
  posix_spawnattr_t *restrict attr,
  const sigset_t *restrict sigdefault)
{
  (*attr)->sigdefault = *sigdefault;
  return 0;
}

int
posix_spawnattr_getschedparam (
  const posix_spawnattr_t *restrict attr,
  struct sched_param *restrict schedparam)
{
  *schedparam = (*attr)->schedparam;
  return 0;
}

int
posix_spawnattr_setschedparam (
  posix_spawnattr_t *restrict attr,
  const struct sched_param *restrict schedparam)
{
  (*attr)->schedparam = *schedparam;
  return 0;
}

int
posix_spawnattr_getschedpolicy (
  const posix_spawnattr_t *restrict attr,
  int *schedpolicy)
{
  *schedpolicy = (*attr)->schedpolicy;
  return 0;
}

int
posix_spawnattr_setschedpolicy (
  posix_spawnattr_t *restrict attr,
  int schedpolicy)
{
  (*attr)->schedpolicy = schedpolicy;
  return 0;
}

int
posix_spawnattr_getsigmask (
  const posix_spawnattr_t *restrict attr,
  sigset_t *restrict sigmask)
{
  *sigmask = (*attr)->sigmask;
  return 0;
}

int
posix_spawnattr_setsigmask (
  posix_spawnattr_t *restrict attr,
  const sigset_t *restrict sigmask)
{
  (*attr)->sigmask = *sigmask;
  return 0;
}

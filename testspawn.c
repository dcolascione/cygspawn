/* Hacky non-forking posix_spawn implementation for Cygwin -*- c-file-style: "qgnu" -*- */
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef USE_FORK
typedef void *posix_spawn_file_actions_t;
#else
#include "cygspawn.h"
#endif

int verbose=0;

static void
usage ()
{
  fprintf (stderr,
           "testspawn [-vg] SHELL_REDIR* PROGRAM ARGS*: test posix_spawn\n");
}

static int
process_redirection (
  posix_spawn_file_actions_t* file_actions,
  const char *redir)
{
  int srcfd;
  char *pos;
  int dstfd;
  int oflag;
  int mode = 0666;

  srcfd = (int) strtol (redir, &pos, 10);
  switch (pos[0])
    {
    case '<': if (pos == redir) srcfd = 0; break;
    case '>': if (pos == redir) srcfd = 1; break;
    default: goto invalid;
    }

  if (pos[1] == '&')
    {
      pos += 2;

      if (pos[0] == '-' && pos[1] == '\0')
        {
          goto do_close;
        }

      dstfd = (int) strtol (pos, &pos, 10);
      if (*pos)
        goto invalid;

      goto do_dup2;
    }

  if (pos[0] == '>')
    {
      ++pos;
      oflag = O_WRONLY | O_TRUNC | O_CREAT;
      if (pos[0] == '>')
        {
          oflag |= O_APPEND;
          ++pos;
        }

      goto do_open;
    }

  if (pos[0] == '<')
    {
      ++pos;
      oflag = O_RDONLY;
      goto do_open;
    }

 invalid:
  fprintf (stderr, "testspawn: invalid redirection '%s'\n", redir);
  return -1;

 do_close:
  if (verbose)
    fprintf (stderr, "addclose(%d)\n", srcfd);

#ifdef USE_FORK
  if (close (srcfd) <0)
    {
      fprintf (stderr, "close(%d): %s\n", srcfd, strerror (errno));
      return -1;
    }
#else
  if (posix_spawn_file_actions_addclose (file_actions, srcfd) < 0)
    {
      fprintf (stderr,
               "posix_spawn_file_actions_addclose(%d): %s\n",
               srcfd, strerror (errno));
      return -1;
    }
#endif

  return 0;

 do_dup2:
  if (verbose)
    fprintf (stderr, "adddup2(%d,%d)\n", srcfd, dstfd);

#ifdef USE_FORK
  if (dup2 ((int) srcfd, (int) dstfd) < 0)
    {
      fprintf (stderr, "dup2(%d,%d): %s\n",
               srcfd, dstfd, strerror (errno));
      return -1;
    }
#else
  if (posix_spawn_file_actions_adddup2 (
        file_actions,
        (int) srcfd, (int) dstfd) < 0)
    {
      fprintf (stderr,
               "posix_spawn_file_actions_adddup2(%d,%d): %s\n",
               srcfd, dstfd, strerror (errno));
      return -1;
    }
#endif

  return 0;

 do_open:
  if (verbose)
    fprintf (stderr, "addopen(%d,%s,%d,%04o)\n", srcfd, pos, oflag, mode);

#ifdef USE_FORK
  int opened = open (pos, oflag, mode);
  if (opened < 0)
    {
      fprintf (stderr, "open(%s,%d,%04o): %s\n",
               pos, oflag, mode, strerror (errno));
      return -1;
    }

  if (opened != srcfd)
    {
      dstfd = srcfd;
      srcfd = opened;
      goto do_dup2;
    }
#else
  if (posix_spawn_file_actions_addopen (
        file_actions, srcfd, pos, oflag, mode) < 0)
    {
      fprintf (stderr,
               "posix_spawn_file_actions_addopen(%d,%s,%d,%04o): %s\n",
               srcfd, pos, oflag, mode, strerror (errno));
      return -1;
    }
#endif

  return 0;
}

int
do_work (int argc, char **argv)
{
  char *c;
  pid_t child;
  int status;

#ifdef USE_FORK
  void *file_actions;
  
  child = fork ();
  if (child < 0)
    {
      perror ("fork");
      return 1;
    }

  if (child != 0)
    goto parent;
  
#else
  
  posix_spawn_file_actions_t file_actions;
  posix_spawnattr_t attr;
  short flags;

  if (posix_spawn_file_actions_init (&file_actions) < 0)
    {
      perror ("posix_spawn_file_actions_init");
      return 1;
    }

  if (posix_spawnattr_init (&attr) < 0)
    {
      perror ("posix_spawnattr_init");
      return 1;
    }

  if (posix_spawnattr_getflags (&attr, &flags) < 0)
    {
      perror ("posix_spawnattr_getflags");
      return 1;
    }
#endif

  /* Process directions and options.  Each redirection is in bourne
     shell syntax.  */
  for (++argv; *argv; ++argv)
    {
      if (**argv == '-')
        {
          for (c = *argv + 1; *c; ++c)
            switch (*c)
              {
              case 'v':
                verbose = 1;
                break;
#ifndef USE_FORK
              case 'g':
                flags |= POSIX_SPAWN_SETPGROUP;
                break;
#endif

              default:
                fprintf (stderr, "testspawn: unknown flag '%c'\n", *c);
                usage ();
                return 1;
              }

          continue;
        }

      if (!strchr ("0123456789<>", **argv))
        break;

      if (process_redirection (&file_actions, *argv) < 0)
        return 1;
    }

  if (!argv[0])
    {
      fprintf (stderr, "testspawn: no program given!\n");
      usage ();
      return 1;
    }

#ifdef USE_FORK
  execvp (argv[0], argv);
  perror ("execvp");
  _exit (127);

 parent:
#else
  if (posix_spawnattr_setflags (&attr, flags) < 0)
    {
      perror ("posix_spawnattr_setflags");
      return 1;
    }

  if (posix_spawnp (&child,
                    argv[0] /* path */,
                    &file_actions, &attr,
                    argv, NULL))
    {
      perror ("posix_spawnp");
      return 1;
    }
#endif

  if (wait (&status) < 0)
    {
      perror ("wait");
      return 1;
    }

  if (WIFEXITED (status))
    {
      if (verbose)
        printf ("child exited: %d\n", WEXITSTATUS (status));

      return WEXITSTATUS (status);
    }

  if (verbose)
    printf ("child killed: %d\n", WTERMSIG (status));

  return 127 + WTERMSIG (status);
}

int
main (int argc, char **argv)
{
  int i;
  int ret;
  unsigned iter = atoi (getenv ("ITER") ?: "1");
  size_t junk_size = atoi (getenv ("JUNKBYTES") ?: "0");
  char *junk = malloc (junk_size);
  memset (junk, 42, junk_size);

  for (i = 0; i < iter; ++i)
    {
      ret = do_work (argc, argv);
      if (ret != 0)
        break;
    }
  
  return ret;
}

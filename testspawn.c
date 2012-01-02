/* Hacky non-forking posix_spawn implementation for Cygwin -*- c-file-style: "qgnu" -*- */
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include "cygspawn.h"

int verbose=0;

static void
usage ()
{
  fprintf (stderr, "testspawn SHELL_REDIR* PROGRAM ARGS*: test posix_spawn\n");
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
    fprintf (stderr, "posix_spawn_file_actions_addclose(%d)\n", srcfd);

  if (posix_spawn_file_actions_addclose (file_actions, srcfd) < 0)
    {
      fprintf (stderr,
               "posix_spawn_file_actions_addclose(%d): %s\n",
               srcfd, strerror (errno));
      return -1;
    }

  return 0;

 do_dup2:
  if (verbose)
    fprintf (stderr,
             "posix_spawn_file_actions_adddup2(%d,%d)\n", srcfd, dstfd);

  if (posix_spawn_file_actions_adddup2 (
        file_actions,
        (int) srcfd, (int) dstfd) < 0)
    {
      fprintf (stderr,
               "posix_spawn_file_actions_adddup2(%d,%d): %s\n",
               srcfd, dstfd, strerror (errno));
      return -1;
    }

  return 0;

 do_open:
  if (verbose)
    fprintf (stderr,
             "posix_spawn_file_actions_addopen(%d,%s,%d,%04o)\n",
             srcfd, pos, oflag, mode);

  if (posix_spawn_file_actions_addopen (
        file_actions, srcfd, pos, oflag, mode) < 0)
    {
      fprintf (stderr,
               "posix_spawn_file_actions_addopen(%d,%s,%d,%04o): %s\n",
               srcfd, pos, oflag, mode, strerror (errno));
      return -1;
    }

  return 0;
}

int
main (int argc, char **argv)
{
  pid_t child;
  int status;
  posix_spawn_file_actions_t file_actions;
  posix_spawnattr_t attr;
  ++argv;

  if (posix_spawn_file_actions_init (&file_actions) < 0)
    {
      perror ("posix_spawn_file_actions_init");
      return 127;
    }

  if (posix_spawnattr_init (&attr) < 0)
    {
      perror ("posix_spawnattr_init");
      return 127;
    }

  /* Process directions given on command line.  Each redirection is in
     bourne shell syntax.  */
  for (; *argv; ++argv)
    {
      if (!strcmp (*argv, "-v"))
        {
          verbose = 1;
          continue;
        }

      if (!strchr ("0123456789<>", **argv))
        break;

      if (process_redirection (&file_actions, *argv) < 0)
        return 127;
    }

  if (!argv[0])
    {
      fprintf (stderr, "testspawn: no program given!\n");
      usage ();
      return 127;
    }

  if (posix_spawnp (&child,
                    argv[0] /* path */,
                    &file_actions,
                    NULL /* attributes */,
                    argv,
                    NULL))
    {
      perror ("posix_spawnp");
      return 127;
    }

  if (wait (&status) < 0)
    {
      perror ("wait");
      return 127;
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

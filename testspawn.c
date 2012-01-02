/* Hacky non-forking posix_spawn implementation for Cygwin -*- c-file-style: "qgnu" -*- */
#include <stdio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include "cygspawn.h"

int
main (int argc, char** argv)
{
  pid_t child;
  int status;
  posix_spawn_file_actions_t file_actions;
  posix_spawnattr_t attr;

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

#if 0
  if (posix_spawn_file_actions_addopen (
        &file_actions,
        1, "foo.txt", O_RDWR | O_CREAT, 0666) < 0)
    {
      perror ("posix_spawn_file_actions_addopen");
      return 1;
    }
#endif

  if (posix_spawn_file_actions_adddup2 (
        &file_actions, 1, 1) < 0)
    {
      perror ("posix_spawn_file_actions_addclose");
      return 1;
    }
  
  ++argv;
  if (posix_spawnp (&child,
                    argv[0] /* path */,
                    &file_actions,
                    NULL /* attributes */,
                    argv,
                    NULL))
    {
      perror ("posix_spawnp");
      return 1;
    }

  wait (&status);
  if (WIFEXITED (status))
    printf ("child exited: %d\n", WEXITSTATUS (status));
  else
    printf ("child killed: %d\n", WTERMSIG (status));
  return 0;
}

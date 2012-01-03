#ifndef CYGSPAWN_H
#define CYGSPAWN_H
#include <unistd.h>
#include <signal.h>
#include <sched.h>

#ifdef __cplusplus
extern "C" {
#endif

/* **** spawn ****  */

typedef struct cygwin_spawn_ops *posix_spawn_file_actions_t;
typedef struct cygwin_spawn_info *posix_spawnattr_t;

int posix_spawn (
  pid_t*restrict pid,
  const char *restrict path,
  const posix_spawn_file_actions_t *file_actions,
  const posix_spawnattr_t *restrict attrp,
  char *const restrict argv[restrict],
  char *const restrict envp[restrict]);

int posix_spawnp (
  pid_t*restrict pid,
  const char *restrict path,
  const posix_spawn_file_actions_t *file_actions,
  const posix_spawnattr_t *restrict attrp,
  char *const restrict argv[restrict],
  char *const restrict envp[restrict]);

/* **** file_actions **** */

int posix_spawn_file_actions_init (
  posix_spawn_file_actions_t *file_actions);

int posix_spawn_file_actions_destroy (
  posix_spawn_file_actions_t *file_actions);

int posix_spawn_file_actions_addclose (
  posix_spawn_file_actions_t *file_actions,
  int filedes);

int posix_spawn_file_actions_adddup2 (
  posix_spawn_file_actions_t *file_actions,
  int filedes,
  int newdes);

int posix_spawn_file_actions_addopen (
  posix_spawn_file_actions_t *file_actions,
  int filedes,
  const char *restrict path,
  int oflag,
  mode_t mode);

/* *** spawnattr **** */

#define POSIX_SPAWN_RESETIDS          (1<<0)
#define POSIX_SPAWN_SETPGROUP         (1<<1)
#define POSIX_SPAWN_SETSCHEDPARAM     (1<<2)
#define POSIX_SPAWN_SETSCHEDULER      (1<<3)
#define POSIX_SPAWN_SETSIGDEF         (1<<4)
#define POSIX_SPAWN_SETSIGMASK        (1<<5)
#define CYGWIN_SPAWN_VALID_FLAGS      ((1<<6) - 1)

int posix_spawnattr_init (
  posix_spawnattr_t *attr);

int posix_spawnattr_destroy (
  posix_spawnattr_t *attr);

int posix_spawnattr_getflags (
  const posix_spawnattr_t *restrict attr,
  short *restrict flags);

int posix_spawnattr_setflags (
  posix_spawnattr_t *attr,
  short flags);

int posix_spawnattr_getpgroup (
  const posix_spawnattr_t *restrict attr,
  pid_t *restrict pgroup);

int posix_spawnattr_setpgroup (
  posix_spawnattr_t *attr,
  pid_t pgroup);

int posix_spawnattr_getsigdefault (
  const posix_spawnattr_t *restrict attr,
  sigset_t *restrict sigdefault);

int posix_spawnattr_setsigdefault (
  posix_spawnattr_t *restrict attr,
  const sigset_t *restrict sigdefault);

int posix_spawnattr_getschedparam (
  const posix_spawnattr_t *restrict attr,
  struct sched_param *restrict schedparam);

int posix_spawnattr_setschedparam (
  posix_spawnattr_t *restrict attr,
  const struct sched_param *restrict schedparam);

int posix_spawnattr_getschedpolicy (
  const posix_spawnattr_t *restrict attr,
  int *restrict schedpolicy);

int posix_spawnattr_setschedpolicy (
  posix_spawnattr_t *attr,
  int schedpolicy);

int posix_spawnattr_getsigmask (
  const posix_spawnattr_t *restrict attr,
  sigset_t *restrict sigmask);

int posix_spawnattr_setsigmask (
  posix_spawnattr_t *restrict attr,
  const sigset_t *restrict sigmask);

#ifdef __cplusplus
}
#endif

#endif /* CYGSPAWN_H */

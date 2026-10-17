// Wombat: libopenconnect is compiled with fork, the exec family, posix_spawn and system renamed
// to these stubs (scripts/build-openconnect.sh passes -Dfork=wombat_noexec_fork and so on), so
// nothing in the library can start a process: not the vpnc-script, a CSD/HostScan wrapper, the
// NTLM helper or an external browser. A server must never make the client run code (CLAUDE.md
// constraint 2). The build checks that the archive has no reference to the real functions left.

#include <errno.h>
#include <spawn.h>
#include <stdarg.h>
#include <sys/types.h>

pid_t wombat_noexec_fork(void) { errno = ENOSYS; return -1; }

int wombat_noexec_execv(const char *path, char *const argv[]) { (void)path; (void)argv; errno = ENOSYS; return -1; }
int wombat_noexec_execvp(const char *file, char *const argv[]) { (void)file; (void)argv; errno = ENOSYS; return -1; }
int wombat_noexec_execve(const char *path, char *const argv[], char *const envp[]) { (void)path; (void)argv; (void)envp; errno = ENOSYS; return -1; }
int wombat_noexec_execl(const char *path, const char *arg, ...) { (void)path; (void)arg; errno = ENOSYS; return -1; }
int wombat_noexec_execlp(const char *file, const char *arg, ...) { (void)file; (void)arg; errno = ENOSYS; return -1; }

int wombat_noexec_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
                              const posix_spawnattr_t *attr, char *const argv[], char *const envp[]) {
    (void)pid; (void)path; (void)actions; (void)attr; (void)argv; (void)envp;
    return ENOSYS;
}
int wombat_noexec_posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *actions,
                               const posix_spawnattr_t *attr, char *const argv[], char *const envp[]) {
    (void)pid; (void)file; (void)actions; (void)attr; (void)argv; (void)envp;
    return ENOSYS;
}

int wombat_noexec_system(const char *command) { (void)command; errno = ENOSYS; return -1; }

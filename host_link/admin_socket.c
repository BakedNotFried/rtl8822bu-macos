#include "admin_socket.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int host_link_connect_session(const char *path, const char *expected_uid) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(expected_uid, &end, 10);
    if (errno || !*expected_uid || *end || !value || value != (uid_t)value) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (*path != '/' || strlcpy(address.sun_path, path, sizeof(address.sun_path)) >= sizeof(address.sun_path)) return -1;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    uid_t peer;
    gid_t group;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) ||
        getpeereid(fd, &peer, &group) || peer != (uid_t)value ||
        dup2(fd, STDIN_FILENO) < 0 || dup2(fd, STDOUT_FILENO) < 0) {
        close(fd);
        return -1;
    }
    if (fd > STDOUT_FILENO) close(fd);
    return 0;
}

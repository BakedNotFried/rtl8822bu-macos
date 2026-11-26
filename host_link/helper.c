#include "admin_socket.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <net/bpf.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

enum { max_frame = 1514, capture_size = 32768 };
struct endpoint { char name[IFNAMSIZ]; unsigned index; };
static volatile sig_atomic_t stopping;

static void interrupted(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}

static bool parse_mac(const char *arg, uint8_t mac[6])
{
    if (strlen(arg) != 17) return false;
    for (size_t i = 0; i < 6; i++) {
        const char *p = arg + 3*i;
        if (!isxdigit((unsigned char)p[0]) || !isxdigit((unsigned char)p[1]) ||
            (i != 5 && p[2] != ':')) return false;
        char hex[3] = {p[0],p[1],0};
        mac[i] = (uint8_t)strtoul(hex,NULL,16);
    }
    static const uint8_t zero[6];
    return !(mac[0] & 1) && memcmp(mac,zero,6) != 0;
}

static int clone_endpoint(int ctl, struct endpoint *ep)
{
    struct ifreq ifr = {0};
    strlcpy(ifr.ifr_name,"feth",IFNAMSIZ);
    if (ioctl(ctl,SIOCIFCREATE2,&ifr) == -1) return -1;
    /* The kernel assigns the unit. No command-line interface names. */
    strlcpy(ep->name,ifr.ifr_name,IFNAMSIZ);
    const char *unit = ep->name + 4;
    if (strncmp(ep->name,"feth",4) || !*unit || unit[strspn(unit,"0123456789")]) {
        errno = EPROTO;
        return -1;
    }
    ep->index = if_nametoindex(ep->name);
    return ep->index ? 0 : -1;
}

static bool owned(const struct endpoint *ep)
{
    return ep->index && if_nametoindex(ep->name) == ep->index;
}

static int destroy_endpoint(int ctl, const struct endpoint *ep)
{
    if (!owned(ep)) return 0;
    struct ifreq ifr = {0};
    strlcpy(ifr.ifr_name,ep->name,IFNAMSIZ);
    return ioctl(ctl,SIOCIFDESTROY,&ifr);
}

/* Use native tools only for the feth peer command and IPConfiguration agent.
 * Subprocesses receive fixed argument vectors, a minimal environment, and no
 * client connection. Send all their output to stderr, outside frame IPC. */
static int command(const char *exe, char *const argv[])
{
    posix_spawn_file_actions_t actions;
    int error = posix_spawn_file_actions_init(&actions);
    if (error) { errno = error; return -1; }
    error = posix_spawn_file_actions_addopen(&actions,0,"/dev/null",O_RDONLY,0);
    if (!error) error = posix_spawn_file_actions_adddup2(&actions,2,1);
    char *const env[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin","LC_ALL=C",NULL};
    pid_t child = -1;
    if (!error) error = posix_spawn(&child,exe,&actions,NULL,argv,env);
    posix_spawn_file_actions_destroy(&actions);
    if (error) { errno = error; return -1; }
    int status;
    while (waitpid(child,&status,0) < 0) if (errno != EINTR) return -1;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;
    errno = EIO;
    return -1;
}

static int set_up(int ctl, const char *name, const uint8_t *mac)
{
    struct ifreq req = {0};
    strlcpy(req.ifr_name,name,IFNAMSIZ);
    if (mac) {
        req.ifr_addr.sa_family = AF_LINK;
        req.ifr_addr.sa_len = 6;
        memcpy(req.ifr_addr.sa_data,mac,6);
        if (ioctl(ctl,SIOCSIFLLADDR,&req) < 0) return -1;
    }
    if (ioctl(ctl,SIOCGIFFLAGS,&req) < 0) return -1;
    req.ifr_flags |= IFF_UP;
    return ioctl(ctl,SIOCSIFFLAGS,&req);
}

static int open_peer_bpf(const struct endpoint *peer, unsigned *buffer_size)
{
    if (!owned(peer)) { errno = ENXIO; return -1; }
    int fd = -1;
    for (int i = 0; i < 256; i++) {
        char device[32];
        snprintf(device,sizeof(device),"/dev/bpf%d",i);
        fd = open(device,O_RDWR | O_CLOEXEC | O_NONBLOCK);
        if (fd >= 0) break;
        if (errno != EBUSY) return -1;
    }
    if (fd < 0) return -1;
    struct ifreq req = {0};
    strlcpy(req.ifr_name,peer->name,IFNAMSIZ);
    unsigned one = 1, zero = 0, dlt = 0, size = capture_size;
    struct bpf_insn filter[] = {
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS,12),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,0x0800,1,0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,0x0806,0,1),
        BPF_STMT(BPF_RET | BPF_K,max_frame),
        BPF_STMT(BPF_RET | BPF_K,0)
    };
    struct bpf_program program = {
        .bf_len = sizeof(filter)/sizeof(filter[0]), .bf_insns = filter
    };
    if (ioctl(fd,BIOCSBLEN,&size) == 0 && ioctl(fd,BIOCSETIF,&req) == 0 &&
        ioctl(fd,BIOCGDLT,&dlt) == 0 && dlt == DLT_EN10MB &&
        ioctl(fd,BIOCSSEESENT,&zero) == 0 && ioctl(fd,BIOCSHDRCMPLT,&one) == 0 &&
        ioctl(fd,BIOCIMMEDIATE,&one) == 0 && ioctl(fd,BIOCSETF,&program) == 0 &&
        ioctl(fd,BIOCGBLEN,&size) == 0 && size <= capture_size && size > max_frame) {
        *buffer_size = size;
        return fd;
    }
    int saved = errno;
    close(fd);
    errno = saved;
    return -1;
}

static bool allowed(const uint8_t *f, size_t n, const uint8_t mac[6], bool from_host)
{
    if (n < 14 || n > max_frame) return false;
    if (from_host ? memcmp(f+6,mac,6) != 0 : !(f[0] & 1) && memcmp(f,mac,6) != 0)
        return false;
    if ((f[6] & 1) || !memcmp(f+6,(uint8_t[6]){0},6)) return false;
    if (f[12] != 8) return false;
    if (f[13] == 6) {
        return n >= 42 && f[14] == 0 && f[15] == 1 && f[16] == 8 && f[17] == 0 &&
               f[18] == 6 && f[19] == 4 && f[20] == 0 && (f[21] == 1 || f[21] == 2);
    }
    if (f[13] != 0 || n < 34 || (f[14] >> 4) != 4) return false;
    unsigned header = (f[14] & 15) * 4, total = (unsigned)f[16] << 8 | f[17];
    return header >= 20 && total >= header && total <= n-14;
}

/* Socket operations are timeout-bounded even if one endpoint stops halfway
 * through a length prefix. EOF before a new message is a normal shutdown. */
static int receive_exact(uint8_t *data, size_t len)
{
    size_t pos = 0;
    while (pos < len && !stopping) {
        ssize_t nr = read(STDIN_FILENO,data+pos,len-pos);
        if (!nr) return pos ? -1 : 0;
        if (nr < 0) {
            if (errno == EINTR) continue;
            if (!pos && (errno == ECONNRESET || errno == EPIPE)) return 0;
            return -1;
        }
        pos += (size_t)nr;
    }
    return pos == len ? 1 : -1;
}

enum output_result { output_error = -1, output_ok, session_closed };

static enum output_result message(const uint8_t *data, size_t length)
{
    uint8_t framed[2 + max_frame];
    if (length == 0 || length > max_frame) return output_error;
    framed[0] = (uint8_t)(length >> 8);
    framed[1] = (uint8_t)length;
    memcpy(framed + 2,data,length);
    size_t amount = length + 2, pos = 0;
    while (pos < amount && !stopping) {
        ssize_t n = write(STDOUT_FILENO,framed+pos,amount-pos);
        if (n == -1 && errno == EINTR) continue;
        if (n < 0 && (errno == EPIPE || errno == ECONNRESET)) return session_closed;
        if (n <= 0) return output_error;
        pos += (size_t)n;
    }
    return pos == amount ? output_ok : session_closed;
}

static enum output_result host_output(int bpf, unsigned cap, const uint8_t mac[6])
{
    uint8_t buffer[capture_size];
    ssize_t nr = read(bpf,buffer,cap);
    if (nr < 0) return errno == EAGAIN || errno == EINTR ? 0 : -1;
    size_t size = (size_t)nr;
    const size_t min_header = offsetof(struct bpf_hdr,bh_hdrlen) + sizeof(uint16_t);
    for (size_t pos = 0; pos < size;) {
        struct bpf_hdr h = {0};
        size_t left = size - pos;
        if (left < min_header) return -1;
        memcpy(&h,buffer + pos,min_header);
        if (h.bh_hdrlen < min_header || h.bh_hdrlen > left ||
            h.bh_caplen > left - h.bh_hdrlen) return -1;
        const uint8_t *frame = buffer + pos + h.bh_hdrlen;
        if (h.bh_caplen == h.bh_datalen && allowed(frame,h.bh_caplen,mac,true)) {
            enum output_result status = message(frame,h.bh_caplen);
            if (status != output_ok) return status;
        }
        size_t span = h.bh_hdrlen + h.bh_caplen;
        if (span == left) break;
        span = BPF_WORDALIGN(span);
        if (span > left) return -1;
        pos += span;
    }
    return 0;
}

static int pump(int bpf, unsigned size, const uint8_t mac[6])
{
    struct pollfd fds[] = {{0,POLLIN,0},{bpf,POLLIN,0}};
    while (!stopping) {
        if (poll(fds,2,500) < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if ((fds[0].revents & POLLNVAL) || (fds[1].revents & (POLLNVAL|POLLERR|POLLHUP)))
            return -1;
        if (fds[0].revents & (POLLIN|POLLHUP|POLLERR)) {
            uint8_t prefix[2], frame[max_frame];
            int received = receive_exact(prefix,sizeof(prefix));
            if (received <= 0) return received;
            size_t n = (size_t)prefix[0] << 8 | prefix[1];
            if (n < 14 || n > sizeof(frame) || receive_exact(frame,n) != 1) return -1;
            if (allowed(frame,n,mac,false) && write(bpf,frame,n) != (ssize_t)n) return -1;
        }
        if (fds[1].revents & POLLIN) {
            enum output_result status = host_output(bpf,size,mac);
            if (status != output_ok) return status == session_closed ? 0 : -1;
        }
    }
    return 0;
}

static bool session_peer(uid_t *uid, gid_t *gid)
{
    struct sockaddr_un local;
    socklen_t len = sizeof(local);
    int type = 0;
    socklen_t type_len = sizeof(type);
    return getsockname(0,(struct sockaddr *)&local,&len) == 0 && local.sun_family == AF_UNIX &&
           getsockopt(0,SOL_SOCKET,SO_TYPE,&type,&type_len) == 0 && type == SOCK_STREAM &&
           getpeereid(0,uid,gid) == 0 && *uid != 0;
}

int main(int argc, char **argv)
{
    if (geteuid() != 0) {
        fprintf(stderr,"Temporary host link setup requires administrator approval.\n");
        return 1;
    }
    if (argc == 5 && !strcmp(argv[2],"--session")) {
        if (host_link_connect_session(argv[3],argv[4]) != 0) return 1;
        argc = 2;
    }
    uint8_t mac[6];
    uid_t uid;
    gid_t gid;
    if (argc != 2 || !parse_mac(argv[1],mac) || !session_peer(&uid,&gid)) {
        fprintf(stderr,"Expected station MAC and private unprivileged station connection.\n");
        return 2;
    }
    struct sigaction action = {.sa_handler = interrupted};
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT,&action,NULL); sigaction(SIGTERM,&action,NULL); sigaction(SIGHUP,&action,NULL);
    signal(SIGPIPE,SIG_IGN);
    int ctl = socket(AF_INET,SOCK_DGRAM,0);
    if (ctl < 0 || fcntl(ctl,F_SETFD,FD_CLOEXEC) < 0) { perror("control socket"); return 1; }
    struct endpoint host = {0}, peer = {0};
    bool dhcp = false;
    int bpf = -1, result = 1;
    unsigned size = 0;
    if (clone_endpoint(ctl,&host) || clone_endpoint(ctl,&peer)) { perror("create feth"); goto done; }
    fprintf(stderr,"Temporary host interface %s and peer %s\n",host.name,peer.name);
    char *peer_args[] = {"ifconfig",host.name,"peer",peer.name,NULL};
    if (command("/sbin/ifconfig",peer_args) || set_up(ctl,host.name,mac) ||
        set_up(ctl,peer.name,NULL)) { perror("configure feth pair"); goto done; }
    bpf = open_peer_bpf(&peer,&size);
    if (bpf < 0) { perror("open temporary peer BPF"); goto done; }
    char *start[] = {"ipconfig","set",host.name,"DHCP",NULL};
    if (stopping || command("/usr/sbin/ipconfig",start)) { perror("start IPv4 DHCP"); goto done; }
    dhcp = true;
    pid_t child = fork();
    if (child < 0) { perror("fork frame worker"); goto done; }
    if (!child) {
        close(ctl);
        if (setgroups(1,&gid) || setgid(gid) || setuid(uid)) { perror("drop privileges"); _exit(1); }
        struct timeval timeout = {.tv_sec=3,.tv_usec=0};
        if (setsockopt(0,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) ||
            setsockopt(1,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))) _exit(1);
        enum output_result ready = message((const uint8_t *)host.name,strlen(host.name));
        if (ready != output_ok) _exit(ready == session_closed ? 0 : 1);
        int status = pump(bpf,size,mac);
        if (status < 0) fprintf(stderr,"Temporary frame transport closed with an error.\n");
        _exit(status < 0 ? 1 : 0);
    }
    close(bpf);
    bpf = -1;
    close(0);
    close(1);
    int child_status;
    for (;;) {
        if (stopping) kill(child,SIGTERM);
        if (waitpid(child,&child_status,0) >= 0) {
            result = WIFEXITED(child_status) ? WEXITSTATUS(child_status) : 1;
            break;
        }
        if (errno != EINTR) break;
    }
done:
    if (bpf >= 0) close(bpf);
    if (dhcp && owned(&host)) {
        char *stop[] = {"ipconfig","set",host.name,"NONE",NULL};
        if (command("/usr/sbin/ipconfig",stop)) { perror("stop temporary DHCP"); result=1; }
    }
    if (destroy_endpoint(ctl,&peer)) { perror("destroy temporary peer"); result=1; }
    if (destroy_endpoint(ctl,&host)) { perror("destroy temporary host interface"); result=1; }
    close(ctl);
    return result;
}

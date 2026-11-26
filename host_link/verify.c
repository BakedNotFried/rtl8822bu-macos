// Read the temporary host interface's DHCP state. Optionally try normal HTTPS.
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>

static bool feth_name(const char *name)
{
    size_t n = strlen(name);
    return n > 4 && n < IFNAMSIZ && !strncmp(name, "feth", 4) &&
           strspn(name + 4, "0123456789") == n - 4;
}

static bool read_ack(FILE *stream, struct in_addr *lease)
{
    char line[1024], text[INET_ADDRSTRLEN];
    bool ack = false, valid = false;
    while (fgets(line, sizeof(line), stream)) {
        char *field = line + strspn(line, " \t");
        const char *prefix = "dhcp_message_type (uint8): ACK";
        size_t len = strlen(prefix);
        if (!strncmp(field, prefix, len) && strchr(" \t\r\n", field[len])) ack = true;
        if (sscanf(field, "yiaddr = %15s", text) == 1)
            valid = inet_pton(AF_INET, text, lease) == 1 && lease->s_addr != INADDR_ANY;
    }
    return !ferror(stream) && ack && valid;
}

static bool success(int status)
{
    return status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* Interface names come exclusively from the validated feth[0-9]+ argument. */
static bool get_lease(const char *name, struct in_addr *lease)
{
    char command[64];
    snprintf(command, sizeof(command), "/usr/sbin/ipconfig getpacket %s", name);
    FILE *stream = popen(command, "r");
    if (!stream) return false;
    bool accepted = read_ack(stream, lease);
    return success(pclose(stream)) && accepted;
}

static bool uniquely_assigned(const struct ifaddrs *list, const char *interface, struct in_addr ip)
{
    bool found = false;
    for (const struct ifaddrs *i = list; i; i = i->ifa_next) {
        if (!i->ifa_addr || !(i->ifa_flags & IFF_UP) || i->ifa_addr->sa_family != AF_INET) continue;
        const struct sockaddr_in *addr = (const struct sockaddr_in *)i->ifa_addr;
        if (addr->sin_addr.s_addr != ip.s_addr) continue;
        if (strcmp(i->ifa_name, interface)) return false;
        found = true;
    }
    return found;
}

static bool same_source(const char *local, struct in_addr lease)
{
    struct in_addr ip;
    return inet_pton(AF_INET, local, &ip) == 1 && ip.s_addr == lease.s_addr &&
           (ntohl(ip.s_addr) >> 24) != 127;
}

static int normal_https(const char *name, unsigned index, struct in_addr lease)
{
    // Use curl's ordinary proxy, resolver and route settings. Verification is mandatory.
    // proxy_used was added in curl 8.7. Older curl can still check HTTPS reachability.
    const char *command =
        "/usr/bin/curl -q --silent --show-error --head --output /dev/null --no-location "
        "--no-insecure --connect-timeout 6 --max-time 15 "
        "--write-out '%{http_code} %{ssl_verify_result} %{local_ip} %{proxy_used}\\n' "
        "https://github.com/";
    FILE *stream = popen(command, "r");
    if (!stream) { perror("start curl"); return 1; }
    char line[256], local[INET6_ADDRSTRLEN] = {0};
    int code = 0, tls = -1, proxy = -1, fields = 0;
    while (fgets(line, sizeof(line), stream))
        fields = sscanf(line, "%d %d %45s %d", &code, &tls, local, &proxy);
    if (!success(pclose(stream)) || fields < 3 || code != 200 || tls != 0) {
        fprintf(stderr, "Ordinary HTTPS to github.com was not verified (HTTP %d).\n", code);
        return 1;
    }
    printf("Ordinary HTTPS to github.com returned HTTP %d with verified TLS. Local address %s.\n", code, local);
    struct ifaddrs *list = NULL;
    bool matches = fields == 4 && proxy == 0 && same_source(local, lease) &&
                   if_nametoindex(name) == index && getifaddrs(&list) == 0 &&
                   uniquely_assigned(list, name, lease);
    if (list) freeifaddrs(list);
    if (!matches) {
        printf("The dongle path is unproven for this request%s.\n",
               proxy == 1 ? " (curl used a proxy)" : fields < 4 ? " (curl could not report proxy use)" : "");
        return 3;
    }
    printf("The connection used the IPv4 source address assigned only to %s.\n", name);
    return 0;
}

int main(int argc, char **argv)
{
    if ((argc != 2 && argc != 3) || !feth_name(argv[1]) || (argc == 3 && strcmp(argv[2], "--https"))) {
        fprintf(stderr, "Usage: host-link-verify fethN [--https]\n");
        return 2;
    }
    unsigned index = if_nametoindex(argv[1]);
    if (!index) { fprintf(stderr, "Interface %s is absent.\n", argv[1]); return 1; }
    struct in_addr lease;
    char address[INET_ADDRSTRLEN];
    if (!get_lease(argv[1], &lease) || if_nametoindex(argv[1]) != index) {
        fprintf(stderr, "No native DHCP ACK on %s.\n", argv[1]);
        return 1;
    }
    printf("Native DHCP ACK on %s (index %u), IPv4 %s.\n", argv[1], index,
           inet_ntop(AF_INET, &lease, address, sizeof(address)));
    return argc == 3 ? normal_https(argv[1], index, lease) : 0;
}

#define main host_link_verify_main
#include "verify.c"
#undef main
#include <assert.h>

static bool ack_fixture(char *fixture, struct in_addr *address)
{
    FILE *input = fmemopen(fixture, strlen(fixture), "r");
    assert(input);
    bool ok = read_ack(input, address);
    fclose(input);
    return ok;
}

int main(void)
{
    struct in_addr lease = {0};
    char ack[] = "yiaddr = 192.0.2.55\noptions:\ndhcp_message_type (uint8): ACK 0x5\n";
    char offer[] = "yiaddr = 192.0.2.55\ndhcp_message_type (uint8): OFFER 0x2\n";
    char missing[] = "yiaddr = 0.0.0.0\ndhcp_message_type (uint8): ACK 0x5\n";
    assert(!ack_fixture(offer, &lease) && !ack_fixture(missing, &lease));
    assert(ack_fixture(ack, &lease) && lease.s_addr == inet_addr("192.0.2.55"));
    assert(feth_name("feth123") && !feth_name("en0") && !feth_name("feth0;cmd"));
    assert(!same_source("127.0.0.1", lease) && !same_source("::1", lease));
    assert(!same_source("198.51.100.3", lease) && same_source("192.0.2.55", lease));
    struct sockaddr_in ip = {.sin_family = AF_INET, .sin_addr = lease};
    struct ifaddrs other = {.ifa_name = "en0", .ifa_flags = IFF_UP, .ifa_addr = (struct sockaddr *)&ip};
    struct ifaddrs host = {.ifa_name = "feth3", .ifa_flags = IFF_UP, .ifa_addr = (struct sockaddr *)&ip};
    assert(uniquely_assigned(&host, "feth3", lease));
    host.ifa_next = &other;
    assert(!uniquely_assigned(&host, "feth3", lease));
    puts("Offline DHCP and connection-source checks passed.");
}

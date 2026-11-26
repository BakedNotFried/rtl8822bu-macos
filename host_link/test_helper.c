/* Offline tests. A pipe stands in for the already-bound temporary peer BPF
 * descriptor. This test never opens a network interface or /dev/bpf. */
#define main temporary_interface_main
#include "helper.c"
#undef main
#include <assert.h>

static void check_host_record(const uint8_t mac[6], const uint8_t arp[42])
{
    uint8_t bytes[128] = {0};
    struct bpf_hdr h = {.bh_caplen=42, .bh_datalen=42, .bh_hdrlen=sizeof(h)};
    memcpy(bytes,&h,sizeof(h));
    memcpy(bytes+sizeof(h),arp,42);
    int input[2], session[2];
    assert(pipe(input) == 0 && socketpair(AF_UNIX,SOCK_STREAM,0,session) == 0);
    int saved = dup(1);
    assert(saved >= 0 && dup2(session[0],1) >= 0);
    assert(write(input[1],bytes,sizeof(h)+42) == (ssize_t)sizeof(h)+42);
    assert(host_output(input[0],sizeof(bytes),mac) == 0);
    uint8_t back[44];
    assert(recv(session[1],back,sizeof(back),MSG_WAITALL) == sizeof(back));
    assert(back[0] == 0 && back[1] == 42 && !memcmp(back+2,arp,42));
    close(session[1]); /* Station exited while a frame was ready. */
    assert(write(input[1],bytes,sizeof(h)+42) == (ssize_t)sizeof(h)+42);
    assert(host_output(input[0],sizeof(bytes),mac) == session_closed);
    h.bh_hdrlen = sizeof(bytes)+1;
    memcpy(bytes,&h,sizeof(h));
    assert(write(input[1],bytes,sizeof(bytes)) == sizeof(bytes));
    assert(host_output(input[0],sizeof(bytes),mac) == output_error);
    assert(dup2(saved,1) >= 0);
    close(saved);
    close(session[0]);
    close(input[0]); close(input[1]);
}

static int simulate_close(const uint8_t *bytes, size_t length, const uint8_t mac[6])
{
    int session[2], bpf[2];
    assert(socketpair(AF_UNIX,SOCK_STREAM,0,session) == 0 && pipe(bpf) == 0);
    int saved = dup(0);
    assert(saved >= 0 && dup2(session[0],0) >= 0);
    if (length) assert(write(session[1],bytes,length) == (ssize_t)length);
    close(session[1]);
    int status = pump(bpf[0],128,mac);
    assert(dup2(saved,0) >= 0);
    close(saved); close(session[0]); close(bpf[0]); close(bpf[1]);
    return status;
}

int main(void)
{
    signal(SIGPIPE,SIG_IGN);
    uint8_t mac[6];
    assert(!parse_mac("00000000000000000",mac));
    assert(!parse_mac("01:00:00:00:00:00",mac));
    assert(!parse_mac("00:00:00:00:00:00",mac));
    assert(parse_mac("02:24:11:22:33:44",mac));
    uint8_t arp[42] = {0xff,0xff,0xff,0xff,0xff,0xff, 2,0x24,0x11,0x22,0x33,0x44,
                       8,6, 0,1,8,0,6,4,0,1};
    assert(allowed(arp,sizeof(arp),mac,true) && allowed(arp,sizeof(arp),mac,false));
    assert(!allowed(arp,sizeof(arp)-1,mac,true) && !allowed(arp,sizeof(arp)+1600,mac,false));
    check_host_record(mac,arp);
    uint8_t record[44] = {0,42};
    memcpy(record + 2,arp,42);
    assert(simulate_close(NULL,0,mac) == 0);
    assert(simulate_close(record,1,mac) == -1); /* Incomplete length. */
    assert(simulate_close(record,2,mac) == -1); /* Missing payload. */
    assert(simulate_close(record,12,mac) == -1);
    /* A closed BPF write path must remain an error despite station closure. */
    assert(simulate_close(record,sizeof(record),mac) == -1);
    arp[6] = 4;
    assert(!allowed(arp,sizeof(arp),mac,true));
    arp[0] = 4;
    assert(!allowed(arp,sizeof(arp),mac,false));
    memcpy(arp,mac,6);
    assert(allowed(arp,sizeof(arp),mac,false));
    arp[13] = 0; arp[14] = 0x45; arp[16] = 0; arp[17] = 28;
    assert(allowed(arp,sizeof(arp),mac,false));
    arp[17] = 29;
    assert(!allowed(arp,sizeof(arp),mac,false));
    arp[12] = 0x86; arp[13] = 0xdd;
    assert(!allowed(arp,sizeof(arp),mac,false));
    puts("Temporary host link framing and direction checks passed");
}

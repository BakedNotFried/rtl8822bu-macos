#include <CommonCrypto/CommonKeyDerivation.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

size_t calnet_secret(bool, const uint8_t *, size_t, uint8_t [65]);

// stdout is a private pipe to the station. Refuse accidental Terminal output.
int main(int argc, char **argv) {
    struct stat output;
    if (argc != 3 || getuid() == 0 || fstat(STDOUT_FILENO, &output) || !S_ISFIFO(output.st_mode)) return 2;
    bool saved = !strcmp(argv[1], "--connect-saved");
    if (!saved && strcmp(argv[1], "--connect")) return 2;
    size_t len = strlen(argv[2]);
    if (!len || len > 32) return 2;
    uint8_t secret[65] = {0}, key[32] = {0};
    size_t n = calnet_secret(saved, (const uint8_t *)argv[2], len, secret);
    int rc = 1;
    if (n == 64) {
        for (size_t i=0; i<n; i++) if (!isxdigit(secret[i])) goto done;
        rc = fwrite(secret, 1, 64, stdout) == 64 ? 0 : 1;
    } else if (n >= 8 && n <= 63 &&
               CCKeyDerivationPBKDF(kCCPBKDF2, (const char *)secret, n,
                   (const uint8_t *)argv[2], len, kCCPRFHmacAlgSHA1, 4096, key, sizeof(key)) == 0) {
        for (size_t i=0; i<sizeof(key); i++) if (printf("%02x", key[i]) != 2) goto done;
        rc = 0;
    }
done:
    memset_s(secret, sizeof(secret), 0, sizeof(secret));
    memset_s(key, sizeof(key), 0, sizeof(key));
    return rc || fflush(stdout);
}

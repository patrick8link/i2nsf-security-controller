#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void error(char *fmt, ...)
{
    va_list ap;

    fprintf(stdout, "ERROR=");
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fprintf(stdout, "\n");

    exit(1);
}

static int write_key_file(FILE *fp)
{
    char buf[4069];
    size_t nread;

    do {
        nread = fread(buf, 1, sizeof(buf), fp);
        fwrite(buf, 1, nread, stdout);
    } while (nread == sizeof(buf));

    if (feof(fp)) {
        return 0;
    }
    fprintf(stdout, "\nERROR=key file read error: %s\n", strerror(errno));
    return 1;
}

int main(int argc, char **argv)
{
    const char *key_file = getenv("CONFD_EXTERNAL_KEYS_ARGUMENT");
    if (! key_file) {
        error("CONFD_EXTERNAL_KEYS_ARGUMENT environment not set");
    } else if (! strlen(key_file)) {
        error("CONFD_EXTERNAL_KEYS_ARGUMENT is empty");
    }

    int ret = 0;
    FILE *fp = fopen(key_file, "r");
    if (fp) {
        ret = write_key_file(fp);
        fclose(fp);
    } else {
        error("unable to open %s: %s", key_file, strerror(errno));
    }

    return ret;
}

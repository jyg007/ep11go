#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* Include the vendor header */
#include <ep11.h>
#include <string.h>
#include <ep11adm.h>

/* Hex dump helper */
static void hexdump(const unsigned char *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);

    printf("\n");
}

int main(int argc, char *argv[])
{
    FILE *fp;
    long certlen;
    unsigned char *certbuf = NULL;

    struct KPH kph;
    struct STATESAVE state;

    unsigned char asn[65536];
    long rc;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s cert.der\n", argv[0]);
        return 1;
    }

    /* Read DER certificate */
    fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    certlen = ftell(fp);
    rewind(fp);

    certbuf = malloc(certlen);
    if (!certbuf) {
        fclose(fp);
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    if (fread(certbuf, 1, certlen, fp) != (size_t)certlen) {
        fclose(fp);
        free(certbuf);
        fprintf(stderr, "fread failed\n");
        return 1;
    }

    fclose(fp);

    memset(&kph, 0, sizeof(kph));
    memset(&state, 0, sizeof(state));
    memset(asn, 0, sizeof(asn));

    /*
     * Adjust these fields according to your KPH definition.
     * Typical examples:
     */
    kph.cert = certbuf;
    kph.clen = (size_t)certlen;

    /*
     * exportstate = 0 => ExportWK request
     */
    rc = xcpa_fill_export_req(
            asn,
            sizeof(asn),
            &kph,
            1,          /* one KPH certificate */
            0,          /* exportstate = false */
            NULL,       /* no STATESAVE needed */
            0           /* no restrictions */
         );

    if (rc < 0) {
        fprintf(stderr, "xcpa_fill_export_req failed rc=%ld\n", rc);
        free(certbuf);
        return 1;
    }

    printf("Generated ASN.1 request (%ld bytes):\n\n", rc);
    hexdump(asn, rc);

    free(certbuf);
    return 0;
}

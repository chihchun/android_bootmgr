/*
 * Copyright 2013 Canonical Ltd.
 * Authros
 *   Rex Tsai <rex.tsai@canonical.com>
 *
 * Copyright 2011 Jens Andersen (@EnJens)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bootimg.h"

#ifdef __ANDROID__ 
#include <utils/Log.h>
#endif


#ifndef SHA_DIGEST_SIZE
#define SHA_DIGEST_SIZE 20
#endif
#define SHA_DIGEST_STR_SIZE 40
#define BUFFER_SIZE 2048

#ifdef __ANDROID__
#define debug(fmt, ...) do { \
    printf(fmt, __VA_ARGS__); \
    ALOGV(fmt,__VA_ARGS__); \
} while(0)
#else
#define debug(fmt, ...) do { \
    printf(fmt, __VA_ARGS__); \
} while(0)
#endif


int verify(char* filename, char* sha1sum, int* size, int verbose)
{
    boot_img_hdr hdr;
    FILE *fh;

    fh = fopen(filename, "r");
    if(fh == NULL)
        return -1;
    fread(&hdr, sizeof(boot_img_hdr), 1, fh);
    fclose(fh);

    // it's not even a boot image.
    if(strncmp((const char*)hdr.magic, BOOT_MAGIC, BOOT_MAGIC_SIZE))
        return -2;
    if(hdr.kernel_size < 1 || hdr.ramdisk_size < 1)
        return -2;
    
    unsigned int header_padding = sizeof(boot_img_hdr) + (-sizeof(boot_img_hdr) & (hdr.page_size -1));
    unsigned int kernel_padding = hdr.kernel_size + ((-hdr.kernel_size) & (hdr.page_size -1));
    unsigned int ramdisk_padding = hdr.ramdisk_size + ((-hdr.ramdisk_size) & (hdr.page_size -1));
    
    *size = header_padding + kernel_padding + ramdisk_padding + hdr.second_size;

    snprintf(sha1sum, SHA_DIGEST_STR_SIZE, "%X%X%X%X%X", hdr.id[0], hdr.id[1], hdr.id[2], hdr.id[3], hdr.id[4]);

    if(verbose) {
        debug("Magic: %.*s\n", BOOT_MAGIC_SIZE, hdr.magic);
        debug("ID: %s\n", sha1sum);
        debug("Kernel size: 0x%X (%d)\n", hdr.kernel_size, hdr.kernel_size);
        debug("Kernel addr: 0x%X\n", hdr.kernel_addr);
        debug("Ramdisk size: 0x%X (%d)\n", hdr.ramdisk_size, hdr.ramdisk_size);
        debug("Ramdisk addr: 0x%X\n", hdr.ramdisk_addr);

        debug("Second size: 0x%X (%d)\n", hdr.second_size, hdr.second_size);
        debug("Second addr: 0x%X\n", hdr.second_addr);
        debug("Tags addr: 0x%X\n", hdr.tags_addr);
        debug("Page size: 0x%X (%d)\n", hdr.page_size, hdr.page_size);
        debug("Name: %.*s\n", BOOT_NAME_SIZE, hdr.name);
        debug("Cmdline: %.*s\n", BOOT_ARGS_SIZE, hdr.cmdline);
    }
    return 0;
}

int main(int argc, char **argv)
{
    char* sha1sum = malloc(SHA_DIGEST_STR_SIZE*sizeof(char));

    int filesize;
    int dump = 0;
    

    if(argc < 3) {
        debug("Usage: %s [-d(ump)] [-c](checksum) [-b](backup) <boot.img>\n", argv[0]);
        return -1;
    }

    // dump the image information.
    if(!strncmp(argv[1], "-d", 2*sizeof(char))) {
        dump = 1;
    }

    if(verify(argv[2], sha1sum, &filesize, dump) < 0) {
        debug("%s is not a correct image.\n", argv[2]);
        return -1;
    }
    if(dump)
        return 0;

    // dump the image checksum
    if(!strncmp(argv[1], "-c", 2*sizeof(char))) {
        debug("%s\n", sha1sum);
        return 0;
    }

    // backup the image
    if(!strncmp(argv[1], "-b", 2*sizeof(char))) {
	char* out_sha1sum = malloc(SHA_DIGEST_STR_SIZE*sizeof(char));
	int out_filesize;

        // check if files have same checksum
	if(verify(argv[3], out_sha1sum, &out_filesize, 0) == 0) 
	    if(strncmp(sha1sum, out_sha1sum, SHA_DIGEST_STR_SIZE) == 0)
		    return 0;


        unsigned int dataleft = filesize;
        FILE *in;
        FILE *out;
        in = fopen(argv[2], "rb");
        out = fopen(argv[3], "wb");
        if(in == NULL || out == NULL) return -1;
   
        char buffer[BUFFER_SIZE];
        while(dataleft > 0) {
            unsigned int fsize = BUFFER_SIZE < dataleft ? BUFFER_SIZE : dataleft;
            unsigned int read_data = fread(buffer, 1, fsize, in);
            unsigned int written_data = fwrite(buffer, 1, read_data, out);
            if(read_data != written_data) {
                abort();
            }
            dataleft -= read_data;
        }

        fclose(in);
        fclose(out);

        return 0;
    }

    debug("Usage: %s [-d(ump)] [-c](checksum) [-b](backup) <boot.img>\n", argv[0]);
    return -1;

}

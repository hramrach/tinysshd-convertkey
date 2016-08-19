/*
 * MIT License
 *
 * Copyright (c) 2016 Anton Semjonov
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Description:
 * This software converts existing ed25519 keys from OpenSSH format to the TinySSH format.
 * TinySSH is a small SSH server put into public domain [https://tinyssh.org/].
 */

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/* local includes */
#include "errors.h"
#include "utils.h"
#include "fileops.h"
#include "buffer.h"

/* the secretkey filename */
char sourcefn[1024];
int have_sourcefn = 0;

/* the destination directory */
char destfn[1024];
int have_destfn = 0;

/* buffer for reading and writing files */
char filebuf[1024 * 1024];

/* ======  MAIN  ====== */

int main(int argc, char **argv)
{
	int opt;
	extern char *optarg;

    /* parse arguments */
	while ((opt = getopt(argc, argv, "?hf:d:")) != -1) {
		switch (opt) {

        /* filename */
        case 'f':
			if (strncpy(sourcefn, optarg, sizeof(sourcefn)) == NULL)
				fatal(ERR_FILENAME_TO_LONG, "privatekey filename too long");
			have_sourcefn = 1;
			break;

        /* destination directory */
        case 'd':
			if (strncpy(destfn, optarg, sizeof(destfn)) == NULL)
			    fatal(ERR_FILENAME_TO_LONG, "destination directory name too long");
			have_destfn = 1;
			break;

        case 'h':
		case '?':
		default:
			usage();
		}
	}

    /* prompt for source if not given */
    //if (!have_sourcefn)
    //    prompt ("Enter a source filename", sourcefn, sizeof sourcefn, "/tmp/nope.txt");
    /* load to buffer */
    //loadfile(sourcefn, filebuf, sizeof filebuf);

    /* show contents of file */
    //debugbuf(sourcefn, filebuf, strlen(filebuf));

    struct buffer *newbuff;
    newbuff = newbuffer();

    printf("allocated %d bytes for new buffer\n", newbuff->allocation);

    memfill(newbuff->dataptr, newbuff->allocation, 0xAE);

    debugbuf("newbuff struct", (unsigned char *)newbuff, sizeof *newbuff);
    debugbuf("newbuff allocated data", newbuff->dataptr, newbuff->allocation);

    unsigned char *datapointer = newbuff->dataptr;
    size_t allocationsize = newbuff->allocation;

    bufferfree(newbuff);

    debugbuf("newbuff allocated data AFTER FREE", datapointer, allocationsize);

	exit(0);
}

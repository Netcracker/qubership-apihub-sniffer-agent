/*
 * Copyright 2024-2025 NetCracker Technology Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
typedef struct _file_head   {
    uint32_t magic;
    uint16_t majorVer;
    uint16_t minorVer;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t snapLen;
    uint16_t linkType;
    uint16_t fcs;
}FileHead;

typedef struct _pck_head {
    uint32_t seconds;
    uint32_t fractions;
    int32_t capturedLen;
    int32_t originalLen;
}PckHead;
#define BUF_LEN 4096
void print_dump(const unsigned char* buf, int data_len)
{
    int i;
    if(data_len>8)  {
        data_len = 16;
    }
    for(i=0; i<data_len; i++)   {
        printf(" %02X", buf[i]);
    }
}

int main(int argc, char* argv[])
{
    int fd;
    int n, nr;
    FileHead fh;
    PckHead ph;
    char buf[BUF_LEN];
    uint32_t pos;
    int need_dump;

    fd = open(argv[1], O_RDONLY);
    if(fd>=0)   {
        nr = sizeof(FileHead);
        n = read(fd, &fh, nr);
        if(n==nr)   {
            pos = nr;
            printf(" Magic Number:%08X\nMajor Version:%d\nMinor Version:%d\n      SnapLen:%d\n          FCS:%04X\n    Link type:%d\n",
                fh.magic, fh.majorVer, fh.minorVer, fh.snapLen, fh.fcs, fh.linkType);
            if(fh.reserved1 || fh.reserved2)    {
                fprintf(stderr, "Warning! reserved1:%08X, Reserved2: %08X\n", fh.reserved1, fh.reserved2);
            }
            printf("  Offset,    Seconds.Timestamp,   Captured,  Original\n");
            nr = sizeof(PckHead);
            while((n=read(fd, &ph, nr))==nr)  {
                printf("%08X, %10u.%010u, %9d, %9d", pos, ph.seconds, ph.fractions, ph.capturedLen, ph.originalLen);
                if(ph.capturedLen>fh.snapLen || ph.originalLen>fh.snapLen)  {
                    fprintf(stderr,"\nError in packet at %08X, read %d bytes\n", pos, nr);
                    break;
                }
                pos += nr;
                need_dump = 1;
                while(ph.capturedLen>0) {
                    nr = ph.capturedLen>BUF_LEN?BUF_LEN:ph.capturedLen;
                    n = read(fd, buf, nr);
                    ph.capturedLen -= n;
                    if(n!=nr) {
                        fprintf(stderr,"Unable to read %d bytes from packet data\n", nr);
                        break;
                    }
                    if(need_dump==1)    {
                        print_dump((const unsigned char*)buf, nr);
                        need_dump = 0;
                    }
                    pos += nr;
                }
                puts("");
                if(n!=nr) {
                    break;
                }
                nr = sizeof(PckHead);
                memset(&ph, 0, nr);
            }
        }
        else {
            fprintf(stderr,"Unable to read %d bytes from packet header data\n", nr);
        }
        fprintf(stderr,"Finished at %08X\n", pos);
        close(fd);
    }
    else {
        fprintf(stderr,"Unable to open file %s. Error: %s\n", argv[1], strerror(errno));
    }
    return EXIT_SUCCESS;
}
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>


const char g_hashlut[] = 
"MLPOIKUJNBHYTGVCFZEDXSRQAWOIUATMQEXKYDSLRFZGNJVCPBWHTRQVCKGUJFSAWMZNXLPOIHBEDYGQMKNHOIUATVEJBWXCDZPSLRFYLRZXJBUFSYGQNPCDITMVAHEOKWYMPNWXKSDTLBQEGHCJVRFZOIUA";

char g_hashbuf[1024];

void check_hash(const char *passwdbuf, int len, int uid, int verbose) {
    int acc = passwdbuf[len-1] - 'A';
    if (len <= 0) return;
    int i = 0;
    char *hashptr = g_hashbuf;
    const char *hashlut = g_hashlut + 52*(uid%3);
    do {
        unsigned char c1 = *(hashlut+acc+26);
        if (verbose)
            printf("i=%d, acc=%d->%d (%c in g_hashlut), c1=%c, ", i, acc, acc-77, hashlut[acc], c1);
        acc = (int)c1 - 77;
        if (acc <= 0)
            acc--;
        acc = acc + (*passwdbuf - 'A');
        passwdbuf++;
        if (verbose)
            printf("acc_preadjust=%d, ", acc);
        if (acc < 0)
            acc += 26;
        if (acc >= 26)
            acc -= 26;
        if (verbose)
            printf("acc_lookup=%d (%c)\n", acc, hashlut[acc]);
        *hashptr = hashlut[acc];
        hashptr++;
        i++;
    } while (i < len);
}

void strtoupper(char *s, int len) {
    int i;
    //printf("converting: [");
    for (i = 0; i < len; i++) {
        // toupper code as CNUSLIB does it:
        unsigned int c = s[i];
        c -= 97;
        if (c < 25) {
            s[i] = s[i] + 224;
        }

        //s[i] = toupper(s[i]);

        //printf("%d", s[i]-65);
        //if (i < len-1)
        //    printf(", ");
    }
    //printf("]\n");
}

char s1[32];
char s2[] = "userAAAA";
char s3[] = "debugAAA";
char s4[] = "logAAAAA";

//log:OYPTEZXR:5:256:trace shell:/var:/sbin/strace 
//default:MZPUHGQY:256:256:Default User:/home/default:/bin/sh
//debug:BQTMQYWL:4:256:Debug Shell:/usr/local:/bin/debugsh 

int main() 
{
    //printf("hashlut is %d chars long.\n", sizeof(g_hashlut));
    int i;
    /*
    for (i = 0; i < 26; i++) {
        printf("Sequence %d ('%c' start) ", i, i+'A');
        memset(s1, 'A', 32);
        s1[0] = 'A' + i;
        memset(g_hashbuf, 0, sizeof(g_hashbuf));
        //printf("before passwdbuf: %s\n", s1);
        strtoupper(s1, 32);
        //printf("after strtoupper: %s\n", s1);
        check_hash(s1, 32, 0, 0);
        printf("after passwdbuf: %s, %s\n", s1, g_hashbuf);
    }
    */

    memset(g_hashbuf, 0, sizeof(g_hashbuf));
    printf("passwdbuf: %s (", s2);
    strtoupper(s2, 8);
    printf("toupper: %s) ", s2);
    check_hash(s2, 8, 256, 0);
    printf("hash: %s (expect MZPUHGQY)\n", g_hashbuf);

    memset(g_hashbuf, 0, sizeof(g_hashbuf));
    printf("passwdbuf: %s (", s3);
    strtoupper(s3, 8);
    printf("toupper: %s) ", s3);
    check_hash(s3, 8, 4, 0);
    printf("hash: %s (expect BQTMQYWL)\n", g_hashbuf);

    memset(g_hashbuf, 0, sizeof(g_hashbuf));
    printf("passwdbuf: %s (", s4);
    strtoupper(s4, 8);
    printf("toupper: %s) ", s4);
    check_hash(s4, 8, 5, 0);
    printf("hash: %s (expect OYPTEZXR)\n", g_hashbuf);

    while(1) {
        memset(s1, 'A', 32);
        printf("Input: ");
        gets(s1);
        s1[8] = '\0';
        strtoupper(s1, 8);
        printf("passwdbuf: %s ", s1);
        check_hash(s1, 8, 0, 0);
        printf("hash: %s\n", g_hashbuf);
    }
    return 0;
}

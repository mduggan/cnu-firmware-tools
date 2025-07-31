#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/types.h>

/////////////////////////////////////////////////////////////////
// Definitions for ELF binary type


typedef unsigned int Elf32_Addr;  
typedef unsigned short Elf32_Half;
typedef unsigned int Elf32_Off;
typedef int Elf32_Sword;
typedef unsigned int Elf32_Word;

#define EI_NIDENT   16

#pragma pack(push, 1)

typedef struct {
    unsigned char   e_ident[EI_NIDENT];
    Elf32_Half      e_type;
    Elf32_Half      e_machine;
    Elf32_Word      e_version;
    Elf32_Addr      e_entry;
    Elf32_Off       e_phoff;
    Elf32_Off       e_shoff;
    Elf32_Word      e_flags;
    Elf32_Half      e_ehsize;
    Elf32_Half      e_phentsize;
    Elf32_Half      e_phnum;
    Elf32_Half      e_shentsize;
    Elf32_Half      e_shnum;
    Elf32_Half      e_shstrndx;
}   Elf32_Ehdr;

//e_type
#define ET_NONE     (Elf32_Half)0
#define ET_REL      (Elf32_Half)1
#define ET_EXEC     (Elf32_Half)2
#define ET_DYN      (Elf32_Half)3
#define ET_CORE     (Elf32_Half)4
#define ET_LOPROC   (Elf32_Half)0xff00
#define ET_HIPROC   (Elf32_Half)0xffff

//e_machine
#define EM_MIPS     (Elf32_Half)8

//e_version
#define EV_NONE     0
#define EV_CURRENT  1

typedef struct {
    Elf32_Word  p_type;
    Elf32_Off   p_offset;
    Elf32_Addr  p_vaddr;
    Elf32_Addr  p_paddr;
    Elf32_Word  p_filesz;
    Elf32_Word  p_memsz;
    Elf32_Word  p_flags;
    Elf32_Word  p_align;
} Elf32_Phdr;

#define PT_NULL         0               /* p_type */
#define PT_LOAD         1
#define PT_DYNAMIC      2
#define PT_INTERP       3
#define PT_NOTE         4
#define PT_SHLIB        5
#define PT_PHDR         6
#define PT_NUM          7

#define PF_R            0x1
#define PF_W            0x2
#define PF_X            0x4

typedef struct {
    Elf32_Word  sh_name;
    Elf32_Word  sh_type;
    Elf32_Word  sh_flags;
    Elf32_Addr  sh_addr;
    Elf32_Off   sh_offset;
    Elf32_Word  sh_size;
    Elf32_Word  sh_link;
    Elf32_Word  sh_info;
    Elf32_Word  sh_addralign;
    Elf32_Word  sh_entsize;
} Elf32_Shdr;

#define SHN_UNDEF    0

#define SHF_WRITE     0x1
#define SHF_ALLOC     0x2
#define SHF_EXECINSTR 0x4
#define SHF_MASKPROC  0x8

#define SHT_NULL     0
#define SHT_PROGBITS 1
#define SHT_STRTAB   3
#define SHT_NOBITS   8

static const char ELF_CNU_IDENT[EI_NIDENT] = { 
    0x7f,0x45,0x4c,0x46,0x01,0x02,0x01,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 
};


static const char ELF_CNU_STRTABLE[] = 
/*0x01*/    "\0.text\0"
/*0x07*/    ".comment\0"
/*0x10*/    ".sdata2\0"
/*0x18*/    ".data\0"
/*0x1e*/    ".sdata\0"
/*0x25*/    ".sbss\0"
/*0x2b*/    ".bss\0"
/*0x30*/    ".shstrtab\0"
/*0x39*/    "\0\0\0\0\0\0\0\0";

unsigned int ELF_CNU_STRTABLE_TEXT   = 0x01;
unsigned int ELF_CNU_STRTABLE_SDATA  = 0x1e;
unsigned int ELF_CNU_STRTABLE_SBSS   = 0x25;
unsigned int ELF_CNU_STRTABLE_STRTAB = 0x30;
unsigned int ELF_CNU_STRTABLE_LEN    = 0x40;

/////////////////////////////////////////////////////////////////
/// Definitions for CNU exe type.

typedef struct { 
    unsigned char   c_sig[4];       // 0xdead beef
    unsigned char   c_version[48];  // 1.0 (0.0) \0\0...
    unsigned char   c_esig[4];      // 0x43fd ef34
    Elf32_Addr      c_entry;        // 0x0020 0010
    Elf32_Addr      c_nsect;        // n sections
} Cnu32_Chdr;

typedef struct { 
    Elf32_Word      c_type;  // size in bytes
    Elf32_Addr      c_addr;  // load address
    Elf32_Word      c_size;  // size in bytes
} Cnu32_Shdr;

typedef struct {
    Cnu32_Chdr      chdr;
    Cnu32_Shdr     *shdrs;
    void *          sections[16];
    unsigned int    codesize;   // code size (same in memory and file)
    unsigned int    datasize_f; // data size, file
    unsigned int    datasize_m; // data size, memory
} cnufile;

static const unsigned char CNU_SIG[4] =  { 0xde, 0xad, 0xbe, 0xef };
static const unsigned char CNU_ESIG[4] = { 0x43, 0xfd, 0xef, 0x34 };
/////////////////////////////////////////////////////////////////

int verbose = 1;

// flip MSB to LSB and vice-versa.
Elf32_Addr flip(Elf32_Addr a) {
    Elf32_Addr r = ((a&0xff)<< 24) | ((a&0xff00)<< 8) | ((a&0xff0000)>> 8) | ((a&0xff000000)>> 24);
    return r;
}

Elf32_Half flip(Elf32_Half a) {
    Elf32_Half r = ((a&0xff)<< 8) | ((a&0xff00)>> 8);
    return r;
}

unsigned int flip(int i) {
    unsigned int a = (unsigned int)i;
    unsigned int r = ((a&0xff)<< 24) | ((a&0xff00)<< 8) | ((a&0xff0000)>> 8) | ((a&0xff000000)>> 24);
    return (int)r;
}

void init_elf_ehdr(Elf32_Ehdr *h) {
    assert(h);
    memcpy(h->e_ident, ELF_CNU_IDENT, EI_NIDENT);
    h->e_type     = flip(ET_EXEC);
    h->e_machine  = flip(EM_MIPS);
    h->e_version  = flip(EV_CURRENT);
    h->e_entry    = flip(0x200010);
    h->e_phoff    = flip(0x34);
    h->e_shoff    = 0; // will be filled out later
    h->e_flags    = flip(0x10000000);
    h->e_ehsize   = flip((Elf32_Half)0x34);
    h->e_phentsize= flip((Elf32_Half)0x20);
    h->e_phnum    = flip((Elf32_Half)0x2); 
    h->e_shentsize= flip((Elf32_Half)0x28);
    h->e_shnum    = 0; // will be filled out later
    h->e_shstrndx = 0; // will be filled out later 
}


/* return 0 on success */
int read_and_check_cnu_hdr(FILE *f, Cnu32_Chdr *h) {
    int sz;
    assert(h);
    sz = fread(h, 1, sizeof(Cnu32_Chdr), f);
    if (sz != sizeof(Cnu32_Chdr)) {
        if (verbose) printf("CNU hdr: expected %d bytes got %d\n", (int)sizeof(Cnu32_Chdr), sz);
        return 1;
    }
    if (memcmp(h->c_sig, CNU_SIG, 4)) {
        if (verbose) printf("CNU signature not found\n");
        return 2;
    }
    if (memcmp(h->c_esig, CNU_ESIG, 4)) {
        if (verbose) printf("CNU end-signature not found (expected %2x%2x%2x%2x got %x%x%x%x)\n",
            CNU_ESIG[0],CNU_ESIG[1],CNU_ESIG[2],CNU_ESIG[3],
            h->c_esig[0],h->c_esig[1],h->c_esig[2],h->c_esig[3]);
        return 3;
    }

    h->c_entry = flip(h->c_entry);
    h->c_nsect = flip(h->c_nsect);

    return 0;
}

int read_cnu_shdr(FILE *f, Cnu32_Shdr *h) {
    int sz;
    assert(h);
    sz = fread(h, 1, sizeof(Cnu32_Shdr), f);
    if (sz != sizeof(Cnu32_Shdr))
        return 1;

    h->c_size = flip(h->c_size);
    h->c_type = flip(h->c_type);
    h->c_addr = flip(h->c_addr);

    return 0;
}

int read_cnu_file(FILE *f, cnufile *d) {
    unsigned int i;
    assert(f);
    assert(d);

    memset(d, 0, sizeof(cnufile));

    if (read_and_check_cnu_hdr(f, &(d->chdr)))
        return 1;
    if (verbose) printf("Valid CNU header.  Program version %s\n", d->chdr.c_version);
    if (verbose) printf("Entrypoint 0x%x, %d sections.\n", d->chdr.c_entry, d->chdr.c_nsect);
    if (d->chdr.c_nsect > 20) {
        printf("%d sections seems suspicious.  Endian-ness probably wrong. Giving up.\n", d->chdr.c_nsect);
        return -1;
    }
    d->shdrs = (Cnu32_Shdr *)malloc(sizeof(Cnu32_Shdr) * d->chdr.c_nsect);
    for (i = 0; i < d->chdr.c_nsect; i++) {
        Cnu32_Shdr *sh = d->shdrs+i;
        if (read_cnu_shdr(f, sh))
            return 2;
        if (verbose) printf("CNU section %d: type 0x%x load addr 0x%x size 0x%x (%d bytes)\n", 
            i, sh->c_type, sh->c_addr, sh->c_size, sh->c_size);
        switch(sh->c_type) {
            case 1:
                d->codesize += sh->c_size; break;
            case 2:
                d->datasize_f += sh->c_size; // fall through.
            case 3:
                d->datasize_m += sh->c_size; break;
            default:
                printf("Don't know what to do with CNU section type %d!\n", sh->c_type);
                return 4;
        }
    }

    for (i = 0; i < d->chdr.c_nsect; i++) {
        int r;
        int sz = d->shdrs[i].c_size;
        int type = d->shdrs[i].c_type;
        if (type <= 2) {
            d->sections[i] = malloc(sz);
            r = fread(d->sections[i], 1, sz, f);
            if (sz != r) {
                if (verbose) printf("Reading section %d expected %d bytes got %d.\n", i, sz, r);
                return 3;
            }
        } else if (type == 3) {
            if (verbose) printf("(not reading section %d)\n", i);
            d->sections[i] = NULL;
        }
    }
    if (verbose) printf("Read %d sections.  Totals: %db code, %db filedata, %db memdata\n", 
        d->chdr.c_nsect, d->codesize, d->datasize_f, d->datasize_m);

    if (!feof(f)) {
        /* Check if there's any more data: */
        unsigned char c;
        int sz = fread(&c, 1, 1, f);
        if (!feof(f)) printf("Trailing data on file:\n");
        while (!feof(f)) {
            if (!sz)
                break;
            printf("%x ", c);
            sz = fread(&c, 1, 1, f);
        }
    }

    return 0;
}


static int cnu_section_to_elf_section(Elf32_Shdr *e, const Cnu32_Shdr *c, unsigned int fileoff) {
    switch (c->c_type) {
        case 1:
            e->sh_name = flip(ELF_CNU_STRTABLE_TEXT);
            e->sh_type = flip(SHT_PROGBITS);
            e->sh_flags = flip(SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR);
            break;
        case 2:
            e->sh_name = flip(ELF_CNU_STRTABLE_SDATA);
            e->sh_type = flip(SHT_PROGBITS);
            e->sh_flags = flip(SHF_WRITE | SHF_ALLOC);
            break;
        case 3:
            e->sh_name = flip(ELF_CNU_STRTABLE_SBSS);
            e->sh_type = flip(SHT_NOBITS);
            e->sh_flags = flip(SHF_WRITE | SHF_ALLOC);
            break;
        default:
            assert(0);
    }
    if (verbose) printf("section name: '%s'\n", ELF_CNU_STRTABLE+flip(e->sh_name));
    e->sh_addr = flip(c->c_addr);
    e->sh_offset = flip(fileoff);
    e->sh_size   = flip(c->c_size);
    e->sh_link   = flip(SHN_UNDEF);
    e->sh_info   = 0;
    e->sh_addralign = flip(4);
    e->sh_entsize = 0;

    return 0;
}

static int cnu_section_add_to_elf_prog(Elf32_Phdr *e, const Cnu32_Shdr *c) 
{
    e->p_type   = flip(PT_LOAD);
    e->p_offset = 0; // offset in the file, will be filled out later.
    if (!e->p_vaddr)
        e->p_vaddr  = flip(c->c_addr);
    e->p_paddr  = 0;
    unsigned int prevsz = flip(e->p_filesz);
    e->p_filesz = flip(c->c_size + prevsz);
    e->p_memsz  = flip(c->c_size + prevsz); 
    if (c->c_type == 1) {
        e->p_flags     = flip(PF_R | PF_W | PF_X);
    } else {
        e->p_flags     = flip(PF_R | PF_W);
    }
    e->p_align  = 0;

    return 0;
}

static void elf_string_table_section(Elf32_Shdr *e, unsigned int offset) 
{ 
    e->sh_name   = flip(ELF_CNU_STRTABLE_STRTAB);
    if (verbose) printf("strtable name: '%s'\n", ELF_CNU_STRTABLE+ELF_CNU_STRTABLE_STRTAB);
    e->sh_type   = flip(SHT_STRTAB);
    e->sh_flags  = 0;
    e->sh_addr   = 0;
    e->sh_offset = flip(offset);
    e->sh_size   = flip(ELF_CNU_STRTABLE_LEN);
    e->sh_link   = flip(SHN_UNDEF);
    e->sh_info   = 0;
    e->sh_addralign = flip(1);
    e->sh_entsize = 0;
}

int convert_to_elf(const cnufile *c, const char *fname) 
{
    Elf32_Ehdr ehdr;
    Elf32_Shdr shdrs[16];
    Elf32_Phdr phdrs[3]; // always 2 phdrs and one padding
    //char phdrpad[2] = { 0x0, 0x0 };
    char fnbuf[256];
    FILE *f;
    unsigned int i = 0;
    unsigned int j = 0;
    unsigned int sz;

    unsigned int hdr_end = sizeof(ehdr) + sizeof(phdrs);// + sizeof(phdrpad); 

    unsigned int nsecthdr = 1; // first section header always blank

    memset(&ehdr, 0, sizeof(ehdr));
    memset(shdrs, 0, sizeof(shdrs));
    memset(phdrs, 0, sizeof(phdrs));
    memset(fnbuf, 0, sizeof(fnbuf));

    init_elf_ehdr(&ehdr);

    if (c->chdr.c_nsect > 16) {
        if (verbose) printf("Too many sections in convert_to_elf.\n"); 
        return 1;
    }

    j = 0;
    for (i = 0; i < c->chdr.c_nsect; i++) {
        const Cnu32_Shdr *sh = c->shdrs + i;
        if (sh->c_type == 1 || sh->c_type == 2) {
            cnu_section_add_to_elf_prog(phdrs+(sh->c_type - 1), sh);
        }
        else {
            // Section type 3 takes space in memory but not on disk:
            phdrs[1].p_memsz = flip(flip(phdrs[1].p_memsz) + sh->c_size);
        }
    }

    sz = hdr_end; 
    for (i = 0; i < c->chdr.c_nsect; i++) {
        const Cnu32_Shdr *sh = c->shdrs + i;
        cnu_section_to_elf_section(shdrs+nsecthdr, sh, sz);
        if (sh->c_type == 1 || sh->c_type == 2) {
            sz += c->shdrs[i].c_size;
        }
        nsecthdr++;
    }
    // Add a section for the string table:
    elf_string_table_section(shdrs+nsecthdr, sz);
    nsecthdr++;

    strcpy(fnbuf, fname);
    strcat(fnbuf, "-elf");

    if (verbose) printf("Writing 2 prog hdrs and %d section hdrs to %s \n", nsecthdr, fnbuf);
    if (verbose) printf("[hdr_end = 0x%x, shoff = 0x%x, shstrndx=%d]\n", hdr_end, hdr_end + c->codesize + c->datasize_f + ELF_CNU_STRTABLE_LEN, nsecthdr-1);

    // Make final tweaks to data now that we know all the sizes:
    ehdr.e_shnum    = flip((Elf32_Half)nsecthdr);
    ehdr.e_shstrndx = flip((Elf32_Half)(nsecthdr-1));
    ehdr.e_shoff    = flip(hdr_end + c->codesize + c->datasize_f + ELF_CNU_STRTABLE_LEN);

    phdrs[0].p_offset = flip(hdr_end);
    phdrs[1].p_offset = flip(hdr_end + c->codesize);

    f = fopen(fnbuf, "wb");

    sz = fwrite(&ehdr, 1, sizeof(ehdr), f);
    if (sz < 1) { return -1; } 
    sz = fwrite(phdrs, 1, sizeof(phdrs), f);
    if (sz < 1) { return -1; } 

    for (i = 0; i < c->chdr.c_nsect; i++) {
        const Cnu32_Shdr *sh = c->shdrs + i;
        if (sh->c_type == 1 || sh->c_type == 2) {
            sz = fwrite(c->sections[i], 1, sh->c_size, f);
            if (sz < 1) { return -1; } 
        }
    }

    sz = fwrite(ELF_CNU_STRTABLE, 1, ELF_CNU_STRTABLE_LEN, f);
    if (sz < 1) { return -1; } 

    sz = fwrite(shdrs, 1, nsecthdr*sizeof(Elf32_Shdr), f);
    if (sz < 1) { return -1; } 

    fclose(f);

    return 0;
}

int main(int argc, char *argv[]) {
    cnufile c;
    FILE *f;
    if (argc < 2) {
        printf("Usage: %s cnufile\n", argv[0]);
        exit(1);
    }

    f = fopen(argv[1], "rb");

    if (f == NULL) {
        printf("error opening %s\n", argv[1]);
        exit(2);
    }

    if (read_cnu_file(f, &c) != 0) {
        exit(3);
    }

    fclose(f);

    if (convert_to_elf(&c, argv[1]) != 0) {
        printf("error converting %s\n", argv[1]);
        exit(4);
    }

    return 0;
}

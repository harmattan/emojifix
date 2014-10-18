#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <elf.h>

#define FAIL(...) printf(__VA_ARGS__); exit(1)

typedef struct {
    size_t gnu_version_section_offset;
    size_t gnu_version_section_size;

    size_t dynsym_section_offset;
    size_t dynsym_section_size;

    size_t dynstr_section_offset;
    size_t dynstr_section_size;

    size_t dynamic_section_offset;
    size_t dynamic_section_size;

    // Offset of "iconv_open" in the dynamic string table
    size_t iconv_open_dynstr_offset;
    // Index in dynamic symbol table of "iconv_open" symbol
    int iconv_open_symbol_index;
    // Offset of the SONAME in the 
    size_t soname_dynstr_offset;
} PatchInfo;

static void
patch_string(char *input, size_t offset, const char *new_str)
{
    char *old_str = input + offset;
    size_t old_len = strlen(old_str);
    size_t new_len = strlen(new_str);

    printf("Patching string '%s' (%d bytes) -> '%s' (%d bytes) @ 0x%x\n",
            old_str, old_len, new_str, new_len, offset);

    if (new_len > old_len) {
        FAIL("Cannot patch %d new bytes of %d old bytes\n", new_len, old_len);
    }

    memset(old_str, 0, old_len);
    memcpy(old_str, new_str, new_len);
}

static PatchInfo *
parse_elf(const char *data, size_t size)
{
    Elf32_Ehdr hdr;
    Elf32_Shdr shdr;
    Elf32_Shdr sshdr;

    PatchInfo *info = calloc(1, sizeof(PatchInfo));
    if (info == NULL) {
        FAIL("Could not allocate PatchInfo\n");
    }

    memcpy(&hdr, data, sizeof(hdr));
    memcpy(&sshdr, data + hdr.e_shoff + hdr.e_shstrndx * hdr.e_shentsize, sizeof(sshdr));

    int i;
    for (i=0; i<hdr.e_shnum; i++) {
        memcpy(&shdr, data + hdr.e_shoff + i * hdr.e_shentsize, sizeof(shdr));
        const char *name = data + sshdr.sh_offset + shdr.sh_name;
        if (strcmp(name, ".gnu.version") == 0) {
            printf("Found .gnu.version section at 0x%x (%d bytes)\n",
                    shdr.sh_offset, shdr.sh_size);
            info->gnu_version_section_offset = shdr.sh_offset;
            info->gnu_version_section_size = shdr.sh_size;
        } else if (strcmp(name, ".dynsym") == 0) {
            printf("Found .dynsym section at 0x%x (%d bytes)\n",
                    shdr.sh_offset, shdr.sh_size);
            info->dynsym_section_offset = shdr.sh_offset;
            info->dynsym_section_size = shdr.sh_size;
        } else if (strcmp(name, ".dynstr") == 0) {
            printf("Found .dynstr section at 0x%x (%d bytes)\n",
                    shdr.sh_offset, shdr.sh_size);
            info->dynstr_section_offset = shdr.sh_offset;
            info->dynstr_section_size = shdr.sh_size;
        } else if (strcmp(name, ".dynamic") == 0) {
            printf("Found .dynamic section at 0x%x (%d bytes)\n",
                    shdr.sh_offset, shdr.sh_size);
            info->dynamic_section_offset = shdr.sh_offset;
            info->dynamic_section_size = shdr.sh_size;
        }
    }

    if (info->gnu_version_section_offset == 0 ||
        info->gnu_version_section_size == 0 ||
        info->dynsym_section_offset == 0 ||
        info->dynsym_section_size == 0 ||
        info->dynstr_section_offset == 0 ||
        info->dynstr_section_size == 0 ||
        info->dynamic_section_offset == 0 ||
        info->dynamic_section_size == 0) {
        FAIL("Could not determine location/size of at least one required section\n");
    }

    return info;
}

static int
file_exists(const char *filename)
{
    struct stat st;
    return (stat(filename, &st) == 0);
}

static void
write_file(const char *filename, char *buf, size_t len)
{
    FILE *fp = NULL;
    
    if ((fp = fopen(filename, "wb")) == NULL) {
        FAIL("Could not open %s for writing\n", filename);
    }

    if (fwrite(buf, len, 1, fp) != 1) {
        FAIL("Could not write %d bytes to %s\n", len, filename);
    }

    printf("Wrote: %s (%d bytes)\n", filename, len);

    fclose(fp);
}

static char *
read_file(const char *filename, size_t *len)
{
    char *result = NULL;
    FILE *fp = NULL;

    if ((fp = fopen(filename, "rb")) == NULL) {
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        FAIL("File open failed: fseek(end)\n");
    }

    size_t size = ftell(fp);
    if (size == 0) {
        FAIL("File open failed: empty file\n");
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        FAIL("File open failed: fseek(start)\n");
    }

    result = malloc(size);
    if (fread(result, size, 1, fp) != 1) {
        FAIL("Could not read file: %s\n", filename);
    }

    printf("Read: %s (%d bytes)\n", filename, size);

    *len = size;

    fclose(fp);
    return result;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        FAIL("Usage: %s <inputfile> <outputfile>\n", argv[0]);
    }

    const char *inputfile = argv[1];
    const char *outputfile = argv[2];
    
    if (!file_exists(inputfile)) {
        FAIL("Input file not found: %s\n", inputfile);
    }

    if (file_exists(outputfile)) {
        FAIL("Output file already exists: %s\n", outputfile);
    }

    printf("Building %s from %s\n", outputfile, inputfile);

    size_t input_size = 0;
    char *input = read_file(inputfile, &input_size);
    if (input == NULL) {
        FAIL("Could not read input file: %s\n", inputfile);
    }

    PatchInfo *info = parse_elf(input, input_size);

    int i;

    for (i=0; i<(info->dynsym_section_size / sizeof(Elf32_Sym)); i++) {
        Elf32_Sym *sym = (Elf32_Sym *)(input + info->dynsym_section_offset + i * sizeof(Elf32_Sym));
        char *name = input + info->dynstr_section_offset + sym->st_name;
        if (strcmp(name, "iconv_open") == 0) {
            printf("Found iconv_open() symbol at index %d\n", i);
            info->iconv_open_dynstr_offset = sym->st_name;
            info->iconv_open_symbol_index = i;
            break;
        }
    }

    if (info->iconv_open_dynstr_offset == 0 ||
            info->iconv_open_symbol_index == 0) {
        FAIL("Could not determine location of iconv_open()\n");
    }

    for (i=0; i<(info->dynamic_section_size / sizeof(Elf32_Dyn)); i++) {
        Elf32_Dyn *dyn = (Elf32_Dyn *)(input + info->dynamic_section_offset + i * sizeof(Elf32_Dyn));
        if (dyn->d_tag == DT_SONAME) {
            printf("Found SONAME (%s) at offset 0x%x\n",
                    input + info->dynstr_section_offset + dyn->d_un.d_val,
                    dyn->d_un.d_val);
            info->soname_dynstr_offset = dyn->d_un.d_val;
            break;
        }
    }

    if (info->soname_dynstr_offset == 0) {
        FAIL("Could not determine SONAME of library\n");
    }

    size_t offset;

    // Replace "iconv_open" symbol with "xconv_open"
    const char *new_function_name = "xconv_open";
    offset = info->dynstr_section_offset + info->iconv_open_dynstr_offset;
    patch_string(input, offset, new_function_name);

    // Replace old SONAME with output filename
    offset = info->dynstr_section_offset + info->soname_dynstr_offset;
    patch_string(input, offset, outputfile);

    offset = info->gnu_version_section_offset +
        info->iconv_open_symbol_index * sizeof(Elf32_Half);
    printf("Patching versioned symbol info for %s @ 0x%x\n",
            new_function_name, offset);
    Elf32_Half *gnu_version_info = (Elf32_Half *)(input + offset);
    *gnu_version_info = 0x1; // set version to 1 (*global*) for xconv_open in .gnu_version

    write_file(outputfile, input, input_size);

    free(info);
    free(input);

    return 0;
}

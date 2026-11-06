// inject.c - insert one LC_LOAD_DYLIB into a thin or universal Mach-O using
// existing header padding only, so no section or segment offsets move.
//
//   inject <input> <output> <install_name>
//
// Handles FAT (0xcafebabe) and FAT64 (0xcafebabf) containers plus thin
// MH_MAGIC_64 slices.  Slices are patched in place, so FAT arch sizes and all
// file offsets remain valid.  The old code signature becomes stale by design;
// sign the bundle afterwards.

#include <errno.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef LC_DYLD_EXPORTS_TRIE
#define LC_DYLD_EXPORTS_TRIE 0x80000033
#endif
#ifndef LC_DYLD_CHAINED_FIXUPS
#define LC_DYLD_CHAINED_FIXUPS 0x80000034
#endif

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t be64(const uint8_t *p) {
    return ((uint64_t)be32(p) << 32) | be32(p + 4);
}

static const char *arch_name(uint32_t cpu) {
    switch (cpu) {
        case CPU_TYPE_X86_64: return "x86_64";
        case CPU_TYPE_ARM64:  return "arm64";
        default:              return "unknown";
    }
}

static void note_offset(uint64_t v, uint64_t *limit) {
    if (v != 0 && v < *limit) *limit = v;
}

static int patch_slice(uint8_t *base, size_t size, const char *install_name, uint32_t cpu) {
    if (size < sizeof(struct mach_header_64)) {
        fprintf(stderr, "[%s] slice too small\n", arch_name(cpu));
        return 0;
    }
    struct mach_header_64 *mh = (struct mach_header_64 *)(void *)base;
    if (mh->magic != MH_MAGIC_64) {
        fprintf(stderr, "[%s] not a 64-bit little-endian Mach-O (magic=0x%08x)\n",
                arch_name(cpu), mh->magic);
        return 0;
    }
    uint64_t cmd_end = sizeof(struct mach_header_64) + (uint64_t)mh->sizeofcmds;
    if (cmd_end > size) {
        fprintf(stderr, "[%s] load commands run past end of slice\n", arch_name(cpu));
        return 0;
    }

    uint64_t limit = size;
    int already = 0;
    uint8_t *lc = base + sizeof(struct mach_header_64);
    uint64_t off = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (off + sizeof(struct load_command) > mh->sizeofcmds) break;
        struct load_command *cmd = (struct load_command *)(void *)(lc + off);
        if (cmd->cmdsize < sizeof(struct load_command) ||
            off + cmd->cmdsize > mh->sizeofcmds) {
            fprintf(stderr, "[%s] malformed load command at +%llu\n",
                    arch_name(cpu), (unsigned long long)off);
            return 0;
        }
        switch (cmd->cmd) {
            case LC_LOAD_DYLIB: {
                struct dylib_command *dc = (struct dylib_command *)(void *)cmd;
                if (dc->dylib.name.offset < cmd->cmdsize) {
                    const char *nm = (const char *)cmd + dc->dylib.name.offset;
                    size_t maxlen = cmd->cmdsize - dc->dylib.name.offset;
                    if (strnlen(nm, maxlen) < maxlen && strcmp(nm, install_name) == 0)
                        already = 1;
                }
                break;
            }
            case LC_SEGMENT_64: {
                struct segment_command_64 *sg = (struct segment_command_64 *)(void *)cmd;
                if (sg->fileoff == 0) {
                    if (sg->filesize > 0) note_offset(sg->filesize, &limit);
                } else {
                    note_offset(sg->fileoff, &limit);
                }
                struct section_64 *s = (struct section_64 *)(void *)(sg + 1);
                for (uint32_t j = 0; j < sg->nsects; j++) {
                    if (s[j].offset != 0) note_offset(s[j].offset, &limit);
                }
                break;
            }
            case LC_SYMTAB: {
                struct symtab_command *sc = (struct symtab_command *)(void *)cmd;
                note_offset(sc->symoff, &limit);
                note_offset(sc->stroff, &limit);
                break;
            }
            case LC_DYSYMTAB: {
                struct dysymtab_command *dc = (struct dysymtab_command *)(void *)cmd;
                note_offset(dc->tocoff, &limit);
                note_offset(dc->modtaboff, &limit);
                note_offset(dc->extreloff, &limit);
                note_offset(dc->locreloff, &limit);
                note_offset(dc->indirectsymoff, &limit);
                break;
            }
            case LC_DYLD_INFO:
            case LC_DYLD_INFO_ONLY: {
                struct dyld_info_command *di = (struct dyld_info_command *)(void *)cmd;
                note_offset(di->rebase_off, &limit);
                note_offset(di->bind_off, &limit);
                note_offset(di->weak_bind_off, &limit);
                note_offset(di->lazy_bind_off, &limit);
                note_offset(di->export_off, &limit);
                break;
            }
            case LC_FUNCTION_STARTS:
            case LC_DATA_IN_CODE:
            case LC_CODE_SIGNATURE:
            case LC_DYLIB_CODE_SIGN_DRS:
            case LC_LINKER_OPTIMIZATION_HINT:
            case LC_DYLD_EXPORTS_TRIE:
            case LC_DYLD_CHAINED_FIXUPS: {
                struct linkedit_data_command *li = (struct linkedit_data_command *)(void *)cmd;
                note_offset(li->dataoff, &limit);
                break;
            }
            case LC_TWOLEVEL_HINTS: {
                struct twolevel_hints_command *th = (struct twolevel_hints_command *)(void *)cmd;
                note_offset(th->offset, &limit);
                break;
            }
            case LC_ENCRYPTION_INFO_64: {
                struct encryption_info_command_64 *ei =
                    (struct encryption_info_command_64 *)(void *)cmd;
                note_offset(ei->cryptoff, &limit);
                break;
            }
            default:
                break;
        }
        off += cmd->cmdsize;
    }

    if (already) {
        printf("[%s] LC_LOAD_DYLIB already present, nothing to do\n", arch_name(cpu));
        return 1;
    }

    uint32_t name_len = (uint32_t)strlen(install_name) + 1;
    uint32_t cmdsize = (uint32_t)((sizeof(struct dylib_command) + name_len + 7u) & ~7u);
    if (cmd_end + cmdsize > limit) {
        fprintf(stderr,
                "[%s] no header slack, skipping %s slice: "
                "cmds end=%llu limit=%llu need=%u\n",
                arch_name(cpu), arch_name(cpu),
                (unsigned long long)cmd_end,
                (unsigned long long)limit, cmdsize);
        return 2;
    }

    uint8_t *dst = base + cmd_end;
    memset(dst, 0, cmdsize);
    struct dylib_command *dc = (struct dylib_command *)(void *)dst;
    dc->cmd = LC_LOAD_DYLIB;
    dc->cmdsize = cmdsize;
    dc->dylib.name.offset = (uint32_t)sizeof(struct dylib_command);
    dc->dylib.timestamp = 2;
    dc->dylib.current_version = 0x00010000;
    dc->dylib.compatibility_version = 0x00010000;
    memcpy(dst + sizeof(struct dylib_command), install_name, name_len);

    mh->ncmds += 1;
    mh->sizeofcmds += cmdsize;

    printf("[%s] inserted LC_LOAD_DYLIB cmdsize=%u, sizeofcmds -> %u, slack limit=%llu\n",
           arch_name(cpu), cmdsize, mh->sizeofcmds, (unsigned long long)limit);
    return 1;
}

static uint8_t *read_file(const char *path, size_t *out_size, mode_t *out_mode) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open(%s): %s\n", path, strerror(errno));
        return NULL;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "stat(%s) failed or not a regular file\n", path);
        close(fd);
        return NULL;
    }
    size_t size = (size_t)st.st_size;
    uint8_t *buf = malloc(size ? size : 1);
    if (!buf) {
        close(fd);
        return NULL;
    }
    size_t done = 0;
    while (done < size) {
        ssize_t n = read(fd, buf + done, size - done);
        if (n <= 0) {
            fprintf(stderr, "read(%s) failed\n", path);
            free(buf);
            close(fd);
            return NULL;
        }
        done += (size_t)n;
    }
    close(fd);
    *out_size = size;
    *out_mode = st.st_mode & 07777;
    return buf;
}

static int write_file(const char *path, const uint8_t *buf, size_t size, mode_t mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) {
        fprintf(stderr, "open(%s, w): %s\n", path, strerror(errno));
        return 0;
    }
    size_t done = 0;
    while (done < size) {
        ssize_t n = write(fd, buf + done, size - done);
        if (n <= 0) {
            fprintf(stderr, "write(%s) failed\n", path);
            close(fd);
            return 0;
        }
        done += (size_t)n;
    }
    fchmod(fd, mode);
    close(fd);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <input> <output> <install_name>\n", argv[0]);
        return 2;
    }
    size_t size = 0;
    mode_t mode = 0755;
    uint8_t *data = read_file(argv[1], &size, &mode);
    if (!data) return 1;

    int ok = 1;
    int patched = 0;
    if (size < 8) {
        fprintf(stderr, "file too small\n");
        free(data);
        return 1;
    }
    uint32_t be_magic = be32(data);
    if (be_magic == 0xcafebabe || be_magic == 0xcafebabf) {
        int is64 = (be_magic == 0xcafebabf);
        uint32_t narch = be32(data + 4);
        size_t off = 8;
        printf("universal: %u slice(s), %s fat header\n", narch, is64 ? "64-bit" : "32-bit");
        for (uint32_t i = 0; i < narch; i++) {
            uint32_t cputype, cpusubtype;
            uint64_t soff, ssize;
            if (is64) {
                if (off + 32 > size) { ok = 0; break; }
                cputype = be32(data + off);
                cpusubtype = be32(data + off + 4);
                soff = be64(data + off + 8);
                ssize = be64(data + off + 16);
                off += 32;
            } else {
                if (off + 20 > size) { ok = 0; break; }
                cputype = be32(data + off);
                cpusubtype = be32(data + off + 4);
                soff = be32(data + off + 8);
                ssize = be32(data + off + 12);
                off += 20;
            }
            (void)cpusubtype;
            if (soff + ssize > size || ssize > size) {
                fprintf(stderr, "slice %u out of bounds\n", i);
                ok = 0;
                break;
            }
            {
                int rc = patch_slice(data + soff, (size_t)ssize, argv[3], cputype);
                if (rc == 1) {
                    patched++;
                } else if (rc == 0) {
                    ok = 0;
                }
            }
        }
        if (ok && patched == 0) {
            fprintf(stderr, "no slice patched\n");
            ok = 0;
        }
    } else {
        uint32_t magic;
        memcpy(&magic, data, 4);
        if (magic != MH_MAGIC_64) {
            fprintf(stderr, "unsupported thin magic 0x%08x\n", magic);
            free(data);
            return 1;
        }
        printf("thin 64-bit Mach-O\n");
        ok = (patch_slice(data, size, argv[3], 0) == 1);
    }

    if (!ok) {
        free(data);
        return 1;
    }
    if (!write_file(argv[2], data, size, mode)) {
        free(data);
        return 1;
    }
    printf("wrote %s (%zu bytes)\n", argv[2], size);
    free(data);
    return 0;
}

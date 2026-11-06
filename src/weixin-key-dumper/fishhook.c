// Minimal fishhook-style symbol rebinding for weixin-key-dumper.
//
// Derived from the public-domain/BSD fishhook implementation. It walks each Mach-O image's __DATA / __DATA_CONST sections, maps lazy and
// non-lazy symbol pointers through LC_SYMTAB + LC_DYSYMTAB, and overwrites the
// slots that reference a rebound symbol.
//
// Limits that matter on macOS 11+:
//   * Only imported symbols have slots.  Calls resolved inside the defining
//     image (WeChat's statically linked SQLCipher codec) never pass through a
//     slot and cannot be rebound here or by __DATA,__interpose.
//   * Images built with LC_DYLD_CHAINED_FIXUPS store encoded pointers until
//     dyld resolves them at launch.  Rewriting a resolved slot from a
//     constructor works (verified against a chained-fixup test-host), but write
//     only after resolution; an unresolved lazy slot is not safe to overwrite.
//     WeChat's main binary uses chained fixups and imports no SQLite symbol, so
//     its static codec calls remain invisible here either way.
//   * __DATA_CONST is read-only at runtime; vm_protect(VM_PROT_COPY) makes the
//     page privately writable before the slot is replaced.

#include "fishhook.h"

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct rebindings_entry {
    struct wx_rebinding *rebindings;
    size_t rebindings_nel;
    struct rebindings_entry *next;
};

static struct rebindings_entry *rebindings_head;

static int prepend_rebindings(struct rebindings_entry **head, struct wx_rebinding rebindings[],
                              size_t nel) {
    struct rebindings_entry *new_entry = malloc(sizeof(struct rebindings_entry));
    if (!new_entry) {
        return -1;
    }
    new_entry->rebindings = malloc(sizeof(struct wx_rebinding) * nel);
    if (!new_entry->rebindings) {
        free(new_entry);
        return -1;
    }
    memcpy(new_entry->rebindings, rebindings, sizeof(struct wx_rebinding) * nel);
    new_entry->rebindings_nel = nel;
    new_entry->next = *head;
    *head = new_entry;
    return 0;
}

#if __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

static size_t page_size_or_default(void) {
    vm_size_t page = vm_page_size;
    return page ? (size_t)page : 4096;
}

// Returns 0 when the page that contains addr is writable.
static int make_writable(void *addr) {
    static uintptr_t last_page = 0;
    static int last_ok = 0;
    const size_t page_size = page_size_or_default();
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)(page_size - 1);
    if (page == last_page) {
        return last_ok;
    }
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)page_size, false,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    last_page = page;
    last_ok = (kr == KERN_SUCCESS) ? 0 : -1;
    return last_ok;
}

static void perform_rebinding_with_section(struct rebindings_entry *rebindings, section_t *section,
                                           intptr_t slide, nlist_t *symtab, uint32_t nsyms,
                                           char *strtab, uint32_t *indirect_symtab) {
    uint32_t type = section->flags & SECTION_TYPE;
    if (type != S_LAZY_SYMBOL_POINTERS && type != S_NON_LAZY_SYMBOL_POINTERS) {
        return;
    }

    uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
    void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
    size_t count = (size_t)(section->size / sizeof(void *));

    for (size_t i = 0; i < count; i++) {
        uint32_t sym_index = indirect_symbol_indices[i];
        if (sym_index == INDIRECT_SYMBOL_ABS || sym_index == INDIRECT_SYMBOL_LOCAL ||
            sym_index == (INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL)) {
            continue;
        }
        if (sym_index >= nsyms) {
            continue;
        }

        uint32_t strx = symtab[sym_index].n_un.n_strx;
        if (strx == 0) {
            continue;
        }
        char *symname = strtab + strx;
        if (symname[0] == '_') {
            symname++;
        }

        for (struct rebindings_entry *cur = rebindings; cur; cur = cur->next) {
            for (size_t j = 0; j < cur->rebindings_nel; j++) {
                if (strcmp(symname, cur->rebindings[j].name) != 0) {
                    continue;
                }
                if (indirect_symbol_bindings[i] == cur->rebindings[j].replacement) {
                    goto next_symbol;
                }

                if (cur->rebindings[j].replaced && *(cur->rebindings[j].replaced) == NULL) {
                    *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
                }

                if (make_writable(&indirect_symbol_bindings[i]) != 0) {
                    continue;
                }

                indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
                goto next_symbol;
            }
        }
    next_symbol:
        (void)0;
    }
}

static void rebind_symbols_for_image(const struct mach_header *header, intptr_t slide) {
    Dl_info info;
    if (dladdr(header, &info) == 0) {
        return;
    }

    segment_command_t *cur_seg_cmd;
    segment_command_t *linkedit_segment = NULL;
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command *load_cmd = (struct load_command *)cur;
        if (load_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
            cur_seg_cmd = (segment_command_t *)cur;
            if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
                linkedit_segment = cur_seg_cmd;
            }
        } else if (load_cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cur;
        } else if (load_cmd->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)cur;
        }
        cur += load_cmd->cmdsize;
    }

    if (!linkedit_segment || !symtab_cmd || !dysymtab_cmd) {
        return;
    }

    uintptr_t linkedit_base =
        (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command *load_cmd = (struct load_command *)cur;
        if (load_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
            cur_seg_cmd = (segment_command_t *)cur;
            if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
                strcmp(cur_seg_cmd->segname, "__DATA_CONST") != 0) {
                cur += load_cmd->cmdsize;
                continue;
            }

            for (uint32_t j = 0; j < cur_seg_cmd->nsects; j++) {
                section_t *sect = (section_t *)(cur + sizeof(segment_command_t) + sizeof(section_t) * j);
                perform_rebinding_with_section(rebindings_head, sect, slide, symtab, symtab_cmd->nsyms,
                                               strtab, indirect_symtab);
            }
        }
        cur += load_cmd->cmdsize;
    }
}

int wx_rebind_symbols(struct wx_rebinding rebindings[], size_t nel) {
    int retval = prepend_rebindings(&rebindings_head, rebindings, nel);
    if (retval < 0) {
        return retval;
    }

    static bool registered = false;
    if (!registered) {
        registered = true;
        _dyld_register_func_for_add_image(rebind_symbols_for_image);
    }

    uint32_t image_count = _dyld_image_count();
    for (uint32_t i = 0; i < image_count; i++) {
        rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    }
    return 0;
}

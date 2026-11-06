#ifndef WX_FISHHOOK_H
#define WX_FISHHOOK_H

#include <stddef.h>

struct wx_rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

// Rewrites dynamic symbol slots in every loaded image (and every image loaded
// later) so calls through those slots land on `replacement`.  Returns 0 on
// success, -1 if the rebinding table could not be stored.
int wx_rebind_symbols(struct wx_rebinding rebindings[], size_t nel);

#endif

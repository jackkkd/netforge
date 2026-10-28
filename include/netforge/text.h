#ifndef NETFORGE_TEXT_H
#define NETFORGE_TEXT_H
#include <stddef.h>
/* Each callback receives a slice, not a NUL-terminated string. NULL counts only. */
typedef void (*NfTextLine)(const char *text, size_t length, void *context);
size_t nf_text_wrap(const char *text, size_t width, NfTextLine callback, void *context);
#endif

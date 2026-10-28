#ifndef NETFORGE_UTIL_H
#define NETFORGE_UTIL_H
#include <stdbool.h>
#include <stdint.h>
int64_t nf_now_ms(void);
bool nf_parse_unsigned(const char *text, unsigned minimum, unsigned maximum, unsigned *value);
#endif

/* Word wrapping shared by live activity rendering and layout checks. */
#include "netforge/text.h"
#include <string.h>

size_t nf_text_wrap(const char *text, size_t width, NfTextLine callback, void *context)
{
    if (!text || !width) return 0;
    size_t count = 0;
    if (!*text) {
        if (callback) callback(text, 0, context);
        return 1;
    }
    while (*text) {
        const char *end = strchr(text, '\n');
        if (!end) end = text + strlen(text);
        if (end == text) {
            if (callback) callback(text, 0, context);
            ++count;
        }
        while (text < end) {
            size_t remaining = (size_t)(end - text);
            size_t length = remaining < width ? remaining : width;
            if (length < remaining && text[length] != ' ') {
                size_t word = length;
                while (word && text[word] != ' ') --word;
                if (word) length = word;
            }
            if (callback) callback(text, length, context);
            ++count;
            text += length;
            while (text < end && *text == ' ') ++text;
        }
        if (*text == '\n') ++text;
    }
    return count;
}

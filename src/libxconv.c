#include <iconv.h>
#include <string.h>

iconv_t
xconv_open(const char *tocode, const char *fromcode)
{
    if (strcmp(tocode, "UTF-8") == 0 && strcmp(fromcode, "UCS-2") == 0) {
        // Big-endian UTF-16 is a superset of UCS-2 for codepoints in the range
        // 0x0000-0xFFFF. If the input is encoded in UCS-2, decoding with UTF-16
        // produces the same results, but if it's in UTF-16 (BE), then we will
        // also be able to decode those. However, if we pass "UTF-16BE", we get
        // the wrong encoding, so we use "UTF-16" instead and let iconv figure
        // out the byte order.
        fromcode = "UTF-16";
    } else if (strcmp(tocode, "UCS-2") == 0 && strcmp(fromcode, "UTF-8") == 0) {
        // Same as above, but for sending SMS (thanks hedayat and peterleinchen)
        tocode = "UTF-16";
    }

    return iconv_open(tocode, fromcode);
}

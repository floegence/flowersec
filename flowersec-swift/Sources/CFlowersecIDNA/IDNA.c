#include "CFlowersecIDNA.h"
#include <unicode/uidna.h>

// Compile against the platform's public ICU header, including its ABI renaming.
FSECIDNA *FSECIDNAOpen(uint32_t options, int32_t *status) {
    UErrorCode error = (UErrorCode)*status;
    UIDNA *processor = uidna_openUTS46(options, &error);
    *status = (int32_t)error;
    return (FSECIDNA *)processor;
}

void FSECIDNAClose(FSECIDNA *processor) {
    uidna_close((UIDNA *)processor);
}

int32_t FSECIDNAToASCII(const FSECIDNA *processor, const char *source, int32_t length,
                      char *destination, int32_t capacity, uint32_t *errors, int32_t *status) {
    UIDNAInfo info = UIDNA_INFO_INITIALIZER;
    UErrorCode error = (UErrorCode)*status;
    int32_t result = uidna_nameToASCII_UTF8((const UIDNA *)processor, source, length,
                                          destination, capacity, &info, &error);
    *errors = info.errors;
    *status = (int32_t)error;
    return result;
}

int32_t FSECIDNAToUnicode(const FSECIDNA *processor, const char *source, int32_t length,
                        char *destination, int32_t capacity, uint32_t *errors, int32_t *status) {
    UIDNAInfo info = UIDNA_INFO_INITIALIZER;
    UErrorCode error = (UErrorCode)*status;
    int32_t result = uidna_nameToUnicodeUTF8((const UIDNA *)processor, source, length,
                                           destination, capacity, &info, &error);
    *errors = info.errors;
    *status = (int32_t)error;
    return result;
}

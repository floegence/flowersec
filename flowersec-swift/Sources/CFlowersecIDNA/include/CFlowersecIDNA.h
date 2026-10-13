#ifndef FLOWERSEC_IDNA_H
#define FLOWERSEC_IDNA_H
#include <stdint.h>

typedef struct FSECIDNA FSECIDNA;
FSECIDNA *FSECIDNAOpen(uint32_t options, int32_t *status);
void FSECIDNAClose(FSECIDNA *processor);
int32_t FSECIDNAToASCII(const FSECIDNA *processor, const char *source, int32_t length,
                      char *destination, int32_t capacity, uint32_t *errors, int32_t *status);
int32_t FSECIDNAToUnicode(const FSECIDNA *processor, const char *source, int32_t length,
                        char *destination, int32_t capacity, uint32_t *errors, int32_t *status);
#endif

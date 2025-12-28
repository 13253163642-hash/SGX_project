/* Enclave/Enclave.h */
#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>
#include "sgx_tcrypto.h"

#if defined(__cplusplus)
extern "C" {
#endif

void ecall_init();
int ecall_dijkstra_search(const char* start_node, const char* end_node);

#if defined(__cplusplus)
}
#endif

#endif /* _ENCLAVE_H_ */
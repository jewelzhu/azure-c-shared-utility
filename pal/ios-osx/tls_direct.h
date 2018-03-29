// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef TLS_DIRECT_H
#define TLS_DIRECT_H

#ifdef __cplusplus
extern "C" {
#include <cstddef>
#else
#include <stddef.h>
#endif /* __cplusplus */

#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/tlsio.h"
#include "azure_c_shared_utility/umock_c_prod.h"

typedef struct TLS_DIRECT_CONTEXT_TAG* TLS_DIRECT_CONTEXT_HANDLE;

typedef struct TLS_DIRECT_INSTANCE_TAG
{
    // Standard tlsio info
    const char* hostname;
    uint16_t port;
    TLSIO_OPTIONS options;
    // A context for the device-specific functions
    TLS_DIRECT_CONTEXT_HANDLE context;
} TLS_DIRECT_INSTANCE;

typedef struct TLS_DIRECT_INSTANCE_TAG* TLS_DIRECT_INSTANCE_HANDLE;


typedef enum TLS_ASYNC_RESULT_TAG
{
    TLS_ASYNC_RESULT_FAILURE = -1,
    TLS_ASYNC_RESULT_WAITING = 0,
    TLS_ASYNC_RESULT_SUCCESS = 1
} TLS_ASYNC_RESULT;

#define TLS_ASYNC_RW_RESULT_FAILURE -1


// Returns either a TLS_DIRECT_HANDLE or NULL
TLS_DIRECT_CONTEXT_HANDLE tls_direct_create(void);

TLS_ASYNC_RESULT tls_direct_open(TLS_DIRECT_INSTANCE_HANDLE tls_direct_instance);

// Returns 0 for waiting, positive for chars read, or TLS_ASYNC_RW_RESULT_FAILURE
int tls_direct_read(TLS_DIRECT_INSTANCE_HANDLE tls_direct_instance, unsigned char* buffer, uint32_t buffer_size);

// Returns 0 for waiting, positive for chars writted, or TLS_ASYNC_RW_RESULT_FAILURE
int tls_direct_write(TLS_DIRECT_INSTANCE_HANDLE tls_direct_instance, const unsigned char* buffer, uint32_t count);

void tls_direct_close(TLS_DIRECT_INSTANCE_HANDLE tls_direct_instance);

void tls_direct_destroy(TLS_DIRECT_CONTEXT_HANDLE context);




#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* TLS_DIRECT_H */

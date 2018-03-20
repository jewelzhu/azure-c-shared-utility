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

typedef struct TLS_DIRECT_INSTANCE_TAG* TLS_DIRECT_HANDLE;

typedef struct TLS_IO_INSTANCE_TAG
{
    ON_BYTES_RECEIVED on_bytes_received;
    ON_IO_ERROR on_io_error;
    ON_IO_OPEN_COMPLETE on_open_complete;
    void* on_bytes_received_context;
    void* on_io_error_context;
    void* on_open_complete_context;
    TLSIO_STATE tlsio_state;
    CFStringRef hostname;
    uint16_t port;
    bool no_messages_yet_sent;
    CFReadStreamRef sockRead;
    CFWriteStreamRef sockWrite;
    SINGLYLINKEDLIST_HANDLE pending_transmission_list;
    TLSIO_OPTIONS options;
} TLS_IO_INSTANCE;

typedef enum TLS_ASYNC_RESULT_TAG
{
    TLS_ASYNC_RESULT_FAILURE = -1,
    TLS_ASYNC_RESULT_WAITING = 0,
    TLS_ASYNC_RESULT_SUCCESS = 1
} TLS_ASYNC_RESULT;


// Returns either a TLS_DIRECT_HANDLE or NULL
TLS_DIRECT_HANDLE tls_direct_create();



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* TLS_DIRECT_H */

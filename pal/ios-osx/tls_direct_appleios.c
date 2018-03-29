// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "azure_c_shared_utility/xio.h"
#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_c_shared_utility/agenttime.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/tlsio_options.h"
#include "tls_direct.h"

#include <CoreFoundation/CoreFoundation.h>
#include <CoreFoundation/CFError.h>
#include <CFNetwork/CFSocketStream.h>
#include <Security/SecureTransport.h>

typedef struct TLS_DIRECT_CONTEXT_TAG
{
    CFReadStreamRef sockRead;
    CFWriteStreamRef sockWrite;
} TLS_DIRECT_CONTEXT;

// No error checking needed here - handled by the caller
TLS_DIRECT_CONTEXT_HANDLE tls_direct_create()
{
    TLS_DIRECT_CONTEXT_HANDLE result = malloc(sizeof(TLS_DIRECT_CONTEXT));
    if (result != NULL)
    {
        result->sockRead = NULL;
        result->sockWrite = NULL;
    }
    return result;
}


TLS_ASYNC_RESULT tls_direct_open(TLS_DIRECT_INSTANCE_HANDLE tls_direct_instance)
{
    TLS_ASYNC_RESULT result;
    TLS_DIRECT_CONTEXT* context = (TLS_DIRECT_CONTEXT*)tls_direct_instance->context;
    
    CFStringRef hostname;
    // This will pretty much only fail if we run out of memory
    if (NULL == (hostname = CFStringCreateWithCString(NULL, tls_direct_instance->hostname, kCFStringEncodingUTF8)))
    {
        /* Codes_SRS_TLSIO_30_011: [ If any resource allocation fails, tlsio_create shall return NULL. ]*/
        LogError("CFStringCreateWithCString failed");
        tlsio_appleios_destroy(result);
        result = NULL;
    }
    
    CFStreamCreatePairWithSocketToHost(NULL, tls_direct_instance->hostname, tls_direct_instance->port, &context->sockRead, &context->sockWrite);
    if (context->sockRead != NULL && context->sockWrite != NULL)
    {
        if (CFReadStreamSetProperty(tls_direct_instance->sockRead, kCFStreamPropertySSLSettings, kCFStreamSocketSecurityLevelNegotiatedSSL))
        {
            if (CFReadStreamOpen(tls_direct_instance->sockRead) && CFWriteStreamOpen(tls_direct_instance->sockWrite))
            {
                result = TLS_ASYNC_RESULT_SUCCESS;
            }
            else
            {
                CFErrorRef readError = CFReadStreamCopyError(tls_direct_instance->sockRead);
                CFErrorRef writeError = CFWriteStreamCopyError(tls_direct_instance->sockWrite);

                LogInfo("Error opening streams - read error=%d;write error=%d", CFErrorGetCode(readError), CFErrorGetCode(writeError));
                result = TLS_ASYNC_RESULT_FAILURE;
            }
        }
        else
        {
            LogError("Failed to set socket properties");
            result = TLS_ASYNC_RESULT_FAILURE;
        }
    }
    else
    {
        LogError("Unable to create socket pair");
        result = TLS_ASYNC_RESULT_FAILURE;
    }
}


// Returns 0 for waiting, positive for chars read, or TLS_ASYNC_RW_RESULT_FAILURE
// Guaranteed to be in the open state, so no need to check for NULLs
int tls_direct_read(TLS_DIRECT_INSTANCE_HANDLE tls_direct_instance, char* buffer, uint32_t buffer_size)
{
    int rcv_bytes;
    if (CFReadStreamHasBytesAvailable(tls_direct_instance->context->sockRead))
    {
        rcv_bytes = CFReadStreamRead(tls_direct_instance->vsockRead, buffer, (CFIndex)(sizeof(buffer)));
    }
    else
    {
        rcv_bytes = 0;
    }
    return rcv_bytes;
}

// Returns 0 for waiting, positive for chars writted, or TLS_ASYNC_RW_RESULT_FAILURE
int tls_direct_write(TLS_DIRECT_INSTANCE_HANDLE tls_direct_instance, const char* buffer, uint32_t count)
{
    int result;
    // Check to see if the socket will not block
    if (CFWriteStreamCanAcceptBytes(tls_direct_instance->sockWrite))
    {
        result = CFWriteStreamWrite(tls_direct_instance->sockWrite, buffer, pending_message->unsent_size);
        if (result > 0)
        {
        }
        else
        {
            // The write returned non-success. It may be busy, or it may be broken
            CFErrorRef write_error = CFWriteStreamCopyError(tls_direct_instance->sockWrite);
            if (CFErrorGetCode(write_error) != errSSLWouldBlock)
            {
                LogInfo("Hard error from CFWriteStreamWrite: %d", CFErrorGetCode(write_error));
                result = TLS_ASYNC_RW_RESULT_FAILURE;
            }
            else
            {
                // The errSSLWouldBlock is defined as a recoverable error and should just be retried
                LogInfo("errSSLWouldBlock on write");
                result = 0;
            }
        }
    }
    else
    {
        result = 0;
    }

    return result;
}

// No need to check tls_direct_instance for NULL
void tls_direct_close(TLS_DIRECT_INSTANCE_HANDLE tls_direct_instance)
{
    tls_direct_instance->context->tlsio_state = OPENING_WAITING_DNS;
    if (tls_direct_instance->context->sockRead != NULL)
    {
        CFReadStreamClose(tls_direct_instance->context->sockRead);
        CFRelease(tls_direct_instance->context->sockRead);
        tls_direct_instance->context->sockRead = NULL;
    }

    if (tls_direct_instance->context->sockWrite != NULL)
    {
        CFWriteStreamClose(tls_direct_instance->context->sockWrite);
        CFRelease(tls_direct_instance->context->sockWrite);
        tls_direct_instance->context->sockWrite = NULL;
    }
}

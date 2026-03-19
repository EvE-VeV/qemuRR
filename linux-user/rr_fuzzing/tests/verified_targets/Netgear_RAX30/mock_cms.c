#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <stdarg.h>

// Generic CMS Return Code
#define CMSRET_SUCCESS 0

// Mock Handle
void *mock_handle = (void*)0xDEADBEEF;

int cmsMsg_init(int entityId, void **msgHandle) {
    printf("[MOCK] cmsMsg_init called with eid=%d\n", entityId);
    if (msgHandle) *msgHandle = mock_handle;
    return CMSRET_SUCCESS;
}

int cmsMsg_initWithFlags(int entityId, int flags, void **msgHandle) {
    printf("[MOCK] cmsMsg_initWithFlags called with eid=%d flags=0x%x\n", entityId, flags);
    if (msgHandle) *msgHandle = mock_handle;
    return CMSRET_SUCCESS;
}

void cmsMsg_cleanup(void **msgHandle) {
    printf("[MOCK] cmsMsg_cleanup called\n");
}

int cmsMsg_receive(void *msgHandle, void **msgBuf) {
    // printf("[MOCK] cmsMsg_receive called (blocking)\n");
    // Simulate generic keep-alive or silence.
    // Ideally we should block or return no message.
    // If we return error, soap_serverd might exit.
    // Let's sleep and return nothing/timeout behavior if possible, or just standard "no message"
    // For now, let's just return an error to prevent tight loops if it polls, 
    // or block indefinitely if it's a listener. 
    // soap_serverd is single threaded usually? No, flags said MULTIPLE_INSTANCES.
    // But it listens on TCP.
    // Let's allow it to return.
    return 9809; // CMSRET_NO_MESSAGE? Or equivalent.
}

int cmsMsg_send(void *msgHandle, void *msg) {
    printf("[MOCK] cmsMsg_send called!\n");
    // Dump the message content
    // CMS Msg Header is usually:
    // type (4), src (4), dst (4), flags (4), dataLen (4) ...
    // Let's verify the header and dump the data.
    
    if (!msg) return CMSRET_SUCCESS;

    uint32_t *header = (uint32_t*)msg;
    // Assuming 32-bit arch (ARM) header layout
    // Word 0: Type?
    // Word 1: Src?
    // Word 2: Dst?
    // Word 3: Flags?
    // Word 4: DataLen?
    
    // Let's just hexdump the first 256 bytes
    unsigned char *p = (unsigned char*)msg;
    int len = 256; // Limit dump
    printf("--- MESSAGE DUMP ---\n");
    for (int i = 0; i < len; i++) {
        printf("%02x ", p[i]);
        if ((i+1) % 16 == 0) printf("\n");
    }
    printf("\n--------------------\n");
    
    // Check for our payload
    const char *payload_sig = "reboot"; // From our python script
    /* Since msg is void*, strict aliasing doesn't apply to char inspection */
    /* We can search the whole buffer passed, but we don't know the exact size yet. 
       Usually header has size. Let's assume header is valid after init. */
    
    return CMSRET_SUCCESS;
}

int cmsMsg_sendAndGetReply(void *msgHandle, void *msg, void **replyMsg) {
    printf("[MOCK] cmsMsg_sendAndGetReply called!\n");
    cmsMsg_send(msgHandle, msg);
    // Return a dummy reply?
    if (replyMsg) *replyMsg = NULL; 
    return CMSRET_SUCCESS;
}

// Add other missing symbols if linker complains or runtime error occurs
// nm -D soap_serverd showed:
// cmsMsg_sendAndGetReplyWithTimeout
// cmsLog_initWithName
// log_log

void cmsLog_initWithName(int eid, char *name) {
    printf("[MOCK] cmsLog_initWithName: %s\n", name);
}

void log_log(int level, char *func, int line, char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("[LOG] %s:%d - ", func, line);
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

// cmsLck_* are also used
int cmsLck_acquireLockWithTimeoutTraced(const char *func, int line, int timeout) {
    // printf("[MOCK] Lock Acquire %s:%d\n", func, line);
    return CMSRET_SUCCESS;
}
void cmsLck_releaseLockTraced(const char *func, int line) {
    // printf("[MOCK] Lock Release %s:%d\n", func, line);
}
void cmsLck_dumpInfo() {}

// cmsMdm_*
int cmsMdm_initWithAcc(int eid, int acc, void *msgHandle, int *shmId) {
    printf("[MOCK] cmsMdm_initWithAcc called\n");
    if (shmId) *shmId = 1234;
    return CMSRET_SUCCESS;
}
void cmsMdm_cleanup() {}

// cmsObj_*
void cmsObj_free(void **obj) {}
int cmsObj_get(int oid, void *iidStack, int flags, void **obj) {
    printf("[MOCK] cmsObj_get called with oid=%d\n", oid);
    if (oid == 3120) {
        // MDM_VS_LOGIN_CFG or similar
        static char buffer[512];
        memset(buffer, 0, 512); // Ensure clean start
        strcpy(buffer, "admin");
        strcpy(buffer + 64, "password"); // Guess offset
        strcpy(buffer + 128, "password");
        strcpy(buffer + 256, "password");
        if (obj) *obj = buffer;
        return CMSRET_SUCCESS;
    }
    return 9002; // INTERNAL_ERROR
}

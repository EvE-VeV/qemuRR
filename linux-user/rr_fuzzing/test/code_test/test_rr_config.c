/*
 * Simple test to verify RR-Fuzz configuration system
 */
#include <stdio.h>
#include <stdlib.h>

int main() {
    // Test environment variables for configuration
    setenv("RR_FUZZING_ENABLED", "1", 1);
    setenv("RR_MODE", "record", 1);
    setenv("RR_CONFIG_FILE", "/tmp/claude/rr_test_config.conf", 1);
    setenv("RR_DEBUG_LEVEL", "verbose", 1);
    setenv("RR_DEBUG_SYSCALL", "true", 1);

    printf("Environment variables set for RR-Fuzz testing:\n");
    printf("RR_FUZZING_ENABLED=%s\n", getenv("RR_FUZZING_ENABLED"));
    printf("RR_MODE=%s\n", getenv("RR_MODE"));
    printf("RR_CONFIG_FILE=%s\n", getenv("RR_CONFIG_FILE"));
    printf("RR_DEBUG_LEVEL=%s\n", getenv("RR_DEBUG_LEVEL"));
    printf("RR_DEBUG_SYSCALL=%s\n", getenv("RR_DEBUG_SYSCALL"));

    return 0;
}
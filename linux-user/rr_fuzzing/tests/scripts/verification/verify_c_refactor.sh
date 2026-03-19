#!/bin/bash
# End-to-end verification of RR-Fuzz C-side refactor
set -e

# Paths
PROJECT_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
QEMU_BIN="/home/webfuzz/Documents/qemu/build/qemu-x86_64"
WORK_DIR="/tmp/rr_refactor_test"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}=== Starting RR-Fuzz C-Side Refactor Verification ===${NC}"

# 1. Cleanup
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

# 2. Compile Target
echo -e "${BLUE}[1/4] Compiling test target...${NC}"
cat > "$WORK_DIR/target.c" <<EOF
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main() {
    char buf[64];
    printf("Enter input: ");
    fflush(stdout);
    if (read(0, buf, 64) > 0) {
        printf("Received: %s\n", buf);
        if (strncmp(buf, "CORRECT", 7) == 0) {
            printf("Success path reached!\n");
        }
    }
    return 0;
}
EOF
gcc "$WORK_DIR/target.c" -o "$WORK_DIR/target"
echo -e "${GREEN}Target compiled successfully.${NC}"

# 3. Record Trace
echo -e "${BLUE}[2/4] Recording initial trace...${NC}"
echo "CORRECT" | RR_MODE=record RR_TRACE_FILE="$WORK_DIR/seed.trace" \
    "$QEMU_BIN" "$WORK_DIR/target" > "$WORK_DIR/record.log" 2>&1

if [ -f "$WORK_DIR/seed.trace" ]; then
    echo -e "${GREEN}Trace recorded: $(ls -lh "$WORK_DIR/seed.trace" | awk '{print $5}')${NC}"
else
    echo -e "${RED}Trace recording failed!${NC}"
    cat "$WORK_DIR/record.log"
    exit 1
fi

# 4. Replay Trace
echo -e "${BLUE}[3/4] Verifying deterministic replay...${NC}"
RR_MODE=replay RR_TRACE_FILE="$WORK_DIR/seed.trace" \
    "$QEMU_BIN" "$WORK_DIR/target" > "$WORK_DIR/replay.log" 2>&1

if grep -q "Success path reached!" "$WORK_DIR/replay.log"; then
    echo -e "${GREEN}Deterministic replay verified.${NC}"
else
    echo -e "${RED}Deterministic replay failed!${NC}"
    cat "$WORK_DIR/replay.log"
    exit 1
fi

# 5. Brief Fuzzing (C-Python Integration)
echo -e "${BLUE}[4/4] Verifying C-Python integration via fuzz_main.py...${NC}"
cd "$PROJECT_ROOT"
# Run fuzzing for only 5 iterations to check integration
python3 fuzzing/fuzz_main.py \
    --qemu "$QEMU_BIN" \
    --target "$WORK_DIR/target" \
    --trace "$WORK_DIR/seed.trace" \
    --output "$WORK_DIR/fuzz_out" \
    --iterations 5 > "$WORK_DIR/fuzz.log" 2>&1 || true

if [ -d "$WORK_DIR/fuzz_out" ] && [ "$(ls -A "$WORK_DIR/fuzz_out" 2>/dev/null)" ]; then
    echo -e "${GREEN}Fuzzing interaction verified.${NC}"
else
    echo -e "${RED}Fuzzing integration failed!${NC}"
    cat "$WORK_DIR/fuzz.log"
    exit 1
fi

echo -e "${GREEN}=== All Verifications Passed! ===${NC}"

# RR-Fuzz模块Makefile
# 用于构建RR-Fuzz相关的目标文件

# 编译器和标志
CC := gcc
CFLAGS := -Wall -Wextra -O2 -g -std=gnu99
CFLAGS += -I./include -I.. -I.
CFLAGS += $(shell pkg-config --cflags glib-2.0)
LDFLAGS += $(shell pkg-config --libs glib-2.0)

# 定义RR_DEBUG以启用调试日志
CFLAGS += -DRR_DEBUG

# 源文件
SOURCES := src/core/rr_main.c src/engine/rr_record.c src/engine/rr_replay.c src/runtime/rr_ipc.c src/runtime/rr_fork_server.c src/engine/rr_fuzz_engine.c src/runtime/rr_snapshot.c
OBJECTS := $(SOURCES:.c=.o)
HEADERS := include/rr_framework.h

# 目标：编译所有对象文件
all: $(OBJECTS)

# 模式规则：编译.c文件到.o文件
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# 清理目标文件
clean:
	rm -f $(OBJECTS)

# 安装目标（复制头文件到include目录）
install: $(HEADERS)
	mkdir -p ../../include/fuzzing
	cp $(HEADERS) ../../include/fuzzing/

# 帮助信息
help:
	@echo "RR-Fuzz Build System"
	@echo "Available targets:"
	@echo "  all     - Build all object files"
	@echo "  clean   - Remove all object files"
	@echo "  install - Install headers to include directory"
	@echo "  help    - Show this help message"

# 检查依赖
check-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists glib-2.0 || (echo "Error: glib-2.0 not found" && exit 1)
	@echo "All dependencies satisfied"

.PHONY: all clean install help check-deps
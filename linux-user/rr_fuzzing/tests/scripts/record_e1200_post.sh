#!/bin/bash
# 录制 E1200 httpd 处理 POST /apply.cgi 的 trace
# 产出: tests/seeds/Linksys_E1200_post.trace
#
# 认证: admin:admin (Basic YWRtaW46YWRtaW4=)
# POST body: apply.cgi 典型参数 (Routing action)
# auth_boundary = trace 中 accept() 的 syscall index (录完后用 trace_analyzer 查)

set -e

SIM="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
BUILD="/home/webfuzz/Documents/qemu/build"
ROOTFS="$SIM/tests/images/Linksys/rootfs"
QEMU="$BUILD/qemu-mipsel"
HTTPD="$ROOTFS/usr/sbin/httpd"
PORT=8094   # 用不同端口避免与运行中的 e1200 campaign 冲突
TRACE_OUT="$SIM/tests/seeds/Linksys_E1200_post.trace"

# 环境准备
mkdir -p /tmp/run_post
export QEMU_LD_PREFIX="$ROOTFS"

echo "[*] 清理旧 trace..."
rm -f "$TRACE_OUT"

echo "[*] 启动 httpd (record mode, port=$PORT)..."
RR_MODE=record \
RR_TRACE_FILE="$TRACE_OUT" \
"$QEMU" -L "$ROOTFS" "$HTTPD" -p $PORT &
HTTPD_PID=$!

# 等待 httpd 启动
sleep 2

echo "[*] 检查 httpd 是否在监听..."
for i in $(seq 1 10); do
    if nc -z 127.0.0.1 $PORT 2>/dev/null; then
        echo "[*] httpd ready (attempt $i)"
        break
    fi
    sleep 1
done

echo "[*] 发送 POST /apply.cgi..."
curl -s -o /tmp/post_response.txt \
    -X POST "http://127.0.0.1:$PORT/apply.cgi" \
    -H "Authorization: Basic YWRtaW46YWRtaW4=" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Referer: http://127.0.0.1:$PORT/index.asp" \
    --data "submit_button=Routing&action=Apply&change_action=&next_page=Routing.asp&need_reboot=0&bg_static_route_num=0&route_if_0=0&route_if_1=0" \
    --connect-timeout 5 \
    --max-time 8 \
    || true

echo "[*] 响应 (前200字节):"
head -c 200 /tmp/post_response.txt 2>/dev/null || echo "(无响应)"

sleep 1

echo "[*] 停止 httpd (PID=$HTTPD_PID)..."
kill -TERM $HTTPD_PID 2>/dev/null || true
wait $HTTPD_PID 2>/dev/null || true

if [ -f "$TRACE_OUT" ]; then
    SIZE=$(stat -c%s "$TRACE_OUT")
    echo "[+] Trace 录制完成: $TRACE_OUT ($SIZE bytes)"
    echo ""
    echo "下一步: 用 TraceAnalyzer 查找 accept() 的 syscall index 作为 auth_boundary"
    echo "  python3 -c \""
    echo "  import sys; sys.path.insert(0,'fuzzing')"
    echo "  from conductor.trace_analyzer import TraceAnalyzer"
    echo "  a = TraceAnalyzer('$TRACE_OUT'); a.analyze()"
    echo "  for i,sc in enumerate(a.syscalls):"
    echo "    if 'accept' in str(getattr(sc,'name','')).lower(): print(i, sc.name)"
    echo "  \""
else
    echo "[-] Trace 未生成，检查 httpd 启动是否成功"
    exit 1
fi

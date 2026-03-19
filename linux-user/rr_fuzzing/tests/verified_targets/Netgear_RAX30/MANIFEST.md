# Netgear RAX30 Verified Archive

## 1. Execution Environment
- **Script**: `run.sh`
- **RootFS**: `./rootfs`
- **Architecture**: ARMv7 Little Endian
- **Config**: `fuzz_lighttpd.conf` (Custom configuration for fuzzing)

## 2. Source Code & Mocks
- **`src/libnvram_mock.c`**: Mock implementation of NVRAM functions.
- **`lib/libwlsysutil.so`**: Extracted library dependency.
- **`lib/libcms_mock.so`**: Extracted/Mocked CMS library.

## 3. Verification Artifacts
- **Logs**: `artifacts/httpd.log`
- **Trace**: `artifacts/rax30_init.txt` (RR Recording)
- **Port**: 8082 (HTTP)

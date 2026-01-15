import os
import subprocess
import time
import argparse
import sys
import signal

class TargetRecorder:
    def __init__(self, qemu_path, target_path, trace_path, args="", env=None):
        self.qemu_path = qemu_path
        self.target_path = target_path
        self.trace_path = trace_path
        self.args = args
        self.env = env or os.environ.copy()
        self.process = None

    def start_recording(self):
        cmd = [self.qemu_path, self.target_path]
        if self.args:
            cmd.extend(self.args.split())
        
        self.env["RR_MODE"] = "RECORD"
        self.env["RR_TRACE_FILE"] = self.trace_path
        
        print(f"[Recorder] Starting: {' '.join(cmd)}")
        print(f"[Recorder] Trace: {self.trace_path}")
        
        self.process = subprocess.Popen(
            cmd,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid
        )
        # Give it a moment to bind to ports
        time.sleep(2)
        return self.process

    def stop_recording(self):
        if self.process:
            print("[Recorder] Stopping target...")
            os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
            print("[Recorder] Stopped.")

def main():
    parser = argparse.ArgumentParser(description="Automated Target Recording Utility")
    parser.add_argument("--qemu", required=True, help="Path to qemu-x86_64")
    parser.add_argument("--target", required=True, help="Path to target binary")
    parser.add_argument("--trace", required=True, help="Output trace file path")
    parser.add_argument("--args", default="", help="Target arguments")
    parser.add_argument("--script", required=True, help="Path to interaction script (Python)")
    parser.add_argument("--script-args", default="", help="Arguments for interaction script")

    args = parser.parse_args()

    recorder = TargetRecorder(args.qemu, args.target, args.trace, args.args)
    
    try:
        recorder.start_recording()
        
        print(f"[Recorder] Running interaction script: {args.script}")
        script_cmd = [sys.executable, args.script]
        if args.script_args:
            script_cmd.extend(args.script_args.split())
        
        result = subprocess.run(script_cmd)
        
        if result.returncode == 0:
            print("[Recorder] Interaction script completed successfully.")
        else:
            print(f"[Recorder] Interaction script failed with code {result.returncode}")
            
    finally:
        recorder.stop_recording()
        print(f"[Recorder] Recording session finished. Trace saved to {args.trace}")

if __name__ == "__main__":
    main()

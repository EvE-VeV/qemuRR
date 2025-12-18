
import threading
import queue
import sys
import time
from datetime import datetime
from pathlib import Path

class AsyncLogger:
    """
    High-performance Asynchronous Logger
    
    Decouples logging I/O from the main execution thread using a background worker.
    This prevents print() calls from blocking the fuzzing loop (which can take ms).
    
    Usage:
        logger = AsyncLogger(log_file="fuzzing.log")
        logger.start()
        logger.log("High frequency message")
        ...
        logger.stop()
    """
    
    _instance = None
    
    def __init__(self, log_file: str = None, console: bool = True):
        self.log_queue = queue.SimpleQueue()
        self.running = False
        self.worker_thread = None
        self.log_file = log_file
        self.console = console
        self.file_handle = None
        
        # Singleton pattern support (optional)
        AsyncLogger._instance = self

    @classmethod
    def get_instance(cls):
        return cls._instance

    def start(self):
        """Start the background logging thread"""
        if self.running:
            return
            
        if self.log_file:
            try:
                path = Path(self.log_file)
                path.parent.mkdir(parents=True, exist_ok=True)
                self.file_handle = open(self.log_file, 'a', encoding='utf-8')
            except Exception as e:
                print(f"[AsyncLogger] Failed to open log file: {e}")
        
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="AsyncLogger")
        self.worker_thread.start()
        print(f"[AsyncLogger] Started (file={self.log_file}, console={self.console})")

    def stop(self):
        """Stop the logger and flush remaining messages"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=2.0)
        
        if self.file_handle:
            self.file_handle.flush()
            self.file_handle.close()
            self.file_handle = None

    def log(self, msg: str, tag: str = None, force: bool = False):
        """
        Log a message asynchronously.
        
        Args:
            msg: Message content
            tag: Optional tag prefix (e.g., "[DEBUG]")
            force: If True, flush immediately (synchronous) - use sparingly!
        """
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        formatted_msg = f"[{timestamp}] {tag} {msg}" if tag else f"[{timestamp}] {msg}"
        
        if force:
            # Synchronous path for critical errors or shutdown
            self._write(formatted_msg)
        else:
            # Fast path: just push to queue
            self.log_queue.put(formatted_msg)

    def _worker_loop(self):
        """Background worker to consume log queue"""
        while self.running or not self.log_queue.empty():
            try:
                # Block with timeout to check self.running periodically
                msg = self.log_queue.get(timeout=0.2)
                self._write(msg)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Logger error: {e}")

    def _write(self, msg):
        """Actual I/O operation"""
        try:
            if self.console:
                sys.stdout.write(msg + '\n')
                # sys.stdout.flush() # Let OS buffer stdout for speed
                
            if self.file_handle:
                self.file_handle.write(msg + '\n')
                self.file_handle.flush() # Flush execution logs to file safer
        except Exception:
            pass

# Global convenience method
def alog(msg, tag=None):
    if AsyncLogger._instance:
        AsyncLogger._instance.log(msg, tag)
    else:
        # Fallback if not initialized
        print(f"[FALLBACK] {tag or ''} {msg}")

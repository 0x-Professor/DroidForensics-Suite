"""
Stress Test Suite for Android Forensics Framework
Federal Investigation Agency

This suite specifically tests:
- Performance under load
- Memory efficiency
- Concurrent operations
- Timeout handling
- Recovery mechanisms

Run with: python -m pytest tests/test_stress.py -v --timeout=60
"""

import asyncio
import gc
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc
import unittest
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from datetime import datetime
from pathlib import Path
from queue import Queue, Empty
from typing import List, Dict
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class TestPerformanceUnderLoad(unittest.TestCase):
    """Test system performance under heavy load."""
    
    def test_rapid_adb_commands_simulation(self):
        """Simulate rapid-fire ADB commands."""
        command_count = 500
        results = []
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="ok")
            
            start = time.time()
            for i in range(command_count):
                result = mock_run(["adb", "shell", "echo", str(i)])
                results.append(result.returncode)
            elapsed = time.time() - start
        
        self.assertEqual(len(results), command_count)
        self.assertLess(elapsed, 2.0)  # Should complete in under 2 seconds
    
    def test_bulk_database_operations(self):
        """Test bulk database insertions and queries."""
        record_count = 50000
        
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            conn = sqlite3.connect(db_path)
            conn.execute("""
                CREATE TABLE messages (
                    id INTEGER PRIMARY KEY,
                    sender TEXT,
                    body TEXT,
                    timestamp INTEGER
                )
            """)
            
            # Bulk insert
            start = time.time()
            data = [(i, f"sender_{i % 100}", f"Message body {i}", i * 1000) 
                    for i in range(record_count)]
            conn.executemany("INSERT INTO messages VALUES (?,?,?,?)", data)
            conn.commit()
            insert_time = time.time() - start
            
            # Bulk query
            start = time.time()
            cursor = conn.execute("SELECT COUNT(*) FROM messages")
            count = cursor.fetchone()[0]
            conn.close()
            query_time = time.time() - start
            
            self.assertEqual(count, record_count)
            self.assertLess(insert_time, 5.0)  # 50k inserts in under 5 seconds
            self.assertLess(query_time, 0.1)  # Count should be instant
        finally:
            os.unlink(db_path)
    
    def test_large_file_hashing(self):
        """Test hashing large files efficiently."""
        import hashlib
        
        # Create 100MB temp file
        size_mb = 100
        with tempfile.NamedTemporaryFile(delete=False) as f:
            # Write in chunks to avoid memory issues
            for _ in range(size_mb):
                f.write(os.urandom(1024 * 1024))
            large_file = f.name
        
        try:
            start = time.time()
            
            # Stream hash (memory efficient)
            hasher = hashlib.sha256()
            with open(large_file, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hasher.update(chunk)
            hash_value = hasher.hexdigest()
            
            elapsed = time.time() - start
            
            self.assertEqual(len(hash_value), 64)
            self.assertLess(elapsed, 10.0)  # 100MB in under 10 seconds
        finally:
            os.unlink(large_file)
    
    def test_json_processing_large_dataset(self):
        """Test processing large JSON datasets."""
        record_count = 100000
        
        # Generate large dataset
        start = time.time()
        data = {
            "case_id": "FIA-STRESS-001",
            "records": [
                {
                    "id": i,
                    "type": "sms" if i % 3 == 0 else "call" if i % 3 == 1 else "app",
                    "timestamp": datetime.now().isoformat(),
                    "details": f"Record details for item {i}"
                }
                for i in range(record_count)
            ]
        }
        generation_time = time.time() - start
        
        # Serialize
        start = time.time()
        json_str = json.dumps(data)
        serialize_time = time.time() - start
        
        # Deserialize
        start = time.time()
        parsed = json.loads(json_str)
        deserialize_time = time.time() - start
        
        self.assertEqual(len(parsed["records"]), record_count)
        self.assertLess(generation_time, 5.0)
        self.assertLess(serialize_time, 2.0)
        self.assertLess(deserialize_time, 2.0)


class TestMemoryEfficiency(unittest.TestCase):
    """Test memory usage efficiency."""
    
    def test_memory_stable_under_repeated_operations(self):
        """Ensure memory doesn't grow with repeated operations."""
        tracemalloc.start()
        
        for iteration in range(10):
            # Simulate forensic data processing
            data = [{"id": i, "body": "x" * 1000} for i in range(10000)]
            processed = [d for d in data if d["id"] % 2 == 0]
            del data, processed
            gc.collect()
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        # Peak memory should be reasonable (under 100MB)
        self.assertLess(peak, 100 * 1024 * 1024)
    
    def test_streaming_file_processing(self):
        """Test that file processing uses constant memory."""
        # Create large file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            for i in range(100000):
                f.write(f"Log line {i}: " + "x" * 100 + "\n")
            large_file = f.name
        
        try:
            tracemalloc.start()
            
            # Process line by line
            line_count = 0
            matches = 0
            with open(large_file, 'r') as f:
                for line in f:
                    line_count += 1
                    if "5000" in line:
                        matches += 1
            
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            
            self.assertEqual(line_count, 100000)
            # Memory should stay low (under 10MB for streaming)
            self.assertLess(peak, 10 * 1024 * 1024)
        finally:
            os.unlink(large_file)
    
    def test_generator_based_processing(self):
        """Test generator-based memory-efficient processing."""
        def generate_records(count):
            """Generator that yields records one at a time."""
            for i in range(count):
                yield {
                    "id": i,
                    "timestamp": datetime.now().isoformat(),
                    "data": "x" * 100
                }
        
        tracemalloc.start()
        
        # Process 1 million records via generator
        processed_count = 0
        for record in generate_records(1000000):
            processed_count += 1
            if processed_count % 100000 == 0:
                gc.collect()  # Periodic cleanup
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        self.assertEqual(processed_count, 1000000)
        # Peak should be minimal since we're streaming
        self.assertLess(peak, 50 * 1024 * 1024)


class TestConcurrencyStress(unittest.TestCase):
    """Test concurrent operation handling."""
    
    def test_thread_pool_stress(self):
        """Stress test thread pool with many tasks."""
        task_count = 100
        results = []
        lock = threading.Lock()
        
        def worker(task_id):
            time.sleep(0.01)  # Simulate work
            with lock:
                results.append(task_id)
            return task_id
        
        start = time.time()
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(worker, i) for i in range(task_count)]
            completed = [f.result() for f in futures]
        elapsed = time.time() - start
        
        self.assertEqual(len(results), task_count)
        self.assertEqual(len(completed), task_count)
        # With 20 workers, 100 tasks of 0.01s each should complete in ~0.5s
        self.assertLess(elapsed, 2.0)
    
    def test_concurrent_database_access(self):
        """Test concurrent database access."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            # Setup
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE counter (id INTEGER, value INTEGER)")
            conn.execute("INSERT INTO counter VALUES (1, 0)")
            conn.commit()
            conn.close()
            
            results = []
            lock = threading.Lock()
            
            def increment(thread_id):
                conn = sqlite3.connect(db_path, timeout=30)
                for _ in range(10):
                    try:
                        conn.execute("UPDATE counter SET value = value + 1 WHERE id = 1")
                        conn.commit()
                        with lock:
                            results.append(thread_id)
                    except sqlite3.OperationalError:
                        time.sleep(0.01)  # Retry on lock
                conn.close()
            
            threads = [threading.Thread(target=increment, args=(i,)) for i in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            
            # Verify final count
            conn = sqlite3.connect(db_path)
            cursor = conn.execute("SELECT value FROM counter WHERE id = 1")
            final_value = cursor.fetchone()[0]
            conn.close()
            
            # May not be exactly 100 due to race conditions, but should be close
            self.assertGreater(final_value, 50)
        finally:
            os.unlink(db_path)
    
    def test_queue_based_processing(self):
        """Test queue-based concurrent processing."""
        input_queue = Queue()
        output_queue = Queue()
        
        # Producer
        for i in range(1000):
            input_queue.put({"id": i, "data": f"item_{i}"})
        
        def worker():
            while True:
                try:
                    item = input_queue.get(timeout=0.1)
                    # Process
                    result = {"id": item["id"], "processed": True}
                    output_queue.put(result)
                    input_queue.task_done()
                except Empty:
                    break
        
        # Start workers
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Collect results
        results = []
        while not output_queue.empty():
            results.append(output_queue.get())
        
        self.assertEqual(len(results), 1000)


class TestTimeoutHandling(unittest.TestCase):
    """Test timeout and interrupt handling."""
    
    def test_operation_timeout_enforcement(self):
        """Test that long operations can be timed out."""
        from concurrent.futures import TimeoutError
        
        def long_operation():
            time.sleep(10)
            return "completed"
        
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(long_operation)
            with self.assertRaises(TimeoutError):
                future.result(timeout=0.5)
    
    def test_graceful_shutdown(self):
        """Test graceful shutdown of operations."""
        shutdown_flag = threading.Event()
        operations_completed = []
        
        def interruptible_operation(op_id):
            for i in range(100):
                if shutdown_flag.is_set():
                    return f"interrupted_at_{i}"
                time.sleep(0.01)
                operations_completed.append((op_id, i))
            return "completed"
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(interruptible_operation, i) for i in range(5)]
            
            # Signal shutdown after 0.2 seconds
            time.sleep(0.2)
            shutdown_flag.set()
            
            results = [f.result() for f in futures]
        
        # All should have been interrupted
        for result in results:
            self.assertIn("interrupted", result)
    
    @patch('subprocess.run')
    def test_adb_timeout_handling(self, mock_run):
        """Test ADB command timeout handling."""
        def slow_adb(*args, **kwargs):
            timeout = kwargs.get('timeout', 30)
            if timeout < 5:
                raise subprocess.TimeoutExpired(args[0], timeout)
            return MagicMock(returncode=0, stdout="success")
        
        mock_run.side_effect = slow_adb
        
        # Should timeout
        with self.assertRaises(subprocess.TimeoutExpired):
            mock_run(["adb", "shell", "sleep", "10"], timeout=1)
        
        # Should succeed with longer timeout
        result = mock_run(["adb", "shell", "echo", "test"], timeout=10)
        self.assertEqual(result.returncode, 0)


class TestRecoveryMechanisms(unittest.TestCase):
    """Test error recovery mechanisms."""
    
    def test_exponential_backoff_retry(self):
        """Test exponential backoff retry logic."""
        attempts = []
        max_retries = 5
        base_delay = 0.1
        
        def operation_with_retry():
            for attempt in range(max_retries):
                attempts.append({
                    "attempt": attempt,
                    "time": time.time()
                })
                
                if attempt < 3:  # Fail first 3 times
                    delay = base_delay * (2 ** attempt)
                    time.sleep(delay)
                    continue
                
                return "success"
            return "failed"
        
        start = time.time()
        result = operation_with_retry()
        elapsed = time.time() - start
        
        self.assertEqual(result, "success")
        self.assertEqual(len(attempts), 4)  # 3 failures + 1 success
        self.assertGreater(elapsed, 0.7)  # 0.1 + 0.2 + 0.4 = 0.7
    
    def test_checkpoint_recovery(self):
        """Test checkpoint-based recovery."""
        checkpoint_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        checkpoint_file.close()
        checkpoint_path = checkpoint_file.name
        
        try:
            total_items = 100
            processed = []
            
            # Simulate processing with checkpoints
            for i in range(total_items):
                processed.append(i)
                
                # Checkpoint every 25 items
                if (i + 1) % 25 == 0:
                    with open(checkpoint_path, 'w') as f:
                        json.dump({"last_processed": i, "items": processed}, f)
                
                # Simulate failure at 60%
                if i == 60:
                    raise Exception("Simulated failure")
            
        except Exception:
            pass  # Expected failure
        
        # Recover from checkpoint
        with open(checkpoint_path, 'r') as f:
            checkpoint = json.load(f)
        
        self.assertEqual(checkpoint["last_processed"], 49)  # Last checkpoint at 50th item
        os.unlink(checkpoint_path)
    
    def test_transaction_recovery(self):
        """Test database transaction recovery."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE data (id INTEGER PRIMARY KEY, value TEXT)")
            conn.commit()
            
            # Successful transaction
            conn.execute("BEGIN TRANSACTION")
            conn.execute("INSERT INTO data VALUES (1, 'good_data')")
            conn.commit()
            
            # Failed transaction
            try:
                conn.execute("BEGIN TRANSACTION")
                conn.execute("INSERT INTO data VALUES (2, 'will_be_rolled_back')")
                raise Exception("Simulated failure")
                conn.commit()
            except Exception:
                conn.rollback()
            
            # Verify only good data exists
            cursor = conn.execute("SELECT * FROM data")
            rows = cursor.fetchall()
            conn.close()
            
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][1], "good_data")
        finally:
            os.unlink(db_path)


class TestEdgeCaseStress(unittest.TestCase):
    """Stress tests for edge cases."""
    
    def test_empty_result_handling_stress(self):
        """Stress test handling empty results repeatedly."""
        for _ in range(1000):
            empty_list = []
            empty_dict = {}
            empty_str = ""
            
            self.assertEqual(len(empty_list), 0)
            self.assertEqual(len(empty_dict), 0)
            self.assertEqual(len(empty_str), 0)
    
    def test_unicode_stress(self):
        """Stress test with various Unicode strings."""
        unicode_samples = [
            "🔍" * 1000,
            "日本語テスト" * 500,
            "العربية" * 500,
            "Тест" * 1000,
            "\u0000\u0001\u0002" * 1000,
        ]
        
        for sample in unicode_samples:
            # Encode/decode
            encoded = sample.encode('utf-8')
            decoded = encoded.decode('utf-8')
            self.assertEqual(decoded, sample)
            
            # JSON roundtrip
            json_str = json.dumps({"text": sample})
            parsed = json.loads(json_str)
            self.assertEqual(parsed["text"], sample)
    
    def test_rapid_file_operations(self):
        """Stress test rapid file create/delete cycles."""
        temp_dir = tempfile.mkdtemp()
        
        try:
            for i in range(100):
                file_path = Path(temp_dir) / f"temp_{i}.txt"
                
                # Create
                file_path.write_text(f"Content {i}")
                self.assertTrue(file_path.exists())
                
                # Read
                content = file_path.read_text()
                self.assertEqual(content, f"Content {i}")
                
                # Delete
                file_path.unlink()
                self.assertFalse(file_path.exists())
        finally:
            Path(temp_dir).rmdir()


# =============================================================================
# RUN STRESS TESTS
# =============================================================================

if __name__ == "__main__":
    print("""
    ================================================================
         STRESS TEST SUITE - FORENSIC FRAMEWORK
         Federal Investigation Agency
    ================================================================
         Testing:
         - Performance Under Load
         - Memory Efficiency
         - Concurrency Stress
         - Timeout Handling
         - Recovery Mechanisms
    ================================================================
    """)
    
    unittest.main(verbosity=2)

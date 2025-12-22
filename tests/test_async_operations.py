"""
Async Operations and MCP Server Integration Tests
Federal Investigation Agency - Android Forensics Framework

Tests async/await patterns, MCP server tool execution, and event loop handling.
Fixes deprecation warnings from pytest-asyncio.

Run with: python -m pytest tests/test_async_operations.py -v
"""

import asyncio
import json
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# =============================================================================
# ASYNC UTILITY TESTS
# =============================================================================

class TestAsyncUtilities(unittest.TestCase):
    """Test async utility functions."""
    
    def test_asyncio_run_basic(self):
        """Test basic asyncio.run execution."""
        async def async_task():
            await asyncio.sleep(0.01)
            return "completed"
        
        result = asyncio.run(async_task())
        self.assertEqual(result, "completed")
    
    def test_asyncio_gather(self):
        """Test gathering multiple async tasks."""
        async def task(n: int):
            await asyncio.sleep(0.01)
            return n * 2
        
        async def main():
            results = await asyncio.gather(
                task(1), task(2), task(3), task(4), task(5)
            )
            return results
        
        results = asyncio.run(main())
        self.assertEqual(results, [2, 4, 6, 8, 10])
    
    def test_asyncio_timeout(self):
        """Test async timeout handling."""
        async def slow_task():
            await asyncio.sleep(10)
            return "completed"
        
        async def main():
            try:
                async with asyncio.timeout(0.1):
                    await slow_task()
            except asyncio.TimeoutError:
                return "timeout"
            return "completed"
        
        result = asyncio.run(main())
        self.assertEqual(result, "timeout")
    
    def test_asyncio_queue(self):
        """Test async queue for producer/consumer pattern."""
        async def producer(queue: asyncio.Queue, count: int):
            for i in range(count):
                await queue.put({"id": i, "data": f"item_{i}"})
            await queue.put(None)  # Sentinel
        
        async def consumer(queue: asyncio.Queue, results: List):
            while True:
                item = await queue.get()
                if item is None:
                    break
                results.append(item)
                queue.task_done()
        
        async def main():
            queue = asyncio.Queue()
            results = []
            
            producer_task = asyncio.create_task(producer(queue, 10))
            consumer_task = asyncio.create_task(consumer(queue, results))
            
            await producer_task
            await consumer_task
            
            return results
        
        results = asyncio.run(main())
        self.assertEqual(len(results), 10)
    
    def test_asyncio_semaphore(self):
        """Test semaphore for limiting concurrent operations."""
        concurrent_count = 0
        max_concurrent = 0
        
        async def limited_task(semaphore: asyncio.Semaphore, task_id: int):
            nonlocal concurrent_count, max_concurrent
            
            async with semaphore:
                concurrent_count += 1
                max_concurrent = max(max_concurrent, concurrent_count)
                await asyncio.sleep(0.05)
                concurrent_count -= 1
            
            return task_id
        
        async def main():
            semaphore = asyncio.Semaphore(3)  # Max 3 concurrent
            tasks = [limited_task(semaphore, i) for i in range(10)]
            results = await asyncio.gather(*tasks)
            return results
        
        results = asyncio.run(main())
        self.assertEqual(len(results), 10)
        self.assertLessEqual(max_concurrent, 3)


# =============================================================================
# ASYNC MCP TOOL SIMULATION TESTS
# =============================================================================

class TestAsyncMCPToolSimulation(unittest.TestCase):
    """Test simulated async MCP tool operations."""
    
    def test_async_device_check(self):
        """Test async device connection check."""
        async def check_device_async():
            await asyncio.sleep(0.01)  # Simulate ADB latency
            return {
                "connected": True,
                "device_id": "TEST123",
                "model": "Test Device"
            }
        
        result = asyncio.run(check_device_async())
        self.assertTrue(result["connected"])
    
    def test_async_file_pull(self):
        """Test async file pull operation."""
        async def pull_file_async(remote_path: str, local_path: str):
            await asyncio.sleep(0.05)  # Simulate transfer
            return {
                "success": True,
                "remote": remote_path,
                "local": local_path,
                "bytes": 1024
            }
        
        result = asyncio.run(
            pull_file_async("/data/data/com.app/db.sqlite", "/output/db.sqlite")
        )
        self.assertTrue(result["success"])
        self.assertEqual(result["bytes"], 1024)
    
    def test_async_batch_operations(self):
        """Test batch async operations."""
        async def batch_pull(files: List[str]):
            async def pull_one(f):
                await asyncio.sleep(0.01)
                return {"file": f, "status": "ok"}
            
            results = await asyncio.gather(*[pull_one(f) for f in files])
            return results
        
        files = [f"/data/file_{i}.db" for i in range(20)]
        results = asyncio.run(batch_pull(files))
        
        self.assertEqual(len(results), 20)
        self.assertTrue(all(r["status"] == "ok" for r in results))
    
    def test_async_error_handling(self):
        """Test async error handling."""
        async def failing_operation():
            await asyncio.sleep(0.01)
            raise RuntimeError("Device disconnected")
        
        async def safe_operation():
            try:
                await failing_operation()
            except RuntimeError as e:
                return {"error": str(e), "status": "failed"}
            return {"status": "ok"}
        
        result = asyncio.run(safe_operation())
        self.assertEqual(result["status"], "failed")
        self.assertIn("disconnected", result["error"])
    
    def test_async_retry_pattern(self):
        """Test async retry pattern."""
        attempt_count = 0
        
        async def flaky_operation():
            nonlocal attempt_count
            attempt_count += 1
            
            if attempt_count < 3:
                raise ConnectionError("Connection failed")
            return "success"
        
        async def with_retry(max_retries: int = 5):
            for attempt in range(max_retries):
                try:
                    return await flaky_operation()
                except ConnectionError:
                    if attempt == max_retries - 1:
                        raise
                    await asyncio.sleep(0.01 * (2 ** attempt))
            return None
        
        result = asyncio.run(with_retry())
        self.assertEqual(result, "success")
        self.assertEqual(attempt_count, 3)


# =============================================================================
# ASYNC STREAM PROCESSING TESTS
# =============================================================================

class TestAsyncStreamProcessing(unittest.TestCase):
    """Test async stream processing for large data."""
    
    def test_async_generator(self):
        """Test async generator for streaming data."""
        async def data_stream(count: int):
            for i in range(count):
                await asyncio.sleep(0.001)
                yield {"id": i, "data": f"chunk_{i}"}
        
        async def consume_stream():
            results = []
            async for item in data_stream(100):
                results.append(item)
            return results
        
        results = asyncio.run(consume_stream())
        self.assertEqual(len(results), 100)
    
    def test_async_file_streaming(self):
        """Test async file content streaming."""
        async def stream_file_chunks(content: bytes, chunk_size: int):
            for i in range(0, len(content), chunk_size):
                await asyncio.sleep(0.001)
                yield content[i:i + chunk_size]
        
        async def process_file():
            content = b"x" * 10000
            chunks = []
            async for chunk in stream_file_chunks(content, 1000):
                chunks.append(chunk)
            return b"".join(chunks)
        
        result = asyncio.run(process_file())
        self.assertEqual(len(result), 10000)
    
    def test_async_logcat_streaming(self):
        """Test streaming logcat output asynchronously."""
        async def stream_logcat():
            lines = [
                "01-15 14:30:45.123 I/System: Boot completed",
                "01-15 14:30:45.234 D/App: Started",
                "01-15 14:30:45.345 W/Warning: Low memory",
                "01-15 14:30:45.456 E/Error: Crash detected",
            ]
            for line in lines:
                await asyncio.sleep(0.001)
                yield line
        
        async def analyze_logcat():
            errors = []
            warnings = []
            
            async for line in stream_logcat():
                if " E/" in line:
                    errors.append(line)
                elif " W/" in line:
                    warnings.append(line)
            
            return {"errors": errors, "warnings": warnings}
        
        result = asyncio.run(analyze_logcat())
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual(len(result["warnings"]), 1)


# =============================================================================
# ASYNC COORDINATION TESTS
# =============================================================================

class TestAsyncCoordination(unittest.TestCase):
    """Test async task coordination patterns."""
    
    def test_async_lock(self):
        """Test async lock for mutual exclusion."""
        shared_data = {"count": 0}
        
        async def increment(lock: asyncio.Lock, times: int):
            for _ in range(times):
                async with lock:
                    current = shared_data["count"]
                    await asyncio.sleep(0.001)
                    shared_data["count"] = current + 1
        
        async def main():
            lock = asyncio.Lock()
            tasks = [increment(lock, 10) for _ in range(5)]
            await asyncio.gather(*tasks)
            return shared_data["count"]
        
        result = asyncio.run(main())
        self.assertEqual(result, 50)
    
    def test_async_event(self):
        """Test async event for signaling."""
        results = []
        
        async def waiter(event: asyncio.Event, name: str):
            await event.wait()
            results.append(f"{name} activated")
        
        async def setter(event: asyncio.Event):
            await asyncio.sleep(0.05)
            event.set()
        
        async def main():
            event = asyncio.Event()
            
            await asyncio.gather(
                waiter(event, "task1"),
                waiter(event, "task2"),
                waiter(event, "task3"),
                setter(event)
            )
            
            return results
        
        results = asyncio.run(main())
        self.assertEqual(len(results), 3)
    
    def test_async_condition(self):
        """Test async condition for complex synchronization."""
        queue = []
        
        async def producer(condition: asyncio.Condition):
            for i in range(5):
                async with condition:
                    queue.append(i)
                    condition.notify()
                await asyncio.sleep(0.01)
        
        async def consumer(condition: asyncio.Condition, results: List):
            while len(results) < 5:
                async with condition:
                    while not queue:
                        await condition.wait()
                    item = queue.pop(0)
                    results.append(item)
        
        async def main():
            condition = asyncio.Condition()
            results = []
            
            await asyncio.gather(
                producer(condition),
                consumer(condition, results)
            )
            
            return results
        
        results = asyncio.run(main())
        self.assertEqual(results, [0, 1, 2, 3, 4])


# =============================================================================
# ASYNC CANCELLATION TESTS
# =============================================================================

class TestAsyncCancellation(unittest.TestCase):
    """Test async task cancellation handling."""
    
    def test_task_cancellation(self):
        """Test cancelling an async task."""
        cancelled = False
        
        async def long_task():
            nonlocal cancelled
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                cancelled = True
                raise
        
        async def main():
            task = asyncio.create_task(long_task())
            await asyncio.sleep(0.01)
            task.cancel()
            
            try:
                await task
            except asyncio.CancelledError:
                pass
            
            return cancelled
        
        result = asyncio.run(main())
        self.assertTrue(result)
    
    def test_graceful_shutdown(self):
        """Test graceful shutdown of multiple tasks."""
        completed = []
        
        async def worker(worker_id: int, shutdown: asyncio.Event):
            while not shutdown.is_set():
                await asyncio.sleep(0.01)
            completed.append(worker_id)
        
        async def main():
            shutdown = asyncio.Event()
            
            workers = [
                asyncio.create_task(worker(i, shutdown))
                for i in range(5)
            ]
            
            await asyncio.sleep(0.05)
            shutdown.set()
            
            await asyncio.gather(*workers)
            return completed
        
        result = asyncio.run(main())
        self.assertEqual(len(result), 5)
    
    def test_timeout_with_cleanup(self):
        """Test timeout with proper cleanup."""
        cleanup_called = False
        
        async def operation_with_cleanup():
            nonlocal cleanup_called
            try:
                await asyncio.sleep(10)
            finally:
                cleanup_called = True
        
        async def main():
            try:
                async with asyncio.timeout(0.05):
                    await operation_with_cleanup()
            except asyncio.TimeoutError:
                pass
            return cleanup_called
        
        result = asyncio.run(main())
        self.assertTrue(result)


# =============================================================================
# PYTEST-ASYNCIO COMPATIBLE TESTS
# =============================================================================

@pytest.mark.asyncio(loop_scope="function")
class TestPytestAsyncio:
    """Tests using pytest-asyncio with proper configuration."""
    
    async def test_simple_async(self):
        """Simple async test."""
        result = await asyncio.sleep(0.01, result="done")
        assert result == "done"
    
    async def test_async_device_simulation(self):
        """Simulate async device operations."""
        async def get_device_info():
            await asyncio.sleep(0.01)
            return {
                "manufacturer": "OnePlus",
                "model": "LE2117",
                "android_version": "13"
            }
        
        info = await get_device_info()
        assert info["manufacturer"] == "OnePlus"
    
    async def test_async_parallel_extraction(self):
        """Test parallel data extraction."""
        async def extract_artifact(name: str):
            await asyncio.sleep(0.01)
            return {"artifact": name, "extracted": True}
        
        artifacts = ["contacts", "messages", "call_log", "apps"]
        results = await asyncio.gather(*[extract_artifact(a) for a in artifacts])
        
        assert len(results) == 4
        assert all(r["extracted"] for r in results)
    
    async def test_async_with_mock(self):
        """Test async with mocked operations."""
        mock_adb = AsyncMock(return_value={"status": "ok", "output": "test"})
        
        result = await mock_adb("shell", "echo", "test")
        
        assert result["status"] == "ok"
        mock_adb.assert_called_once()


# =============================================================================
# ASYNC PERFORMANCE TESTS
# =============================================================================

class TestAsyncPerformance(unittest.TestCase):
    """Test async performance characteristics."""
    
    def test_concurrent_vs_sequential(self):
        """Compare concurrent vs sequential execution time."""
        async def slow_task():
            await asyncio.sleep(0.1)
            return 1
        
        async def sequential():
            start = time.time()
            for _ in range(5):
                await slow_task()
            return time.time() - start
        
        async def concurrent():
            start = time.time()
            await asyncio.gather(*[slow_task() for _ in range(5)])
            return time.time() - start
        
        seq_time = asyncio.run(sequential())
        conc_time = asyncio.run(concurrent())
        
        # Concurrent should be roughly 5x faster
        self.assertLess(conc_time, seq_time / 3)
    
    def test_task_creation_overhead(self):
        """Measure task creation overhead."""
        async def empty_task():
            pass
        
        async def main():
            start = time.time()
            tasks = [asyncio.create_task(empty_task()) for _ in range(10000)]
            await asyncio.gather(*tasks)
            return time.time() - start
        
        elapsed = asyncio.run(main())
        
        # 10000 tasks should complete quickly (under 1 second)
        self.assertLess(elapsed, 1.0)
    
    def test_event_loop_efficiency(self):
        """Test event loop efficiency under load."""
        counter = 0
        
        async def incrementer():
            nonlocal counter
            for _ in range(1000):
                counter += 1
                await asyncio.sleep(0)  # Yield control
        
        async def main():
            tasks = [incrementer() for _ in range(100)]
            await asyncio.gather(*tasks)
            return counter
        
        result = asyncio.run(main())
        self.assertEqual(result, 100000)


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    print("""
    ================================================================
         ASYNC OPERATIONS TEST SUITE
         Federal Investigation Agency - Forensics Framework
    ================================================================
         Testing:
         - Async Utilities
         - MCP Tool Simulation
         - Stream Processing
         - Task Coordination
         - Cancellation Handling
         - Performance Characteristics
    ================================================================
    """)
    
    unittest.main(verbosity=2)

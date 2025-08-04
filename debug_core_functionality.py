#!/usr/bin/env python3
"""
Debug Core Functionality
========================

Test if the core modules actually work when called directly.
"""

import asyncio
import time
import sys


def test_port_scanner():
    """Test the core port scanner functionality."""
    print("\n🔍 Testing Core Port Scanner...")

    try:
        from core.scanner import PortScanner
        # Create scanner with short timeout
        scanner = PortScanner(timeout=3, max_concurrent=1)
        print("✅ Port scanner imported successfully")

        # Test scan of a closed port (should return closed status)
        print("🚀 Testing scan of 127.0.0.1:22 (likely closed)...")

        async def quick_scan():
            try:
                start_time = time.time()
                result = await scanner.scan_port('127.0.0.1', 22)
                end_time = time.time()

                print(f"⏱️  Scan took {end_time - start_time:.2f} seconds")
                print(f"📊 Result: {result}")
                print(f"📊 Status: {result.status}")

                return result
            except Exception as e:
                print(f"❌ Scan error: {e}")
                import traceback
                traceback.print_exc()
                return None

        # Run the scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        result = loop.run_until_complete(quick_scan())
        loop.close()

        if result and hasattr(result, 'status'):
            print("✅ Core port scanner is working!")
            return True
        else:
            print("❌ Core port scanner failed!")
            return False

    except Exception as e:
        print(f"❌ Port scanner error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_simple_scan():
    """Test a very simple port scan."""
    print("\n🔍 Testing Simple Socket Connection...")

    try:
        import socket

        # Test a port that's more likely to be open or at least respond
        print("🚀 Testing direct socket connection to google.com:80...")

        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)

        try:
            result = sock.connect_ex(('google.com', 80))
            sock.close()
            end_time = time.time()

            print(f"⏱️  Connection took {end_time - start_time:.2f} seconds")

            if result == 0:
                print("✅ Port 80 is open!")
                return True
            else:
                print(f"❌ Port 80 connection failed (result: {result})")

                # Also test localhost with a different approach
                print("🚀 Testing localhost connection...")
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(1)
                result2 = sock2.connect_ex(('127.0.0.1', 22))
                sock2.close()

                if result2 == 61:  # Connection refused (normal for closed port)
                    print("✅ Network stack is working (port correctly refused)")
                    return True
                else:
                    print(f"❌ Unexpected result: {result2}")
                    return False

        except Exception as e:
            print(f"❌ Socket error: {e}")
            return False

    except Exception as e:
        print(f"❌ Socket test error: {e}")
        return False


def main():
    """Run core functionality tests."""
    print("🚀 Testing NetSecureX Core Functionality")
    print("=" * 50)
    
    # Test simple socket first
    socket_works = test_simple_scan()
    
    # Test core scanner
    scanner_works = test_port_scanner()
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 CORE TEST SUMMARY")
    print("=" * 50)
    
    print(f"{'✅' if socket_works else '❌'} Simple Socket Connection")
    print(f"{'✅' if scanner_works else '❌'} Core Port Scanner")
    
    if socket_works and scanner_works:
        print("🎉 Core functionality is working!")
        print("🔍 Issue is likely in GUI integration")
    elif socket_works and not scanner_works:
        print("⚠️  Network works but core scanner has issues")
    else:
        print("❌ Basic network connectivity issues")
    
    return socket_works and scanner_works


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

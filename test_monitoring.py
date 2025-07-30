#!/usr/bin/env python3
"""
Test script for monitoring dashboard functionality
"""

def test_monitoring():
    """Test the monitoring functions without GUI."""
    print("🧪 Testing NetSecureX Monitoring Functions...")
    
    try:
        import psutil
        print("✅ psutil imported successfully")
        
        # Test CPU
        try:
            cpu = psutil.cpu_percent(interval=0.1)
            print(f"✅ CPU usage: {cpu}%")
        except Exception as e:
            print(f"❌ CPU error: {e}")
        
        # Test Memory
        try:
            memory = psutil.virtual_memory()
            print(f"✅ Memory usage: {memory.percent}%")
        except Exception as e:
            print(f"❌ Memory error: {e}")
        
        # Test Disk
        try:
            disk = psutil.disk_usage('/')
            print(f"✅ Disk usage: {disk.percent}%")
        except Exception as e:
            print(f"❌ Disk error: {e}")
        
        # Test Network Statistics (safer approach)
        try:
            # Get network I/O statistics instead of connections
            net_io = psutil.net_io_counters()
            print(f"✅ Network statistics:")
            print(f"  Bytes sent: {net_io.bytes_sent:,}")
            print(f"  Bytes received: {net_io.bytes_recv:,}")
            print(f"  Packets sent: {net_io.packets_sent:,}")
            print(f"  Packets received: {net_io.packets_recv:,}")

            print(f"✅ Network monitoring working with statistics")
            
        except Exception as e:
            print(f"❌ Network connections error: {e}")
        
        print("\n🎉 Monitoring test completed!")
        print("The monitoring dashboard should now work with better error handling.")
        
    except ImportError:
        print("❌ psutil not installed. Install with: pip install psutil")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    test_monitoring()

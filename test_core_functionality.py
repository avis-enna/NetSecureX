#!/usr/bin/env python3
"""
Test Core Functionality
=======================

Test if the core modules actually work when called directly.
This will help identify if the issue is in the core modules or GUI integration.
"""

import asyncio
import time
import sys


def test_port_scanner():
    """Test the core port scanner functionality."""
    print("\n🔍 Testing Core Port Scanner...")
    
    try:
        from core.scanner import PortScanner
        scanner = PortScanner()
        print("✅ Port scanner imported successfully")
        
        # Test a simple scan of localhost port 22 (SSH)
        print("🚀 Testing scan of 127.0.0.1:22 (should be quick)...")
        
        async def quick_scan():
            try:
                start_time = time.time()
                result = await scanner.scan_port('127.0.0.1', 22, timeout=3)
                end_time = time.time()
                
                print(f"⏱️  Scan took {end_time - start_time:.2f} seconds")
                print(f"📊 Result: {result}")
                
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
        
        if result:
            print("✅ Core port scanner is working!")
            return True
        else:
            print("❌ Core port scanner failed!")
            return False
            
    except Exception as e:
        print(f"❌ Port scanner import/setup error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_cve_lookup():
    """Test the core CVE lookup functionality."""
    print("\n🛡️ Testing Core CVE Lookup...")
    
    try:
        from core.cve_lookup import CVELookup
        cve_lookup = CVELookup()
        print("✅ CVE lookup imported successfully")
        
        # Test a simple CVE search
        print("🚀 Testing CVE search for 'nginx'...")
        
        async def quick_cve_search():
            try:
                start_time = time.time()
                results = await cve_lookup.search_cves('nginx', limit=5)
                end_time = time.time()
                
                print(f"⏱️  Search took {end_time - start_time:.2f} seconds")
                print(f"📊 Found {len(results) if results else 0} results")
                
                if results and len(results) > 0:
                    print(f"📋 First result: {results[0].cve_id}")
                
                return results
            except Exception as e:
                print(f"❌ CVE search error: {e}")
                import traceback
                traceback.print_exc()
                return None
        
        # Run the search
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        results = loop.run_until_complete(quick_cve_search())
        loop.close()
        
        if results:
            print("✅ Core CVE lookup is working!")
            return True
        else:
            print("❌ Core CVE lookup failed!")
            return False
            
    except Exception as e:
        print(f"❌ CVE lookup import/setup error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_ssl_analyzer():
    """Test the core SSL analyzer functionality."""
    print("\n🔒 Testing Core SSL Analyzer...")
    
    try:
        from core.ssl_check import SSLAnalyzer
        ssl_analyzer = SSLAnalyzer()
        print("✅ SSL analyzer imported successfully")
        
        # Test SSL analysis of a known good site
        print("🚀 Testing SSL analysis of google.com:443...")
        
        async def quick_ssl_check():
            try:
                start_time = time.time()
                result = await ssl_analyzer.analyze_ssl('google.com', 443)
                end_time = time.time()
                
                print(f"⏱️  Analysis took {end_time - start_time:.2f} seconds")
                print(f"📊 Result: {result.hostname if result else 'None'}")
                
                return result
            except Exception as e:
                print(f"❌ SSL analysis error: {e}")
                import traceback
                traceback.print_exc()
                return None
        
        # Run the analysis
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        result = loop.run_until_complete(quick_ssl_check())
        loop.close()
        
        if result:
            print("✅ Core SSL analyzer is working!")
            return True
        else:
            print("❌ Core SSL analyzer failed!")
            return False
            
    except Exception as e:
        print(f"❌ SSL analyzer import/setup error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_ip_reputation():
    """Test the core IP reputation functionality."""
    print("\n🌐 Testing Core IP Reputation...")
    
    try:
        from core.ip_reputation import IPReputationChecker
        ip_checker = IPReputationChecker()
        print("✅ IP reputation checker imported successfully")
        
        # Test IP reputation check
        print("🚀 Testing IP reputation check for 8.8.8.8...")
        
        async def quick_ip_check():
            try:
                start_time = time.time()
                result = await ip_checker.check_ip_reputation('8.8.8.8')
                end_time = time.time()
                
                print(f"⏱️  Check took {end_time - start_time:.2f} seconds")
                print(f"📊 Result: {result.ip if result else 'None'}")
                
                return result
            except Exception as e:
                print(f"❌ IP reputation error: {e}")
                import traceback
                traceback.print_exc()
                return None
        
        # Run the check
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        result = loop.run_until_complete(quick_ip_check())
        loop.close()
        
        if result:
            print("✅ Core IP reputation checker is working!")
            return True
        else:
            print("❌ Core IP reputation checker failed!")
            return False
            
    except Exception as e:
        print(f"❌ IP reputation import/setup error: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all core functionality tests."""
    print("🚀 Testing NetSecureX Core Functionality")
    print("=" * 50)
    
    results = {}
    results['port_scanner'] = test_port_scanner()
    results['cve_lookup'] = test_cve_lookup()
    results['ssl_analyzer'] = test_ssl_analyzer()
    results['ip_reputation'] = test_ip_reputation()
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 CORE FUNCTIONALITY TEST SUMMARY")
    print("=" * 50)
    
    working_count = sum(1 for result in results.values() if result)
    total_count = len(results)
    
    for module, status in results.items():
        status_icon = "✅" if status else "❌"
        print(f"{status_icon} {module.replace('_', ' ').title()}")
    
    print(f"\n🎯 Overall Status: {working_count}/{total_count} core modules working")
    
    if working_count == total_count:
        print("🎉 All core functionality is working!")
        print("🔍 Issue is likely in GUI integration, not core modules")
    else:
        print(f"⚠️  {total_count - working_count} core modules need fixing")
        print("🔧 Core modules must be fixed before GUI can work")
    
    return working_count == total_count


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

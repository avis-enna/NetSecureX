"""
Command Line Interface for NetSecureX
=====================================

This module provides the main CLI interface using Click framework.
"""

import asyncio
import csv
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.scanner import PortScanner
from core.ssl_check import SSLAnalyzer
from core.vuln_lookup import CVELookup
from core.banner_grabber import BannerGrabber
from core.ip_reputation import IPReputationChecker
from core.firewall_tester import FirewallTester
from core.cert_analyzer import CertificateAnalyzer
from core.cve_lookup import CVELookup as CVELookupNew
from core.ip_reputation_new import IPReputationAssessment
from utils.logger import setup_logging, get_logger
from utils.network import parse_port_range, get_top_ports

# Import packet sniffer with error handling
try:
    from core.packet_sniffer import PacketSniffer
    PACKET_SNIFFER_AVAILABLE = True
except ImportError:
    PacketSniffer = None
    PACKET_SNIFFER_AVAILABLE = False


console = Console()
logger = get_logger(__name__)


@click.group()
@click.option('--log-level', default='INFO', 
              type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']),
              help='Set logging level')
@click.option('--log-file', type=click.Path(), help='Log file path')
@click.option('--no-console-log', is_flag=True, help='Disable console logging')
@click.pass_context
def main_cli(ctx, log_level, log_file, no_console_log):
    """
    NetSecureX - Unified Cybersecurity Tool
    
    A comprehensive security testing toolkit with modular components.
    """
    # Ensure context object exists
    ctx.ensure_object(dict)
    
    # Setup logging
    log_file_path = Path(log_file) if log_file else None
    setup_logging(
        log_level=log_level,
        log_file=log_file_path,
        enable_console=not no_console_log
    )
    
    # Store configuration in context
    ctx.obj['log_level'] = log_level
    ctx.obj['log_file'] = log_file_path


@main_cli.command()
@click.argument('target')
@click.option('--ports', '-p', help='Port specification (e.g., "80,443,8000-8010")')
@click.option('--top-ports', '-t', type=int, default=1000, 
              help='Number of top ports to scan (default: 1000)')
@click.option('--timeout', type=float, default=3.0, 
              help='Connection timeout in seconds (default: 3.0)')
@click.option('--max-concurrent', '-c', type=int, default=100,
              help='Maximum concurrent connections (default: 100)')
@click.option('--delay', type=float, default=0.01,
              help='Delay between connections in seconds (default: 0.01)')
@click.option('--output', '-o', type=click.Path(), 
              help='Output file path (JSON format)')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json']),
              default='table', help='Output format (default: table)')
@click.option('--banner-grab', is_flag=True, 
              help='Enable banner grabbing (slower but more info)')
@click.option('--report', type=click.Path(), 
              help='Generate markdown report file')
@click.pass_context
def scan(ctx, target, ports, top_ports, timeout, max_concurrent, delay, 
         output, output_format, banner_grab, report):
    """
    Perform port scanning on target(s).
    
    TARGET can be:
    - Single IP: 192.168.1.1
    - IP range: 192.168.1.0/24
    - IP list: 192.168.1.1,192.168.1.2
    - Hostname: example.com
    
    Examples:
    
    \b
    # Scan top 1000 ports on single IP
    netsecurex scan 192.168.1.1
    
    \b
    # Scan specific ports on IP range
    netsecurex scan 192.168.1.0/24 --ports "22,80,443"
    
    \b
    # Scan with custom settings and save results
    netsecurex scan example.com --top-ports 100 --timeout 5 --output results.json
    """
    try:
        # Parse port specification
        scan_ports = None
        use_top_ports = True
        
        if ports:
            scan_ports = parse_port_range(ports)
            use_top_ports = False
            console.print(f"[blue]Scanning {len(scan_ports)} specified ports[/blue]")
        else:
            console.print(f"[blue]Scanning top {top_ports} ports[/blue]")
        
        # Initialize scanner
        scanner = PortScanner(
            timeout=timeout,
            max_concurrent=max_concurrent,
            delay=delay,
            enable_banner_grab=banner_grab
        )
        
        # Run scan with progress indicator
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Scanning {target}...", total=None)
            
            # Execute scan
            summary = asyncio.run(scanner.scan_target(
                target=target,
                ports=scan_ports,
                use_top_ports=use_top_ports,
                top_ports_count=top_ports
            ))
            
            progress.update(task, completed=True)
        
        # Display results
        if output_format == 'table':
            display_scan_results_table(summary)
        else:
            formatted_output = scanner.format_results(summary, output_format)
            console.print(formatted_output)
        
        # Save output file if specified
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(summary.to_dict(), f, indent=2, default=str)
            
            console.print(f"[green]Results saved to {output_path}[/green]")
        
        # Generate report if specified
        if report:
            generate_scan_report(summary, Path(report))
            console.print(f"[green]Report generated: {report}[/green]")
        
        # Exit with appropriate code
        if summary.open_ports > 0:
            console.print(f"[yellow]Found {summary.open_ports} open ports[/yellow]")
        else:
            console.print("[green]No open ports found[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.error(f"Scan failed: {e}")
        sys.exit(1)


@main_cli.command()
@click.argument('target')
@click.option('--port', '-p', type=int, default=443,
              help='Port number (default: 443)')
@click.option('--timeout', type=float, default=10.0,
              help='Connection timeout in seconds (default: 10.0)')
@click.option('--output', '-o', type=click.Path(),
              help='Output file path (JSON format)')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json']),
              default='table', help='Output format (default: table)')
@click.option('--no-verify-hostname', is_flag=True,
              help='Disable hostname verification')
@click.option('--report', type=click.Path(),
              help='Generate markdown report file')
@click.pass_context
def sslcheck(ctx, target, port, timeout, output, output_format, no_verify_hostname, report):
    """
    Analyze SSL/TLS certificates for target hosts.

    TARGET can be:
    - Hostname: example.com
    - IP address: 192.168.1.1
    - URL: https://example.com (port extracted automatically)

    Examples:

    \b
    # Check SSL certificate for a website
    netsecurex sslcheck example.com

    \b
    # Check SSL on custom port
    netsecurex sslcheck mail.example.com --port 993

    \b
    # Check with JSON output and save results
    netsecurex sslcheck example.com --format json --output ssl_results.json

    \b
    # Check self-signed certificate (skip hostname verification)
    netsecurex sslcheck 192.168.1.1 --no-verify-hostname
    """
    try:
        # Parse target if it's a URL
        parsed_target, parsed_port = parse_ssl_target(target, port)

        # Initialize SSL analyzer
        analyzer = SSLAnalyzer(
            timeout=timeout,
            verify_hostname=not no_verify_hostname
        )

        # Run SSL analysis with progress indicator
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Analyzing SSL certificate for {parsed_target}:{parsed_port}...", total=None)

            # Execute analysis
            result = analyzer.analyze_target(parsed_target, parsed_port)

            progress.update(task, completed=True)

        # Display results
        if output_format == 'table':
            display_ssl_results_table(result)
        else:
            formatted_output = analyzer.format_results(result, output_format)
            console.print(formatted_output)

        # Save output file if specified
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, 'w') as f:
                json.dump(result.to_dict(), f, indent=2, default=str)

            console.print(f"[green]Results saved to {output_path}[/green]")

        # Generate report if specified
        if report:
            generate_ssl_report(result, Path(report))
            console.print(f"[green]Report generated: {report}[/green]")

        # Exit with appropriate code based on certificate status
        if result.status == 'valid':
            console.print(f"[green]✅ SSL certificate is valid[/green]")
        elif result.status == 'expired':
            console.print(f"[red]❌ SSL certificate is expired[/red]")
            sys.exit(1)
        elif result.status == 'self_signed':
            console.print(f"[yellow]⚠️ SSL certificate is self-signed[/yellow]")
        elif result.status == 'invalid':
            console.print(f"[red]❌ SSL certificate is invalid[/red]")
            sys.exit(1)
        else:
            console.print(f"[red]💥 SSL analysis failed[/red]")
            sys.exit(1)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.error(f"SSL analysis failed: {e}")
        sys.exit(1)


@main_cli.command()
@click.argument('target')
@click.option('--api', type=click.Choice(['vulners', 'nvd']), default='vulners',
              help='API to use for CVE lookup (default: vulners)')
@click.option('--max-results', '-n', type=int, default=20,
              help='Maximum number of CVEs to return (default: 20)')
@click.option('--timeout', type=float, default=30.0,
              help='Request timeout in seconds (default: 30.0)')
@click.option('--output', '-o', type=click.Path(),
              help='Output file path (JSON format)')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json']),
              default='table', help='Output format (default: table)')
@click.option('--severity-filter', type=click.Choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
              help='Filter results by minimum severity level')
@click.option('--report', type=click.Path(),
              help='Generate markdown report file')
@click.option('--bulk-file', type=click.Path(exists=True),
              help='File containing product:version pairs (one per line)')
@click.pass_context
def cve(ctx, target, api, max_results, timeout, output, output_format, severity_filter, report, bulk_file):
    """
    Look up CVE vulnerabilities for software products and versions.

    TARGET format: product:version (e.g., apache:2.4.54, openssl:1.1.1n)

    Examples:

    \b
    # Look up CVEs for Apache HTTP Server
    netsecurex cve apache:2.4.54

    \b
    # Look up CVEs for OpenSSL with JSON output
    netsecurex cve openssl:1.1.1n --format json

    \b
    # Filter for high severity CVEs only
    netsecurex cve nginx:1.18.0 --severity-filter HIGH

    \b
    # Save results and generate report
    netsecurex cve mysql:8.0.25 --output cve_results.json --report cve_report.md

    \b
    # Bulk lookup from file
    netsecurex cve dummy --bulk-file software_list.txt
    """
    try:
        # Initialize CVE lookup
        lookup = CVELookup(
            preferred_api=api,
            timeout=timeout
        )

        # Check for API key if using Vulners
        if api == 'vulners' and not lookup.vulners_api_key:
            console.print("[yellow]Warning: No Vulners API key found. Set VULNERS_API_KEY environment variable for better results.[/yellow]")
            console.print("[yellow]Falling back to NVD API...[/yellow]")

        # Handle bulk lookup
        if bulk_file:
            results = asyncio.run(handle_bulk_cve_lookup(lookup, bulk_file, max_results, severity_filter))

            # Display bulk results
            if output_format == 'table':
                display_bulk_cve_results(results, severity_filter)
            else:
                formatted_output = json.dumps(results, indent=2, default=str)
                console.print(formatted_output)
        else:
            # Single target lookup
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(f"Looking up CVEs for {target}...", total=None)

                # Parse target
                try:
                    product, version = lookup.parse_product_version(target)
                except ValueError as e:
                    console.print(f"[red]Error: {e}[/red]")
                    sys.exit(1)

                # Execute CVE lookup
                results = asyncio.run(lookup.lookup_cves(product, version, max_results))

                # Apply severity filter
                if severity_filter:
                    results = filter_by_severity(results, severity_filter)

                progress.update(task, completed=True)

            # Display results
            if output_format == 'table':
                display_cve_results_table(results, target)
            else:
                formatted_output = lookup.format_results(results, output_format)
                console.print(formatted_output)

        # Save output file if specified
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            if bulk_file:
                with open(output_path, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
            else:
                with open(output_path, 'w') as f:
                    json.dump([result.to_dict() for result in results], f, indent=2, default=str)

            console.print(f"[green]Results saved to {output_path}[/green]")

        # Generate report if specified
        if report:
            if bulk_file:
                generate_bulk_cve_report(results, Path(report))
            else:
                generate_cve_report(results, target, Path(report))
            console.print(f"[green]Report generated: {report}[/green]")

        # Exit with appropriate code
        if bulk_file:
            total_cves = sum(len(cves) for cves in results.values())
            if total_cves > 0:
                console.print(f"[yellow]Found {total_cves} total CVEs across all products[/yellow]")
            else:
                console.print("[green]No CVEs found for any products[/green]")
        else:
            if results:
                high_severity_count = len([r for r in results if r.severity in ['HIGH', 'CRITICAL']])
                if high_severity_count > 0:
                    console.print(f"[red]⚠️ Found {len(results)} CVEs ({high_severity_count} high/critical severity)[/red]")
                    sys.exit(1)
                else:
                    console.print(f"[yellow]Found {len(results)} CVEs (low/medium severity)[/yellow]")
            else:
                console.print("[green]No CVEs found[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.error(f"CVE lookup failed: {e}")
        sys.exit(1)


@main_cli.command()
@click.argument('target')
@click.option('--ports', '-p', help='Port specification (e.g., "22,80,443,3306")')
@click.option('--timeout', type=float, default=5.0,
              help='Connection timeout in seconds (default: 5.0)')
@click.option('--safe-mode', is_flag=True,
              help='Enable safe mode (less aggressive probing)')
@click.option('--delay', type=float, default=0.1,
              help='Delay between connections in seconds (default: 0.1)')
@click.option('--output', '-o', type=click.Path(),
              help='Output file path (JSON format)')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json']),
              default='table', help='Output format (default: table)')
@click.option('--pass-to-cve', is_flag=True,
              help='Automatically lookup CVEs for detected services')
@click.option('--report', type=click.Path(),
              help='Generate markdown report file')
@click.pass_context
def banner_scan(ctx, target, ports, timeout, safe_mode, delay, output, output_format, pass_to_cve, report):
    """
    Perform banner grabbing and service version detection.

    TARGET can be:
    - Single IP: 192.168.1.1
    - Hostname: example.com

    Examples:

    \b
    # Basic banner scan on common ports
    netsecurex banner-scan 192.168.1.1

    \b
    # Scan specific ports
    netsecurex banner-scan example.com --ports "22,80,443,3306"

    \b
    # Safe mode with CVE lookup
    netsecurex banner-scan 192.168.1.1 --safe-mode --pass-to-cve

    \b
    # Save results and generate report
    netsecurex banner-scan example.com --output banner_results.json --report banner_report.md
    """
    try:
        # Parse port specification
        if ports:
            scan_ports = parse_port_range(ports)
        else:
            # Default common ports for banner grabbing
            scan_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432]

        console.print(f"[blue]Banner scanning {len(scan_ports)} ports on {target}[/blue]")

        # Initialize banner grabber
        grabber = BannerGrabber(
            timeout=timeout,
            safe_mode=safe_mode,
            delay=delay
        )

        # Run banner scan with progress indicator
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Banner scanning {target}...", total=None)

            # Execute banner scan
            results = asyncio.run(grabber.scan_multiple_ports(
                target, scan_ports, pass_to_cve
            ))

            progress.update(task, completed=True)

        # Display results
        if output_format == 'table':
            display_banner_results_table(results, target)
        else:
            formatted_output = grabber.format_results(results, output_format)
            console.print(formatted_output)

        # Save output file if specified
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, 'w') as f:
                json.dump([result.to_dict() for result in results], f, indent=2, default=str)

            console.print(f"[green]Results saved to {output_path}[/green]")

        # Generate report if specified
        if report:
            generate_banner_report(results, target, Path(report))
            console.print(f"[green]Report generated: {report}[/green]")

        # Exit with appropriate code
        detected_count = len([r for r in results if r.status == "detected"])
        if detected_count > 0:
            console.print(f"[green]✅ Detected {detected_count} services[/green]")

            # Check for CVEs if pass_to_cve was used
            if pass_to_cve:
                cve_count = 0
                for result in results:
                    if result.additional_info and 'cves' in result.additional_info:
                        cve_count += len(result.additional_info['cves'])

                if cve_count > 0:
                    console.print(f"[yellow]⚠️ Found {cve_count} CVEs for detected services[/yellow]")
        else:
            console.print("[yellow]No services detected[/yellow]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.error(f"Banner scan failed: {e}")
        sys.exit(1)


@main_cli.command()
@click.option('--interface', '-i', help='Network interface to capture on (e.g., eth0, wlan0)')
@click.option('--duration', '-d', type=int, help='Capture duration in seconds')
@click.option('--filter', 'capture_filter', help='BPF filter string (e.g., "tcp port 80")')
@click.option('--max-packets', type=int, default=10000,
              help='Maximum packets to capture (default: 10000)')
@click.option('--save-pcap', type=click.Path(),
              help='Save captured packets to PCAP file')
@click.option('--output', '-o', type=click.Path(),
              help='Output file path (JSON format)')
@click.option('--report', type=click.Path(),
              help='Generate markdown report file')
@click.option('--show-stats', is_flag=True,
              help='Show real-time statistics during capture')
@click.pass_context
def sniff(ctx, interface, duration, capture_filter, max_packets, save_pcap, output, report, show_stats):
    """
    Passive packet capture and network analysis.

    Captures and analyzes network traffic for security monitoring and threat detection.
    Supports protocol analysis, anomaly detection, and flow tracking.

    Examples:

    \b
    # Basic packet capture for 60 seconds
    netsecurex sniff --duration 60

    \b
    # Capture HTTP traffic on specific interface
    netsecurex sniff --interface eth0 --filter "tcp port 80" --duration 30

    \b
    # Capture with PCAP save and analysis
    netsecurex sniff --duration 120 --save-pcap capture.pcap --report analysis.md

    \b
    # Monitor DNS traffic
    netsecurex sniff --filter "port 53" --show-stats --duration 60

    \b
    # Capture HTTPS traffic and analyze TLS
    netsecurex sniff --filter "tcp port 443" --output tls_analysis.json
    """
    if not PACKET_SNIFFER_AVAILABLE:
        console.print("[red]Error: Packet sniffing requires Scapy. Install with: pip install scapy[/red]")
        sys.exit(1)

    try:
        # Validate interface if specified
        if interface:
            available_interfaces = PacketSniffer.get_available_interfaces()
            if interface not in available_interfaces:
                console.print(f"[red]Error: Interface '{interface}' not found.[/red]")
                console.print(f"Available interfaces: {', '.join(available_interfaces)}")
                sys.exit(1)

        # Validate BPF filter if specified
        if capture_filter and not PacketSniffer.validate_bpf_filter(capture_filter):
            console.print(f"[yellow]Warning: BPF filter '{capture_filter}' may be invalid[/yellow]")

        # Check permissions
        import os
        if hasattr(os, 'geteuid') and os.geteuid() != 0:
            console.print("[yellow]Warning: Packet capture may require root privileges for full functionality[/yellow]")

        # Initialize packet sniffer
        sniffer = PacketSniffer(
            interface=interface,
            capture_filter=capture_filter or "",
            max_packets=max_packets,
            enable_analysis=True
        )

        # Display capture information
        console.print(f"[blue]Starting packet capture...[/blue]")
        console.print(f"Interface: {interface or 'default'}")
        console.print(f"Filter: {capture_filter or 'none'}")
        console.print(f"Duration: {duration or 'indefinite'} seconds")
        console.print(f"Max packets: {max_packets}")
        console.print()

        # Start capture
        if not sniffer.start_capture(duration=duration, save_pcap=save_pcap):
            console.print("[red]Failed to start packet capture[/red]")
            sys.exit(1)

        # Real-time monitoring
        if show_stats:
            monitor_capture_stats(sniffer, duration)
        else:
            # Simple progress display
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Capturing packets...", total=None)

                # Wait for capture to complete
                start_time = time.time()
                while sniffer.is_capturing:
                    time.sleep(1)
                    elapsed = time.time() - start_time

                    if duration and elapsed >= duration:
                        break

                    # Update progress with packet count
                    stats = sniffer.get_statistics()
                    progress.update(task, description=f"Captured {stats['total_packets']} packets...")

                progress.update(task, completed=True)

        # Stop capture
        sniffer.stop_capture()

        # Display results
        display_capture_results(sniffer)

        # Save output file if specified
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            sniffer.export_to_json(str(output_path))
            console.print(f"[green]Results saved to {output_path}[/green]")

        # Generate report if specified
        if report:
            report_path = Path(report)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            sniffer.generate_report(str(report_path))
            console.print(f"[green]Report generated: {report_path}[/green]")

        # Exit with appropriate code
        stats = sniffer.get_statistics()
        anomalies = sniffer.get_anomalies()

        if anomalies:
            console.print(f"[red]⚠️ {len(anomalies)} anomalies detected during capture[/red]")
            sys.exit(1)
        elif stats['total_packets'] > 0:
            console.print(f"[green]✅ Captured {stats['total_packets']} packets successfully[/green]")
        else:
            console.print("[yellow]No packets captured[/yellow]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Capture interrupted by user[/yellow]")
        if 'sniffer' in locals():
            sniffer.stop_capture()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.error(f"Packet capture failed: {e}")
        sys.exit(1)


@main_cli.command()
@click.option('--ip', help='Single IP address to check')
@click.option('--file', 'ip_file', type=click.Path(exists=True),
              help='File containing IP addresses (one per line)')
@click.option('--output', '-o', type=click.Path(),
              help='Output file path (JSON format)')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json']),
              default='table', help='Output format (default: table)')
@click.option('--report', type=click.Path(),
              help='Generate markdown report file')
@click.option('--risky-only', is_flag=True,
              help='Show only risky IPs (MEDIUM, HIGH, CRITICAL)')
@click.option('--providers', help='Comma-separated list of providers to use (abuseipdb,otx,greynoise,shodan)')
@click.pass_context
def reput(ctx, ip, ip_file, output, output_format, report, risky_only, providers):
    """
    Check IP reputation using threat intelligence APIs.

    Queries multiple threat intelligence providers to assess IP reputation:
    - AbuseIPDB: Abuse confidence and reporting data
    - AlienVault OTX: Threat intelligence and pulse data
    - GreyNoise: Internet scanning activity (requires API key)
    - Shodan: Host information and vulnerabilities (requires API key)

    Examples:

    \b
    # Check single IP address
    netsecurex reput --ip 1.2.3.4

    \b
    # Check multiple IPs from file
    netsecurex reput --file ip_list.txt

    \b
    # Show only risky IPs with JSON output
    netsecurex reput --file targets.txt --risky-only --format json

    \b
    # Generate comprehensive report
    netsecurex reput --ip 1.2.3.4 --output results.json --report reputation_report.md

    \b
    # Use specific providers only
    netsecurex reput --ip 1.2.3.4 --providers "abuseipdb,otx"
    """
    try:
        # Validate input
        if not ip and not ip_file:
            console.print("[red]Error: Must specify either --ip or --file[/red]")
            sys.exit(1)

        if ip and ip_file:
            console.print("[red]Error: Cannot specify both --ip and --file[/red]")
            sys.exit(1)

        # Collect IP addresses
        ip_addresses = []
        if ip:
            ip_addresses = [ip]
        elif ip_file:
            with open(ip_file, 'r') as f:
                ip_addresses = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        if not ip_addresses:
            console.print("[red]Error: No valid IP addresses found[/red]")
            sys.exit(1)

        console.print(f"[blue]Checking reputation for {len(ip_addresses)} IP address(es)...[/blue]")

        # Initialize IP reputation checker
        checker = IPReputationChecker()

        if not checker.available_providers:
            console.print("[red]Error: No reputation providers available.[/red]")
            console.print("[yellow]Please set API keys in .env file:[/yellow]")
            console.print("- ABUSEIPDB_API_KEY=your_key_here")
            console.print("- OTX_API_KEY=your_key_here (optional)")
            console.print("- GREYNOISE_API_KEY=your_key_here (optional)")
            console.print("- SHODAN_API_KEY=your_key_here (optional)")
            sys.exit(1)

        # Show available providers
        console.print(f"Available providers: {', '.join(checker.available_providers.keys())}")
        console.print()

        # Run reputation checks with progress indicator
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Checking IP reputation...", total=None)

            # Execute reputation checks
            if len(ip_addresses) == 1:
                results = [asyncio.run(checker.check_ip_reputation(ip_addresses[0]))]
            else:
                results = asyncio.run(checker.check_multiple_ips(ip_addresses))

            progress.update(task, completed=True)

        # Filter risky IPs if requested
        if risky_only:
            results = [r for r in results if r.risk_level in ['MEDIUM', 'HIGH', 'CRITICAL']]
            if not results:
                console.print("[green]No risky IPs found[/green]")
                return

        # Display results
        if output_format == 'table':
            display_reputation_results_table(results)
        else:
            formatted_output = json.dumps([result.to_dict() for result in results], indent=2, default=str)
            console.print(formatted_output)

        # Save output file if specified
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            checker.export_results(results, str(output_path))
            console.print(f"[green]Results saved to {output_path}[/green]")

        # Generate report if specified
        if report:
            report_path = Path(report)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            checker.generate_report(results, str(report_path))
            console.print(f"[green]Report generated: {report_path}[/green]")

        # Exit with appropriate code
        malicious_count = len([r for r in results if r.is_malicious])
        high_risk_count = len([r for r in results if r.risk_level in ['HIGH', 'CRITICAL']])

        if malicious_count > 0:
            console.print(f"[red]⚠️ Found {malicious_count} malicious IP(s)[/red]")
            sys.exit(1)
        elif high_risk_count > 0:
            console.print(f"[yellow]⚠️ Found {high_risk_count} high-risk IP(s)[/yellow]")
        else:
            console.print(f"[green]✅ All {len(results)} IP(s) appear clean[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.error(f"IP reputation check failed: {e}")
        sys.exit(1)


@main_cli.command()
@click.option('--target', '-t', required=True, help='Target IP address or hostname')
@click.option('--ports', '-p', help='Port specification (e.g., "80", "80,443", "80-90")')
@click.option('--udp', is_flag=True, help='Test UDP ports instead of TCP')
@click.option('--traceroute', is_flag=True, help='Perform traceroute to target')
@click.option('--timeout', type=float, default=3.0,
              help='Connection timeout in seconds (default: 3.0)')
@click.option('--delay', type=float, default=0.1,
              help='Delay between tests in seconds (default: 0.1)')
@click.option('--max-concurrent', type=int, default=50,
              help='Maximum concurrent connections (default: 50)')
@click.option('--output', '-o', type=click.Path(),
              help='Output file path (JSON or CSV based on extension)')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'csv']),
              default='table', help='Output format (default: table)')
@click.option('--common-ports', is_flag=True,
              help='Test common ports instead of specifying --ports')
@click.pass_context
def firewall(ctx, target, ports, udp, traceroute, timeout, delay, max_concurrent,
            output, output_format, common_ports):
    """
    Test firewall rules and port connectivity.

    Tests TCP or UDP port connectivity to identify firewall behavior:
    - Open: Connection successful
    - Closed: Connection refused
    - Filtered: Connection timeout (likely blocked by firewall)

    Examples:

    \b
    # Test common TCP ports
    netsecurex firewall --target 192.168.1.1 --common-ports

    \b
    # Test specific ports
    netsecurex firewall --target example.com --ports "22,80,443"

    \b
    # Test port range
    netsecurex firewall --target 192.168.1.1 --ports "80-90"

    \b
    # Test UDP ports
    netsecurex firewall --target 8.8.8.8 --ports "53,123" --udp

    \b
    # Include traceroute analysis
    netsecurex firewall --target example.com --ports "80,443" --traceroute

    \b
    # Export results to CSV
    netsecurex firewall --target 192.168.1.1 --common-ports --output results.csv
    """
    try:
        # Validate target
        tester = FirewallTester(
            timeout=timeout,
            delay=delay,
            max_concurrent=max_concurrent
        )

        if not tester.validate_target(target):
            console.print(f"[red]Error: Invalid target '{target}'[/red]")
            sys.exit(1)

        # Determine ports to test
        if common_ports:
            if udp:
                test_ports = FirewallTester.COMMON_UDP_PORTS
            else:
                test_ports = FirewallTester.COMMON_TCP_PORTS
        elif ports:
            try:
                test_ports = FirewallTester.parse_port_range(ports)
            except ValueError as e:
                console.print(f"[red]Error: {e}[/red]")
                sys.exit(1)
        else:
            console.print("[red]Error: Must specify either --ports or --common-ports[/red]")
            sys.exit(1)

        protocol = 'udp' if udp else 'tcp'
        console.print(f"[blue]Testing {protocol.upper()} firewall rules for {target}[/blue]")
        console.print(f"Ports to test: {len(test_ports)}")
        console.print(f"Protocol: {protocol.upper()}")
        console.print(f"Timeout: {timeout}s")
        console.print()

        # Perform port tests
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Testing {len(test_ports)} ports...", total=None)

            # Execute firewall tests
            results = asyncio.run(tester.test_multiple_ports(target, test_ports, protocol))

            progress.update(task, completed=True)

        # Perform traceroute if requested
        traceroute_hops = []
        if traceroute:
            console.print("[blue]Performing traceroute...[/blue]")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Tracing route...", total=None)

                try:
                    traceroute_hops = asyncio.run(tester.perform_traceroute(target))
                    progress.update(task, completed=True)
                except Exception as e:
                    progress.update(task, completed=True)
                    console.print(f"[yellow]Traceroute failed: {e}[/yellow]")

        # Display results
        if output_format == 'table':
            display_firewall_results_table(results, traceroute_hops, target, protocol)
        elif output_format == 'json':
            display_firewall_results_json(results, traceroute_hops)
        elif output_format == 'csv':
            display_firewall_results_csv(results)

        # Save output file if specified
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            if output_path.suffix.lower() == '.csv':
                tester.export_results_csv(results, str(output_path))
            else:
                # Default to JSON
                export_data = {
                    'firewall_tests': [result.to_dict() for result in results],
                    'traceroute': [hop.to_dict() for hop in traceroute_hops] if traceroute_hops else []
                }
                with open(output_path, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)

            console.print(f"[green]Results saved to {output_path}[/green]")

        # Generate summary and exit with appropriate code
        summary = tester.generate_summary(results)

        if summary:
            open_count = summary.get('open_ports', 0)
            filtered_count = summary.get('filtered_ports', 0)

            if open_count > 0:
                console.print(f"[green]✅ Found {open_count} open port(s)[/green]")

            if filtered_count > 0:
                console.print(f"[yellow]⚠️ Found {filtered_count} filtered port(s) (likely firewall blocked)[/yellow]")

            if open_count == 0 and filtered_count == 0:
                console.print("[red]🔒 All ports appear closed or filtered[/red]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Firewall test interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.error(f"Firewall test failed: {e}")
        sys.exit(1)


@main_cli.command()
@click.option('--host', '--domain', required=True, help='Domain name or IP address to analyze')
@click.option('--port', type=int, default=443, help='Port number (default: 443)')
@click.option('--output', '-o', type=click.Path(),
              help='Output file path (JSON or CSV based on extension)')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'csv']),
              default='table', help='Output format (default: table)')
@click.option('--timeout', type=float, default=10.0,
              help='Connection timeout in seconds (default: 10.0)')
@click.pass_context
def cert(ctx, host, port, output, output_format, timeout):
    """
    Analyze SSL/TLS certificates for security assessment.

    Retrieves and analyzes SSL/TLS certificates to identify security issues:
    - Certificate validity and expiration
    - Signature algorithm strength
    - Key size and algorithm
    - Hostname verification
    - Certificate chain analysis
    - Security grade assignment

    Examples:

    \b
    # Analyze certificate for domain
    netsecurex cert --host google.com

    \b
    # Analyze certificate on custom port
    netsecurex cert --host example.com --port 8443

    \b
    # Export results to JSON
    netsecurex cert --host google.com --format json --output cert_analysis.json

    \b
    # Analyze with custom timeout
    netsecurex cert --host slow-server.com --timeout 30

    \b
    # Test expired certificate
    netsecurex cert --host expired.badssl.com

    \b
    # Test self-signed certificate
    netsecurex cert --host self-signed.badssl.com
    """
    try:
        # Initialize certificate analyzer
        analyzer = CertificateAnalyzer(timeout=timeout)

        console.print(f"[blue]Analyzing SSL/TLS certificate for {host}:{port}[/blue]")
        console.print()

        # Perform certificate analysis
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Retrieving certificate...", total=None)

            # Execute certificate analysis
            cert_info = analyzer.get_certificate_info(host, port)

            progress.update(task, completed=True)

        # Display results
        if output_format == 'table':
            display_certificate_results_table([cert_info])
        elif output_format == 'json':
            display_certificate_results_json([cert_info])
        elif output_format == 'csv':
            display_certificate_results_csv([cert_info])

        # Save output file if specified
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            if output_path.suffix.lower() == '.csv':
                analyzer.export_results_csv([cert_info], str(output_path))
            else:
                # Default to JSON
                analyzer.export_results_json([cert_info], str(output_path))

            console.print(f"[green]Results saved to {output_path}[/green]")

        # Exit with appropriate code based on certificate status
        if cert_info.is_expired:
            console.print(f"[red]❌ Certificate has expired[/red]")
            sys.exit(1)
        elif cert_info.expires_soon:
            console.print(f"[yellow]⚠️ Certificate expires soon ({cert_info.days_until_expiry} days)[/yellow]")
        elif cert_info.security_issues:
            console.print(f"[yellow]⚠️ Certificate has {len(cert_info.security_issues)} security issue(s)[/yellow]")
        else:
            console.print(f"[green]✅ Certificate appears secure[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.error(f"Certificate analysis failed: {e}")
        sys.exit(1)


@main_cli.command()
@click.option('--query', help='Search query (e.g., "nginx 1.18.0", "apache httpd")')
@click.option('--cve', help='Look up specific CVE ID (e.g., "CVE-2022-12345")')
@click.option('--latest', type=int, default=10, help='Number of results to show (default: 10)')
@click.option('--output', '-o', type=click.Path(),
              help='Output file path (JSON or Markdown based on extension)')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json', 'markdown']),
              default='table', help='Output format (default: table)')
@click.option('--critical-only', is_flag=True,
              help='Show only critical and high severity CVEs')
@click.option('--no-cache', is_flag=True,
              help='Disable result caching')
@click.pass_context
def cve(ctx, query, cve, latest, output, output_format, critical_only, no_cache):
    """
    Look up CVE vulnerabilities using public databases.

    Searches multiple vulnerability databases for CVE information:
    - Vulners API for comprehensive vulnerability data
    - NVD (National Vulnerability Database) for official CVE information
    - CVSS scoring and severity analysis
    - Exploitability and impact assessment

    Examples:

    \b
    # Search for nginx vulnerabilities
    netsecurex cve --query "nginx 1.18.0"

    \b
    # Search for Apache HTTP Server vulnerabilities
    netsecurex cve --query "apache httpd 2.4.51"

    \b
    # Look up specific CVE
    netsecurex cve --cve CVE-2022-12345

    \b
    # Show only critical/high severity CVEs
    netsecurex cve --query "openssh 8.2" --critical-only

    \b
    # Export results to JSON
    netsecurex cve --query "log4j" --format json --output cve_results.json

    \b
    # Generate markdown report
    netsecurex cve --query "nginx" --latest 20 --format markdown --output report.md
    """
    try:
        # Validate input
        if cve and query:
            console.print("[red]Error: Cannot specify both --query and --cve[/red]")
            sys.exit(1)

        if not cve and not query:
            console.print("[red]Error: Must specify either --query or --cve[/red]")
            sys.exit(1)

        # Initialize CVE lookup
        lookup = CVELookupNew()

        if cve:
            # Look up specific CVE
            console.print(f"[blue]Looking up CVE: {cve}[/blue]")
            console.print()

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Retrieving CVE information...", total=None)

                # Execute CVE lookup
                cve_info = asyncio.run(lookup.lookup_cve_by_id(cve))

                progress.update(task, completed=True)

            if cve_info:
                results = [cve_info]
            else:
                console.print(f"[red]CVE {cve} not found[/red]")
                sys.exit(1)
        else:
            # Search for CVEs
            console.print(f"[blue]Searching for CVEs: {query}[/blue]")
            console.print(f"Limit: {latest} results")
            console.print()

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Searching vulnerability databases...", total=None)

                # Execute CVE search
                results = asyncio.run(lookup.search_cves(query, latest, use_cache=not no_cache))

                progress.update(task, completed=True)

        # Filter critical/high only if requested
        if critical_only:
            results = [r for r in results if CVELookupNew.is_critical_or_high(r)]
            if not results:
                console.print("[green]No critical or high severity CVEs found[/green]")
                return

        # Display results
        if output_format == 'table':
            display_cve_results_table(results, query or cve)
        elif output_format == 'json':
            display_cve_results_json(results)
        elif output_format == 'markdown':
            display_cve_results_markdown(results, query or cve)

        # Save output file if specified
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            if output_path.suffix.lower() == '.md':
                lookup.export_results_markdown(results, str(output_path), query or cve)
            else:
                # Default to JSON
                lookup.export_results_json(results, str(output_path))

            console.print(f"[green]Results saved to {output_path}[/green]")

        # Exit with appropriate code based on severity
        critical_high_count = len([r for r in results if CVELookupNew.is_critical_or_high(r)])

        if critical_high_count > 0:
            console.print(f"[red]⚠️ Found {critical_high_count} critical/high severity CVE(s)[/red]")
            sys.exit(1)
        elif results:
            console.print(f"[green]✅ Found {len(results)} CVE(s) - no critical/high severity issues[/green]")
        else:
            console.print("[green]No CVEs found for the specified query[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.error(f"CVE lookup failed: {e}")
        sys.exit(1)


@main_cli.command()
@click.option('--ip', help='Single IP address to assess')
@click.option('--file', 'ip_file', type=click.Path(exists=True),
              help='File containing IP addresses (one per line)')
@click.option('--min-score', type=float, default=0.0,
              help='Minimum threat score to display (0-100)')
@click.option('--output', '-o', type=click.Path(),
              help='Output file path (JSON format)')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json']),
              default='table', help='Output format (default: table)')
@click.pass_context
def iprep(ctx, ip, ip_file, min_score, output, output_format):
    """
    Assess IP reputation using threat intelligence APIs.

    Queries multiple threat intelligence providers to assess IP reputation:
    - AbuseIPDB for abuse confidence and reporting data
    - IPQualityScore for fraud detection and risk scoring
    - VirusTotal for malware and threat detection (optional)

    Examples:

    \b
    # Check single IP address
    netsecurex iprep --ip 8.8.8.8

    \b
    # Check multiple IPs from file
    netsecurex iprep --file bad_ips.txt

    \b
    # Show only high-risk IPs (score >= 60)
    netsecurex iprep --file ip_list.txt --min-score 60

    \b
    # Export results to JSON
    netsecurex iprep --ip 1.2.3.4 --format json --output reputation_report.json

    \b
    # Batch assessment with filtering
    netsecurex iprep --file targets.txt --min-score 50 --format table
    """
    try:
        # Validate input
        if not ip and not ip_file:
            console.print("[red]Error: Must specify either --ip or --file[/red]")
            sys.exit(1)

        if ip and ip_file:
            console.print("[red]Error: Cannot specify both --ip and --file[/red]")
            sys.exit(1)

        # Collect IP addresses
        ip_addresses = []
        if ip:
            ip_addresses = [ip]
        elif ip_file:
            with open(ip_file, 'r') as f:
                ip_addresses = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        if not ip_addresses:
            console.print("[red]Error: No valid IP addresses found[/red]")
            sys.exit(1)

        console.print(f"[blue]Assessing reputation for {len(ip_addresses)} IP address(es)...[/blue]")

        # Initialize IP reputation assessment
        assessor = IPReputationAssessment()

        if not assessor.providers:
            console.print("[red]Error: No reputation providers available.[/red]")
            console.print("[yellow]Please set API keys in .env file:[/yellow]")
            console.print("- ABUSEIPDB_API_KEY=your_key_here")
            console.print("- IPQUALITYSCORE_API_KEY=your_key_here (optional)")
            console.print("- VIRUSTOTAL_API_KEY=your_key_here (optional)")
            sys.exit(1)

        # Show available providers
        console.print(f"Available providers: {', '.join(assessor.providers.keys())}")
        console.print()

        # Run reputation assessment with progress indicator
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Assessing IP reputation...", total=None)

            # Execute reputation assessment
            if len(ip_addresses) == 1:
                results = [asyncio.run(assessor.assess_ip_reputation(ip_addresses[0]))]
            else:
                results = asyncio.run(assessor.assess_multiple_ips(ip_addresses))

            progress.update(task, completed=True)

        # Filter by minimum score if specified
        if min_score > 0:
            filtered_results = assessor.filter_by_score(results, min_score)
            if not filtered_results:
                console.print(f"[green]No IPs found with threat score >= {min_score}[/green]")
                return
            results = filtered_results

        # Display results
        if output_format == 'table':
            display_ip_reputation_results_table(results)
        else:
            formatted_output = json.dumps([result.to_dict() for result in results], indent=2, default=str)
            console.print(formatted_output)

        # Save output file if specified
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            assessor.export_results_json(results, str(output_path))
            console.print(f"[green]Results saved to {output_path}[/green]")

        # Exit with appropriate code
        high_risk_count = len([r for r in results if r.threat_level in ['HIGH', 'CRITICAL']])
        malicious_count = len([r for r in results if r.is_malicious])

        if malicious_count > 0:
            console.print(f"[red]⚠️ Found {malicious_count} malicious IP(s)[/red]")
            sys.exit(1)
        elif high_risk_count > 0:
            console.print(f"[yellow]⚠️ Found {high_risk_count} high-risk IP(s)[/yellow]")
        else:
            console.print(f"[green]✅ All {len(results)} IP(s) appear clean[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.error(f"IP reputation assessment failed: {e}")
        sys.exit(1)


def display_scan_results_table(summary):
    """Display scan results in a formatted table."""
    # Summary table
    summary_table = Table(title=f"Port Scan Summary - {summary.target}")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="magenta")
    
    summary_table.add_row("Scan Duration", f"{summary.scan_duration:.2f} seconds")
    summary_table.add_row("Total Ports", str(summary.total_ports))
    summary_table.add_row("Open Ports", str(summary.open_ports))
    summary_table.add_row("Closed Ports", str(summary.closed_ports))
    summary_table.add_row("Filtered Ports", str(summary.filtered_ports))
    summary_table.add_row("Errors", str(summary.errors))
    
    console.print(summary_table)
    console.print()
    
    # Open ports table
    if summary.open_ports > 0:
        ports_table = Table(title="Open Ports")
        ports_table.add_column("IP", style="cyan")
        ports_table.add_column("Port", style="magenta")
        ports_table.add_column("Service", style="green")
        ports_table.add_column("Response Time", style="yellow")
        ports_table.add_column("Banner", style="blue")
        
        for result in summary.results:
            if result.status == 'open':
                response_time = f"{result.response_time:.3f}s" if result.response_time else "N/A"
                banner = result.banner[:50] + "..." if result.banner and len(result.banner) > 50 else result.banner or ""
                
                ports_table.add_row(
                    result.ip,
                    str(result.port),
                    result.service or "unknown",
                    response_time,
                    banner
                )
        
        console.print(ports_table)
    else:
        console.print("[yellow]No open ports found[/yellow]")


def parse_ssl_target(target: str, default_port: int) -> tuple:
    """Parse SSL target and extract hostname/port."""
    from urllib.parse import urlparse

    # If target looks like a URL, parse it
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == 'https' else default_port)
        return hostname, port

    # If target contains port (host:port format)
    if ':' in target and not target.count(':') > 1:  # Not IPv6
        try:
            hostname, port_str = target.rsplit(':', 1)
            port = int(port_str)
            return hostname, port
        except ValueError:
            pass

    # Default case
    return target, default_port


def display_ssl_results_table(result):
    """Display SSL analysis results in a formatted table."""
    from rich.panel import Panel

    # Status panel with color coding
    status_colors = {
        'valid': 'green',
        'expired': 'red',
        'self_signed': 'yellow',
        'invalid': 'red',
        'error': 'red'
    }

    status_emojis = {
        'valid': '✅',
        'expired': '❌',
        'self_signed': '⚠️',
        'invalid': '❌',
        'error': '💥'
    }

    color = status_colors.get(result.status, 'white')
    emoji = status_emojis.get(result.status, '❓')

    # Main status panel
    status_text = f"{emoji} {result.status.upper()}"
    if result.error:
        status_text += f"\nError: {result.error}"

    console.print(Panel(
        status_text,
        title=f"SSL Certificate Status - {result.target}:{result.port}",
        border_style=color
    ))

    if result.error:
        return

    # Certificate details table
    cert_table = Table(title="Certificate Details")
    cert_table.add_column("Property", style="cyan")
    cert_table.add_column("Value", style="magenta")

    if result.common_name:
        cert_table.add_row("Common Name", result.common_name)
    if result.subject:
        cert_table.add_row("Subject", result.subject)
    if result.issuer:
        cert_table.add_row("Issuer", result.issuer)
    if result.issued_on:
        cert_table.add_row("Issued On", result.issued_on)
    if result.expires_on:
        expiry_text = result.expires_on
        if result.days_until_expiry is not None:
            if result.days_until_expiry < 0:
                expiry_text += f" (EXPIRED {abs(result.days_until_expiry)} days ago)"
            elif result.days_until_expiry < 30:
                expiry_text += f" (⚠️ expires in {result.days_until_expiry} days)"
            else:
                expiry_text += f" (expires in {result.days_until_expiry} days)"
        cert_table.add_row("Expires On", expiry_text)

    console.print(cert_table)
    console.print()

    # Connection details table
    conn_table = Table(title="Connection Details")
    conn_table.add_column("Property", style="cyan")
    conn_table.add_column("Value", style="green")

    if result.tls_version:
        conn_table.add_row("TLS Version", result.tls_version)
    if result.cipher_suite:
        conn_table.add_row("Cipher Suite", result.cipher_suite)
    if result.signature_algorithm:
        conn_table.add_row("Signature Algorithm", result.signature_algorithm)

    console.print(conn_table)

    # Security warnings
    warnings = []
    if result.is_self_signed:
        warnings.append("⚠️ Certificate is self-signed")
    if result.is_expired:
        warnings.append("❌ Certificate is expired")
    if result.days_until_expiry is not None and 0 <= result.days_until_expiry < 30:
        warnings.append(f"⚠️ Certificate expires soon ({result.days_until_expiry} days)")

    if warnings:
        console.print()
        console.print(Panel(
            "\n".join(warnings),
            title="Security Warnings",
            border_style="yellow"
        ))

    # SAN list
    if result.san_list:
        console.print()
        san_table = Table(title="Subject Alternative Names")
        san_table.add_column("DNS/IP", style="blue")

        for san in result.san_list:
            san_table.add_row(san)

        console.print(san_table)


def generate_ssl_report(result, report_path: Path):
    """Generate a markdown report from SSL analysis results."""
    report_path.parent.mkdir(parents=True, exist_ok=True)

    with open(report_path, 'w') as f:
        f.write(f"# SSL/TLS Certificate Analysis Report\n\n")
        f.write(f"**Target:** {result.target}:{result.port}\n")
        f.write(f"**Analysis Date:** {result.timestamp}\n")
        f.write(f"**Status:** {result.status.upper()}\n\n")

        if result.error:
            f.write(f"**Error:** {result.error}\n\n")
            return

        f.write("## Certificate Details\n\n")
        if result.common_name:
            f.write(f"- **Common Name:** {result.common_name}\n")
        if result.subject:
            f.write(f"- **Subject:** {result.subject}\n")
        if result.issuer:
            f.write(f"- **Issuer:** {result.issuer}\n")
        if result.issued_on:
            f.write(f"- **Issued On:** {result.issued_on}\n")
        if result.expires_on:
            f.write(f"- **Expires On:** {result.expires_on}\n")
        if result.days_until_expiry is not None:
            f.write(f"- **Days Until Expiry:** {result.days_until_expiry}\n")

        f.write("\n## Connection Details\n\n")
        if result.tls_version:
            f.write(f"- **TLS Version:** {result.tls_version}\n")
        if result.cipher_suite:
            f.write(f"- **Cipher Suite:** {result.cipher_suite}\n")
        if result.signature_algorithm:
            f.write(f"- **Signature Algorithm:** {result.signature_algorithm}\n")

        f.write("\n## Security Assessment\n\n")
        if result.status == 'valid':
            f.write("✅ **Certificate is valid and trusted**\n")
        elif result.status == 'expired':
            f.write("❌ **Certificate is expired**\n")
        elif result.status == 'self_signed':
            f.write("⚠️ **Certificate is self-signed**\n")
        elif result.status == 'invalid':
            f.write("❌ **Certificate is invalid**\n")

        if result.san_list:
            f.write("\n## Subject Alternative Names\n\n")
            for san in result.san_list:
                f.write(f"- {san}\n")


def generate_scan_report(summary, report_path: Path):
    """Generate a markdown report from scan results."""
    report_path.parent.mkdir(parents=True, exist_ok=True)

    with open(report_path, 'w') as f:
        f.write(f"# Port Scan Report\n\n")
        f.write(f"**Target:** {summary.target}\n")
        f.write(f"**Scan Date:** {summary.start_time}\n")
        f.write(f"**Duration:** {summary.scan_duration:.2f} seconds\n\n")

        f.write("## Summary\n\n")
        f.write(f"- Total Ports Scanned: {summary.total_ports}\n")
        f.write(f"- Open Ports: {summary.open_ports}\n")
        f.write(f"- Closed Ports: {summary.closed_ports}\n")
        f.write(f"- Filtered Ports: {summary.filtered_ports}\n")
        f.write(f"- Errors: {summary.errors}\n\n")

        if summary.open_ports > 0:
            f.write("## Open Ports\n\n")
            f.write("| IP | Port | Service | Response Time | Banner |\n")
            f.write("|----|----|---------|---------------|--------|\n")

            for result in summary.results:
                if result.status == 'open':
                    response_time = f"{result.response_time:.3f}s" if result.response_time else "N/A"
                    banner = result.banner.replace('|', '\\|') if result.banner else ""
                    service = result.service or "unknown"

                    f.write(f"| {result.ip} | {result.port} | {service} | {response_time} | {banner} |\n")

        f.write("\n## Scan Details\n\n")
        f.write(f"- Start Time: {summary.start_time}\n")
        f.write(f"- End Time: {summary.end_time}\n")
        f.write(f"- Total Duration: {summary.scan_duration:.2f} seconds\n")


async def handle_bulk_cve_lookup(lookup, bulk_file_path, max_results, severity_filter):
    """Handle bulk CVE lookup from file."""
    with open(bulk_file_path, 'r') as f:
        product_versions = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if not product_versions:
        raise ValueError("No valid product:version entries found in bulk file")

    console.print(f"[blue]Processing {len(product_versions)} products from bulk file...[/blue]")

    results = await lookup.bulk_lookup(product_versions, max_results)

    # Apply severity filter to all results
    if severity_filter:
        for product_version in results:
            results[product_version] = filter_by_severity(results[product_version], severity_filter)

    return results


def filter_by_severity(results, min_severity):
    """Filter CVE results by minimum severity level."""
    severity_levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    min_level = severity_levels.get(min_severity.upper(), 0)

    return [
        result for result in results
        if severity_levels.get(result.severity, 0) >= min_level
    ]


def display_cve_results_table(results, target):
    """Display CVE results in a formatted table."""
    from rich.panel import Panel

    if not results:
        console.print(Panel(
            "No CVEs found for the specified product and version.",
            title=f"CVE Lookup Results - {target}",
            border_style="green"
        ))
        return

    # Summary panel
    high_critical_count = len([r for r in results if r.severity in ['HIGH', 'CRITICAL']])

    summary_color = "red" if high_critical_count > 0 else "yellow" if results else "green"
    summary_text = f"Found {len(results)} CVE(s)"
    if high_critical_count > 0:
        summary_text += f" ({high_critical_count} high/critical severity)"

    console.print(Panel(
        summary_text,
        title=f"CVE Lookup Results - {target}",
        border_style=summary_color
    ))
    console.print()

    # CVE details table
    cve_table = Table(title="Vulnerability Details")
    cve_table.add_column("CVE ID", style="cyan")
    cve_table.add_column("Severity", style="bold")
    cve_table.add_column("Score", style="magenta")
    cve_table.add_column("Published", style="blue")
    cve_table.add_column("Summary", style="white", max_width=60)

    for result in results:
        # Color code severity
        severity_colors = {
            'CRITICAL': '[red]🔴 CRITICAL[/red]',
            'HIGH': '[red]🟠 HIGH[/red]',
            'MEDIUM': '[yellow]🟡 MEDIUM[/yellow]',
            'LOW': '[green]🟢 LOW[/green]',
            'UNKNOWN': '[white]⚪ UNKNOWN[/white]'
        }

        severity_display = severity_colors.get(result.severity, result.severity)
        score_display = str(result.primary_score) if result.primary_score else "N/A"
        published_display = result.published_date or "N/A"
        summary_display = result.summary[:80] + "..." if len(result.summary) > 80 else result.summary

        cve_table.add_row(
            result.cve_id,
            severity_display,
            score_display,
            published_display,
            summary_display
        )

    console.print(cve_table)


def display_bulk_cve_results(results, severity_filter):
    """Display bulk CVE lookup results."""
    total_cves = sum(len(cves) for cves in results.values())

    console.print(f"\n[bold]Bulk CVE Lookup Results[/bold]")
    console.print(f"Total products scanned: {len(results)}")
    console.print(f"Total CVEs found: {total_cves}")
    if severity_filter:
        console.print(f"Filtered by minimum severity: {severity_filter}")
    console.print()

    # Summary table
    summary_table = Table(title="CVE Summary by Product")
    summary_table.add_column("Product:Version", style="cyan")
    summary_table.add_column("CVE Count", style="magenta")
    summary_table.add_column("Highest Severity", style="bold")
    summary_table.add_column("Max Score", style="red")

    for product_version, cves in results.items():
        if not cves:
            summary_table.add_row(product_version, "0", "N/A", "N/A")
            continue

        # Find highest severity and score
        severity_levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4, 'UNKNOWN': 0}
        highest_severity = max(cves, key=lambda x: severity_levels.get(x.severity, 0)).severity
        max_score = max((cve.primary_score for cve in cves if cve.primary_score), default=0)

        # Color code highest severity
        severity_colors = {
            'CRITICAL': '[red]🔴 CRITICAL[/red]',
            'HIGH': '[red]🟠 HIGH[/red]',
            'MEDIUM': '[yellow]🟡 MEDIUM[/yellow]',
            'LOW': '[green]🟢 LOW[/green]',
            'UNKNOWN': '[white]⚪ UNKNOWN[/white]'
        }

        severity_display = severity_colors.get(highest_severity, highest_severity)

        summary_table.add_row(
            product_version,
            str(len(cves)),
            severity_display,
            str(max_score) if max_score > 0 else "N/A"
        )

    console.print(summary_table)


def generate_cve_report(results, target, report_path):
    """Generate a markdown report from CVE results."""
    report_path.parent.mkdir(parents=True, exist_ok=True)

    with open(report_path, 'w') as f:
        f.write(f"# CVE Vulnerability Report\n\n")
        f.write(f"**Target:** {target}\n")
        f.write(f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"**Total CVEs Found:** {len(results)}\n\n")

        if not results:
            f.write("✅ **No CVEs found for the specified product and version.**\n\n")
            return

        # Severity summary
        severity_counts = {}
        for result in results:
            severity_counts[result.severity] = severity_counts.get(result.severity, 0) + 1

        f.write("## Severity Summary\n\n")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'UNKNOWN': '⚪'}[severity]
                f.write(f"- {emoji} **{severity}:** {count} CVE(s)\n")
        f.write("\n")

        # Detailed CVE list
        f.write("## Detailed CVE Information\n\n")

        for i, result in enumerate(results, 1):
            f.write(f"### {i}. {result.cve_id}\n\n")
            f.write(f"- **Severity:** {result.severity}\n")
            f.write(f"- **CVSS Score:** {result.primary_score or 'N/A'}\n")
            f.write(f"- **Published:** {result.published_date or 'N/A'}\n")
            f.write(f"- **Source:** {result.source_api or 'N/A'}\n\n")
            f.write(f"**Description:**\n{result.summary}\n\n")

            if result.references:
                f.write("**References:**\n")
                for ref in result.references[:3]:  # Limit to first 3 references
                    f.write(f"- {ref}\n")
                f.write("\n")


def generate_bulk_cve_report(results, report_path):
    """Generate a markdown report from bulk CVE results."""
    report_path.parent.mkdir(parents=True, exist_ok=True)

    total_cves = sum(len(cves) for cves in results.values())

    with open(report_path, 'w') as f:
        f.write(f"# Bulk CVE Vulnerability Report\n\n")
        f.write(f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"**Products Analyzed:** {len(results)}\n")
        f.write(f"**Total CVEs Found:** {total_cves}\n\n")

        # Summary table
        f.write("## Summary by Product\n\n")
        f.write("| Product:Version | CVE Count | Highest Severity | Max Score |\n")
        f.write("|-----------------|-----------|------------------|----------|\n")

        for product_version, cves in results.items():
            if not cves:
                f.write(f"| {product_version} | 0 | N/A | N/A |\n")
                continue

            severity_levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4, 'UNKNOWN': 0}
            highest_severity = max(cves, key=lambda x: severity_levels.get(x.severity, 0)).severity
            max_score = max((cve.primary_score for cve in cves if cve.primary_score), default=0)

            f.write(f"| {product_version} | {len(cves)} | {highest_severity} | {max_score or 'N/A'} |\n")

        f.write("\n")

        # Detailed results for each product
        for product_version, cves in results.items():
            if not cves:
                continue

            f.write(f"## {product_version}\n\n")
            f.write(f"Found {len(cves)} CVE(s):\n\n")

            for cve in cves:
                f.write(f"- **{cve.cve_id}** ({cve.severity}, Score: {cve.primary_score or 'N/A'})\n")
                f.write(f"  {cve.summary[:100]}{'...' if len(cve.summary) > 100 else ''}\n\n")


def display_banner_results_table(results, target):
    """Display banner grabbing results in a formatted table."""
    from rich.panel import Panel

    detected_count = len([r for r in results if r.status == "detected"])
    partial_count = len([r for r in results if r.status == "partial"])
    failed_count = len([r for r in results if r.status in ["failed", "timeout"]])

    # Summary panel
    summary_color = "green" if detected_count > 0 else "yellow"
    summary_text = f"Scanned {len(results)} ports\n"
    summary_text += f"Services detected: {detected_count}\n"
    summary_text += f"Partial detection: {partial_count}\n"
    summary_text += f"Failed/Timeout: {failed_count}"

    console.print(Panel(
        summary_text,
        title=f"Banner Scan Results - {target}",
        border_style=summary_color
    ))
    console.print()

    # Detected services table
    if detected_count > 0:
        services_table = Table(title="Detected Services")
        services_table.add_column("Port", style="cyan")
        services_table.add_column("Service", style="green")
        services_table.add_column("Product", style="magenta")
        services_table.add_column("Version", style="yellow")
        services_table.add_column("Confidence", style="blue")
        services_table.add_column("CVEs", style="red")

        for result in results:
            if result.status == "detected":
                cve_info = ""
                if result.additional_info and 'cves' in result.additional_info:
                    cve_count = len(result.additional_info['cves'])
                    if cve_count > 0:
                        cve_info = f"{cve_count} found"

                services_table.add_row(
                    str(result.port),
                    result.service or "unknown",
                    result.product or "unknown",
                    result.version or "unknown",
                    f"{result.confidence:.1%}",
                    cve_info
                )

        console.print(services_table)
        console.print()

    # CVE details if available
    cve_results = []
    for result in results:
        if result.additional_info and 'cves' in result.additional_info:
            for cve in result.additional_info['cves']:
                cve_results.append({
                    'service': f"{result.product}:{result.version}",
                    'port': result.port,
                    'cve': cve
                })

    if cve_results:
        console.print()
        cve_table = Table(title="Detected Vulnerabilities")
        cve_table.add_column("Service", style="cyan")
        cve_table.add_column("Port", style="blue")
        cve_table.add_column("CVE ID", style="red")
        cve_table.add_column("Severity", style="bold")
        cve_table.add_column("Score", style="magenta")

        for item in cve_results[:10]:  # Limit to first 10 CVEs
            cve = item['cve']
            severity_colors = {
                'CRITICAL': '[red]🔴 CRITICAL[/red]',
                'HIGH': '[red]🟠 HIGH[/red]',
                'MEDIUM': '[yellow]🟡 MEDIUM[/yellow]',
                'LOW': '[green]🟢 LOW[/green]',
                'UNKNOWN': '[white]⚪ UNKNOWN[/white]'
            }

            severity_display = severity_colors.get(cve.get('severity', 'UNKNOWN'), cve.get('severity', 'UNKNOWN'))
            score = cve.get('cvss_v3_score') or cve.get('cvss_v2_score') or 'N/A'

            cve_table.add_row(
                item['service'],
                str(item['port']),
                cve.get('cve_id', 'Unknown'),
                severity_display,
                str(score)
            )

        console.print(cve_table)


def generate_banner_report(results, target, report_path):
    """Generate a markdown report from banner scan results."""
    report_path.parent.mkdir(parents=True, exist_ok=True)

    detected_count = len([r for r in results if r.status == "detected"])

    with open(report_path, 'w') as f:
        f.write(f"# Banner Grabbing Report\n\n")
        f.write(f"**Target:** {target}\n")
        f.write(f"**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"**Ports Scanned:** {len(results)}\n")
        f.write(f"**Services Detected:** {detected_count}\n\n")

        if detected_count == 0:
            f.write("✅ **No services detected on scanned ports.**\n\n")
            return

        # Detected services summary
        f.write("## Detected Services\n\n")
        f.write("| Port | Service | Product | Version | Confidence |\n")
        f.write("|------|---------|---------|---------|------------|\n")

        for result in results:
            if result.status == "detected":
                f.write(f"| {result.port} | {result.service or 'unknown'} | "
                       f"{result.product or 'unknown'} | {result.version or 'unknown'} | "
                       f"{result.confidence:.1%} |\n")

        f.write("\n")

        # CVE information if available
        cve_found = False
        for result in results:
            if result.additional_info and 'cves' in result.additional_info:
                if not cve_found:
                    f.write("## Detected Vulnerabilities\n\n")
                    cve_found = True

                f.write(f"### {result.product}:{result.version} (Port {result.port})\n\n")

                for cve in result.additional_info['cves']:
                    f.write(f"- **{cve.get('cve_id', 'Unknown')}** ({cve.get('severity', 'Unknown')})\n")
                    f.write(f"  - Score: {cve.get('cvss_v3_score') or cve.get('cvss_v2_score') or 'N/A'}\n")
                    f.write(f"  - Published: {cve.get('published_date', 'Unknown')}\n")
                    summary = cve.get('summary', '')
                    f.write(f"  - Summary: {summary[:100]}{'...' if len(summary) > 100 else ''}\n\n")

        # Detailed service information
        f.write("## Detailed Service Information\n\n")

        for result in results:
            if result.status == "detected":
                f.write(f"### Port {result.port} - {result.service}\n\n")
                f.write(f"- **Product:** {result.product or 'Unknown'}\n")
                f.write(f"- **Version:** {result.version or 'Unknown'}\n")
                f.write(f"- **Confidence:** {result.confidence:.1%}\n")
                if result.banner:
                    f.write(f"- **Banner:** `{result.banner[:100]}{'...' if len(result.banner) > 100 else ''}`\n")
                f.write("\n")


def monitor_capture_stats(sniffer, duration):
    """Monitor and display real-time capture statistics."""
    import time
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.columns import Columns

    start_time = time.time()

    def create_stats_display():
        """Create real-time statistics display."""
        stats = sniffer.get_statistics()
        anomalies = sniffer.get_anomalies()

        # Main statistics table
        stats_table = Table(title="Capture Statistics")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="magenta")

        elapsed = time.time() - start_time
        stats_table.add_row("Elapsed Time", f"{elapsed:.1f}s")
        stats_table.add_row("Total Packets", str(stats['total_packets']))
        stats_table.add_row("Active Flows", str(stats['active_flows']))
        stats_table.add_row("Anomalies", str(len(anomalies)))

        # Protocol distribution table
        protocol_table = Table(title="Protocol Distribution")
        protocol_table.add_column("Protocol", style="green")
        protocol_table.add_column("Packets", style="yellow")

        for protocol, count in stats['protocols'].items():
            protocol_table.add_row(protocol.upper(), str(count))

        # Top ports table
        port_table = Table(title="Top Ports")
        port_table.add_column("Port", style="blue")
        port_table.add_column("Packets", style="yellow")

        for port, count in list(stats['top_ports'].items())[:5]:
            port_table.add_row(str(port), str(count))

        # Recent anomalies
        anomaly_panel = Panel(
            "\n".join([f"• {a['description']}" for a in anomalies[-5:]]) or "No anomalies detected",
            title="Recent Anomalies",
            border_style="red" if anomalies else "green"
        )

        return Columns([stats_table, protocol_table, port_table, anomaly_panel])

    # Live display
    with Live(create_stats_display(), refresh_per_second=2, console=console) as live:
        while sniffer.is_capturing:
            time.sleep(0.5)
            live.update(create_stats_display())

            if duration:
                elapsed = time.time() - start_time
                if elapsed >= duration:
                    break


def display_capture_results(sniffer):
    """Display packet capture results summary."""
    from rich.panel import Panel

    stats = sniffer.get_statistics()
    flows = sniffer.get_flows()
    anomalies = sniffer.get_anomalies()

    # Summary panel
    summary_text = f"Total Packets: {stats['total_packets']}\n"
    summary_text += f"Active Flows: {stats['active_flows']}\n"
    summary_text += f"Total Flows: {stats['total_flows']}\n"
    summary_text += f"Anomalies: {len(anomalies)}"

    panel_color = "red" if anomalies else "green"
    console.print(Panel(
        summary_text,
        title="Capture Summary",
        border_style=panel_color
    ))
    console.print()

    # Protocol distribution
    if stats['protocols']:
        protocol_table = Table(title="Protocol Distribution")
        protocol_table.add_column("Protocol", style="cyan")
        protocol_table.add_column("Packets", style="magenta")
        protocol_table.add_column("Percentage", style="yellow")

        total = stats['total_packets']
        for protocol, count in stats['protocols'].items():
            percentage = (count / total * 100) if total > 0 else 0
            protocol_table.add_row(
                protocol.upper(),
                str(count),
                f"{percentage:.1f}%"
            )

        console.print(protocol_table)
        console.print()

    # Top ports
    if stats['top_ports']:
        port_table = Table(title="Top Destination Ports")
        port_table.add_column("Port", style="blue")
        port_table.add_column("Packets", style="magenta")
        port_table.add_column("Service", style="green")

        for port, count in list(stats['top_ports'].items())[:10]:
            service = get_service_name_for_port(port)
            port_table.add_row(str(port), str(count), service)

        console.print(port_table)
        console.print()

    # Anomalies
    if anomalies:
        console.print("[red]⚠️ Detected Anomalies:[/red]")

        anomaly_table = Table()
        anomaly_table.add_column("Type", style="red")
        anomaly_table.add_column("Source IP", style="cyan")
        anomaly_table.add_column("Description", style="white")

        for anomaly in anomalies[-10:]:  # Show last 10 anomalies
            anomaly_table.add_row(
                anomaly['type'].replace('_', ' ').title(),
                anomaly['src_ip'],
                anomaly['description']
            )

        console.print(anomaly_table)
        console.print()

    # Top flows
    active_flows = [f for f in flows if f['state'] == 'active']
    if active_flows:
        flow_table = Table(title="Top Active Flows")
        flow_table.add_column("Source", style="cyan")
        flow_table.add_column("Destination", style="blue")
        flow_table.add_column("Protocol", style="green")
        flow_table.add_column("Packets", style="magenta")
        flow_table.add_column("Bytes", style="yellow")

        # Sort by packet count
        sorted_flows = sorted(active_flows, key=lambda x: x['packet_count'], reverse=True)

        for flow in sorted_flows[:10]:
            src = f"{flow['src_ip']}:{flow['src_port']}"
            dst = f"{flow['dst_ip']}:{flow['dst_port']}"
            flow_table.add_row(
                src,
                dst,
                flow['protocol'].upper(),
                str(flow['packet_count']),
                str(flow['bytes_total'])
            )

        console.print(flow_table)


def get_service_name_for_port(port):
    """Get service name for port number."""
    common_ports = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        993: 'IMAPS',
        995: 'POP3S',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        27017: 'MongoDB'
    }
    return common_ports.get(port, 'Unknown')


def display_reputation_results_table(results):
    """Display IP reputation results in a formatted table."""
    from rich.panel import Panel

    if not results:
        console.print(Panel(
            "No IP reputation results found.",
            title="IP Reputation Results",
            border_style="yellow"
        ))
        return

    # Summary statistics
    risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'CLEAN': 0, 'UNKNOWN': 0}
    malicious_count = 0

    for result in results:
        risk_counts[result.risk_level] += 1
        if result.is_malicious:
            malicious_count += 1

    # Summary panel
    summary_text = f"Total IPs: {len(results)}\n"
    summary_text += f"Malicious: {malicious_count}\n"
    summary_text += f"High Risk: {risk_counts['HIGH'] + risk_counts['CRITICAL']}\n"
    summary_text += f"Clean: {risk_counts['CLEAN']}"

    panel_color = "red" if malicious_count > 0 else "yellow" if risk_counts['HIGH'] + risk_counts['CRITICAL'] > 0 else "green"
    console.print(Panel(
        summary_text,
        title="IP Reputation Summary",
        border_style=panel_color
    ))
    console.print()

    # Main results table
    results_table = Table(title="IP Reputation Analysis")
    results_table.add_column("IP Address", style="cyan")
    results_table.add_column("Risk Level", style="bold")
    results_table.add_column("Score", style="magenta")
    results_table.add_column("Malicious", style="red")
    results_table.add_column("Confidence", style="blue")
    results_table.add_column("Location", style="green")
    results_table.add_column("Threats", style="yellow")
    results_table.add_column("Providers", style="white")

    for result in results:
        # Color code risk level
        risk_colors = {
            'CRITICAL': '[red]🔴 CRITICAL[/red]',
            'HIGH': '[red]🟠 HIGH[/red]',
            'MEDIUM': '[yellow]🟡 MEDIUM[/yellow]',
            'LOW': '[green]🟢 LOW[/green]',
            'CLEAN': '[green]✅ CLEAN[/green]',
            'UNKNOWN': '[white]⚪ UNKNOWN[/white]'
        }

        risk_display = risk_colors.get(result.risk_level, result.risk_level)
        score_display = f"{result.overall_risk_score:.1f}/100"
        malicious_display = "Yes" if result.is_malicious else "No"
        confidence_display = f"{result.confidence_score:.0f}%"

        # Location info
        location_parts = []
        if result.geolocation:
            if 'city' in result.geolocation:
                location_parts.append(result.geolocation['city'])
            if 'country' in result.geolocation:
                location_parts.append(result.geolocation['country'])
            elif 'country_code' in result.geolocation:
                location_parts.append(result.geolocation['country_code'])

        location_display = ', '.join(location_parts) if location_parts else "Unknown"

        # Threat categories
        threat_display = ', '.join(list(result.threat_categories)[:3]) if result.threat_categories else "None"
        if len(result.threat_categories) > 3:
            threat_display += "..."

        # Providers
        providers_display = ', '.join(result.providers_checked)

        results_table.add_row(
            result.ip_address,
            risk_display,
            score_display,
            malicious_display,
            confidence_display,
            location_display,
            threat_display,
            providers_display
        )

    console.print(results_table)
    console.print()

    # Detailed threat information for high-risk IPs
    high_risk_ips = [r for r in results if r.risk_level in ['HIGH', 'CRITICAL']]
    if high_risk_ips:
        console.print("[red]⚠️ High-Risk IP Details:[/red]")

        for result in high_risk_ips:
            threat_panel_content = f"Risk Score: {result.overall_risk_score:.1f}/100\n"

            if result.threat_categories:
                threat_panel_content += f"Threats: {', '.join(result.threat_categories)}\n"

            if result.geolocation:
                location_info = []
                if 'city' in result.geolocation:
                    location_info.append(result.geolocation['city'])
                if 'country' in result.geolocation:
                    location_info.append(result.geolocation['country'])
                if location_info:
                    threat_panel_content += f"Location: {', '.join(location_info)}\n"

            if result.asn_info:
                asn_info = []
                if 'organization' in result.asn_info:
                    asn_info.append(result.asn_info['organization'])
                if 'isp' in result.asn_info:
                    asn_info.append(result.asn_info['isp'])
                if asn_info:
                    threat_panel_content += f"Organization: {', '.join(asn_info)}\n"

            if result.last_seen:
                threat_panel_content += f"Last Seen: {result.last_seen}"

            console.print(Panel(
                threat_panel_content.strip(),
                title=f"{result.ip_address} - {result.risk_level}",
                border_style="red"
            ))


def display_firewall_results_table(results, traceroute_hops, target, protocol):
    """Display firewall test results in a formatted table."""
    from rich.panel import Panel

    if not results:
        console.print(Panel(
            "No firewall test results found.",
            title=f"Firewall Test Results - {target}",
            border_style="yellow"
        ))
        return

    # Summary statistics
    open_count = len([r for r in results if r.status == 'open'])
    closed_count = len([r for r in results if r.status == 'closed'])
    filtered_count = len([r for r in results if r.status == 'filtered'])
    error_count = len([r for r in results if r.status == 'error'])

    # Summary panel
    summary_text = f"Protocol: {protocol.upper()}\n"
    summary_text += f"Total Ports: {len(results)}\n"
    summary_text += f"Open: {open_count}\n"
    summary_text += f"Closed: {closed_count}\n"
    summary_text += f"Filtered: {filtered_count}\n"
    summary_text += f"Errors: {error_count}"

    panel_color = "green" if open_count > 0 else "yellow" if filtered_count > 0 else "red"
    console.print(Panel(
        summary_text,
        title=f"Firewall Test Summary - {target}",
        border_style=panel_color
    ))
    console.print()

    # Main results table
    results_table = Table(title=f"{protocol.upper()} Port Test Results")
    results_table.add_column("Port", style="cyan")
    results_table.add_column("Status", style="bold")
    results_table.add_column("Response Time", style="magenta")
    results_table.add_column("Notes", style="white")

    # Sort results by port number
    sorted_results = sorted(results, key=lambda x: x.port)

    for result in sorted_results:
        # Color code status
        status_colors = {
            'open': '[green]🟢 OPEN[/green]',
            'closed': '[red]🔴 CLOSED[/red]',
            'filtered': '[yellow]🟡 FILTERED[/yellow]',
            'error': '[red]❌ ERROR[/red]'
        }

        status_display = status_colors.get(result.status, result.status)

        # Format response time
        if result.response_time is not None:
            response_time_display = f"{result.response_time*1000:.1f}ms"
        else:
            response_time_display = "N/A"

        # Notes
        notes = ""
        if result.status == 'filtered':
            notes = "Likely blocked by firewall"
        elif result.status == 'error' and result.error_message:
            notes = result.error_message[:50] + "..." if len(result.error_message) > 50 else result.error_message

        results_table.add_row(
            str(result.port),
            status_display,
            response_time_display,
            notes
        )

    console.print(results_table)
    console.print()

    # Open ports summary
    open_ports = [r for r in results if r.status == 'open']
    if open_ports:
        console.print("[green]🟢 Open Ports:[/green]")
        open_ports_list = [str(r.port) for r in open_ports]
        console.print(f"   {', '.join(open_ports_list)}")
        console.print()

    # Filtered ports summary
    filtered_ports = [r for r in results if r.status == 'filtered']
    if filtered_ports:
        console.print("[yellow]🟡 Filtered Ports (Likely Firewall Blocked):[/yellow]")
        filtered_ports_list = [str(r.port) for r in filtered_ports]
        console.print(f"   {', '.join(filtered_ports_list)}")
        console.print()

    # Traceroute results
    if traceroute_hops:
        console.print("[blue]📍 Traceroute Results:[/blue]")

        traceroute_table = Table(title="Network Path")
        traceroute_table.add_column("Hop", style="cyan")
        traceroute_table.add_column("IP Address", style="green")
        traceroute_table.add_column("Hostname", style="blue")
        traceroute_table.add_column("Response Time", style="magenta")

        for hop in traceroute_hops:
            if hop.timeout:
                traceroute_table.add_row(
                    str(hop.hop_number),
                    "* * *",
                    "Timeout",
                    "N/A"
                )
            else:
                response_time = f"{hop.response_time:.1f}ms" if hop.response_time else "N/A"
                hostname = hop.hostname or "N/A"

                traceroute_table.add_row(
                    str(hop.hop_number),
                    hop.ip_address or "N/A",
                    hostname,
                    response_time
                )

        console.print(traceroute_table)


def display_firewall_results_json(results, traceroute_hops):
    """Display firewall test results in JSON format."""
    output_data = {
        'firewall_tests': [result.to_dict() for result in results],
        'traceroute': [hop.to_dict() for hop in traceroute_hops] if traceroute_hops else []
    }

    formatted_output = json.dumps(output_data, indent=2, default=str)
    console.print(formatted_output)


def display_firewall_results_csv(results):
    """Display firewall test results in CSV format."""
    import io

    output = io.StringIO()
    fieldnames = ['target', 'port', 'protocol', 'status', 'response_time', 'error_message', 'timestamp']
    writer = csv.DictWriter(output, fieldnames=fieldnames)

    writer.writeheader()
    for result in results:
        writer.writerow(result.to_dict())

    console.print(output.getvalue())


def display_certificate_results_table(results):
    """Display certificate analysis results in a formatted table."""
    from rich.panel import Panel

    if not results:
        console.print(Panel(
            "No certificate analysis results found.",
            title="Certificate Analysis Results",
            border_style="yellow"
        ))
        return

    for cert_info in results:
        # Determine panel color based on certificate status
        if cert_info.is_expired:
            panel_color = "red"
            status_icon = "❌"
            status_text = "EXPIRED"
        elif cert_info.expires_soon:
            panel_color = "yellow"
            status_icon = "⚠️"
            status_text = "EXPIRES SOON"
        elif cert_info.security_issues:
            panel_color = "yellow"
            status_icon = "⚠️"
            status_text = "SECURITY ISSUES"
        else:
            panel_color = "green"
            status_icon = "✅"
            status_text = "SECURE"

        # Certificate grade
        from core.cert_analyzer import CertificateAnalyzer
        grade = CertificateAnalyzer.get_certificate_grade(cert_info)

        # Summary panel
        summary_text = f"Host: {cert_info.host}:{cert_info.port}\n"
        summary_text += f"Status: {status_icon} {status_text}\n"
        summary_text += f"Security Grade: {grade}\n"
        if cert_info.days_until_expiry is not None:
            summary_text += f"Days Until Expiry: {cert_info.days_until_expiry}"

        console.print(Panel(
            summary_text,
            title=f"Certificate Analysis - {cert_info.host}",
            border_style=panel_color
        ))
        console.print()

        # Detailed certificate information table
        cert_table = Table(title="Certificate Details")
        cert_table.add_column("Property", style="cyan")
        cert_table.add_column("Value", style="white")

        # Basic information
        cert_table.add_row("Common Name", cert_info.common_name or "N/A")
        cert_table.add_row("Issuer", cert_info.issuer or "N/A")
        cert_table.add_row("Valid From", cert_info.not_before or "N/A")
        cert_table.add_row("Valid Until", cert_info.not_after or "N/A")

        # Subject Alternative Names
        if cert_info.subject_alt_names:
            san_text = ", ".join(cert_info.subject_alt_names[:5])
            if len(cert_info.subject_alt_names) > 5:
                san_text += f" (+{len(cert_info.subject_alt_names) - 5} more)"
            cert_table.add_row("Subject Alt Names", san_text)

        # Technical details
        if cert_info.signature_algorithm:
            cert_table.add_row("Signature Algorithm", cert_info.signature_algorithm)

        if cert_info.key_algorithm and cert_info.key_size:
            cert_table.add_row("Key Algorithm", f"{cert_info.key_algorithm} {cert_info.key_size} bits")

        if cert_info.serial_number:
            cert_table.add_row("Serial Number", cert_info.serial_number)

        # Security features
        cert_table.add_row("Self-Signed", "Yes" if cert_info.is_self_signed else "No")
        cert_table.add_row("Certificate Authority", "Yes" if cert_info.is_ca else "No")
        cert_table.add_row("Certificate Transparency", "Yes" if cert_info.has_sct else "No")

        if cert_info.certificate_chain_length > 0:
            cert_table.add_row("Chain Length", str(cert_info.certificate_chain_length))

        console.print(cert_table)
        console.print()

        # Security issues
        if cert_info.security_issues:
            console.print("[red]🚨 Security Issues:[/red]")

            issues_table = Table()
            issues_table.add_column("Issue", style="red")

            for issue in cert_info.security_issues:
                issues_table.add_row(issue)

            console.print(issues_table)
            console.print()

        # OCSP and CRL URLs
        if cert_info.ocsp_urls or cert_info.crl_urls:
            console.print("[blue]📋 Revocation Information:[/blue]")

            if cert_info.ocsp_urls:
                console.print(f"OCSP URLs: {', '.join(cert_info.ocsp_urls)}")

            if cert_info.crl_urls:
                console.print(f"CRL URLs: {', '.join(cert_info.crl_urls)}")

            console.print()


def display_certificate_results_json(results):
    """Display certificate analysis results in JSON format."""
    output_data = {
        'certificates': [result.to_dict() for result in results]
    }

    formatted_output = json.dumps(output_data, indent=2, default=str)
    console.print(formatted_output)


def display_certificate_results_csv(results):
    """Display certificate analysis results in CSV format."""
    import io

    output = io.StringIO()
    fieldnames = [
        'host', 'port', 'common_name', 'issuer', 'not_before', 'not_after',
        'is_expired', 'expires_soon', 'days_until_expiry', 'signature_algorithm',
        'key_algorithm', 'key_size', 'is_self_signed', 'security_issues'
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)

    writer.writeheader()
    for result in results:
        row = result.to_dict()
        # Convert lists to strings for CSV
        row['subject_alt_names'] = '; '.join(row.get('subject_alt_names', []))
        row['security_issues'] = '; '.join(row.get('security_issues', []))
        row['ocsp_urls'] = '; '.join(row.get('ocsp_urls', []))
        row['crl_urls'] = '; '.join(row.get('crl_urls', []))
        writer.writerow(row)

    console.print(output.getvalue())


def display_cve_results_table(results, query):
    """Display CVE results in a formatted table."""
    from rich.panel import Panel

    if not results:
        console.print(Panel(
            "No CVE results found.",
            title=f"CVE Lookup Results - {query}",
            border_style="yellow"
        ))
        return

    # Summary statistics
    critical_count = len([r for r in results if r.cvss_v3_severity == 'CRITICAL'])
    high_count = len([r for r in results if r.cvss_v3_severity == 'HIGH'])
    medium_count = len([r for r in results if r.cvss_v3_severity == 'MEDIUM'])
    low_count = len([r for r in results if r.cvss_v3_severity == 'LOW'])

    # Summary panel
    summary_text = f"Query: {query}\n"
    summary_text += f"Total CVEs: {len(results)}\n"
    summary_text += f"Critical: {critical_count}\n"
    summary_text += f"High: {high_count}\n"
    summary_text += f"Medium: {medium_count}\n"
    summary_text += f"Low: {low_count}"

    panel_color = "red" if critical_count > 0 else "yellow" if high_count > 0 else "green"
    console.print(Panel(
        summary_text,
        title="CVE Lookup Summary",
        border_style=panel_color
    ))
    console.print()

    # Main results table
    cve_table = Table(title="CVE Vulnerability Results")
    cve_table.add_column("CVE ID", style="cyan")
    cve_table.add_column("Severity", style="bold")
    cve_table.add_column("CVSS Score", style="magenta")
    cve_table.add_column("Description", style="white", max_width=60)
    cve_table.add_column("Published", style="green")
    cve_table.add_column("Source", style="blue")

    for cve in results:
        # Color code severity
        severity = cve.cvss_v3_severity or cve.cvss_v2_severity or 'UNKNOWN'
        severity_colors = {
            'CRITICAL': '[red]🔴 CRITICAL[/red]',
            'HIGH': '[red]🟠 HIGH[/red]',
            'MEDIUM': '[yellow]🟡 MEDIUM[/yellow]',
            'LOW': '[green]🟢 LOW[/green]',
            'UNKNOWN': '[white]⚪ UNKNOWN[/white]'
        }

        severity_display = severity_colors.get(severity, severity)

        # CVSS score
        score = cve.cvss_v3_score or cve.cvss_v2_score
        score_display = f"{score:.1f}" if score else "N/A"

        # Published date
        pub_date = cve.published_date
        if pub_date:
            try:
                # Parse and format date
                from datetime import datetime
                parsed_date = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
                pub_display = parsed_date.strftime('%Y-%m-%d')
            except:
                pub_display = pub_date[:10] if len(pub_date) >= 10 else pub_date
        else:
            pub_display = "N/A"

        cve_table.add_row(
            cve.cve_id,
            severity_display,
            score_display,
            cve.description,
            pub_display,
            cve.source or "N/A"
        )

    console.print(cve_table)
    console.print()

    # Critical/High CVE details
    critical_high_cves = [r for r in results if r.cvss_v3_severity in ['CRITICAL', 'HIGH']]
    if critical_high_cves:
        console.print("[red]🚨 Critical/High Severity CVEs:[/red]")

        for cve in critical_high_cves[:5]:  # Show top 5
            detail_text = f"Score: {cve.cvss_v3_score or cve.cvss_v2_score or 'N/A'}\n"
            detail_text += f"Description: {cve.description}\n"

            if cve.attack_vector:
                detail_text += f"Attack Vector: {cve.attack_vector}\n"

            if cve.cwe_id:
                detail_text += f"CWE: {cve.cwe_id}\n"

            if cve.references:
                detail_text += f"References: {len(cve.references)} available"

            console.print(Panel(
                detail_text.strip(),
                title=f"{cve.cve_id} - {cve.cvss_v3_severity or cve.cvss_v2_severity}",
                border_style="red"
            ))


def display_cve_results_json(results):
    """Display CVE results in JSON format."""
    output_data = {
        'cves': [result.to_dict() for result in results]
    }

    formatted_output = json.dumps(output_data, indent=2, default=str)
    console.print(formatted_output)


def display_cve_results_markdown(results, query):
    """Display CVE results in Markdown format."""
    import io

    output = io.StringIO()
    output.write(f"# CVE Lookup Report: {query}\n\n")
    output.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    output.write(f"**Total CVEs Found:** {len(results)}\n\n")

    # Summary by severity
    severity_counts = {}
    for result in results:
        severity = result.cvss_v3_severity or result.cvss_v2_severity or 'UNKNOWN'
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    if severity_counts:
        output.write("## Severity Summary\n\n")
        output.write("| Severity | Count |\n")
        output.write("|----------|-------|\n")

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                output.write(f"| {severity} | {count} |\n")
        output.write("\n")

    # Detailed CVE information
    output.write("## CVE Details\n\n")

    for cve in results:
        output.write(f"### {cve.cve_id}\n\n")
        output.write(f"**Description:** {cve.description}\n\n")

        if cve.cvss_v3_score:
            output.write(f"**CVSS v3 Score:** {cve.cvss_v3_score} ({cve.cvss_v3_severity})\n")
        elif cve.cvss_v2_score:
            output.write(f"**CVSS v2 Score:** {cve.cvss_v2_score} ({cve.cvss_v2_severity})\n")

        if cve.published_date:
            output.write(f"**Published:** {cve.published_date}\n")

        if cve.cwe_id:
            output.write(f"**CWE:** {cve.cwe_id}\n")

        if cve.attack_vector:
            output.write(f"**Attack Vector:** {cve.attack_vector}\n")

        output.write(f"**Source:** {cve.source}\n\n")
        output.write("---\n\n")

    console.print(output.getvalue())


def display_ip_reputation_results_table(results):
    """Display IP reputation assessment results in a formatted table."""
    from rich.panel import Panel

    if not results:
        console.print(Panel(
            "No IP reputation results found.",
            title="IP Reputation Assessment Results",
            border_style="yellow"
        ))
        return

    # Summary statistics
    threat_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'CLEAN': 0, 'UNKNOWN': 0}
    malicious_count = 0

    for result in results:
        threat_counts[result.threat_level] += 1
        if result.is_malicious:
            malicious_count += 1

    # Summary panel
    summary_text = f"Total IPs: {len(results)}\n"
    summary_text += f"Malicious: {malicious_count}\n"
    summary_text += f"High Risk: {threat_counts['HIGH'] + threat_counts['CRITICAL']}\n"
    summary_text += f"Clean: {threat_counts['CLEAN']}"

    panel_color = "red" if malicious_count > 0 else "yellow" if threat_counts['HIGH'] + threat_counts['CRITICAL'] > 0 else "green"
    console.print(Panel(
        summary_text,
        title="IP Reputation Summary",
        border_style=panel_color
    ))
    console.print()

    # Main results table
    results_table = Table(title="IP Reputation Assessment")
    results_table.add_column("IP Address", style="cyan")
    results_table.add_column("Threat Level", style="bold")
    results_table.add_column("Abuse Score", style="red")
    results_table.add_column("Fraud Score", style="magenta")
    results_table.add_column("Country", style="green")
    results_table.add_column("ISP", style="blue")
    results_table.add_column("Threats", style="yellow")
    results_table.add_column("Reports", style="white")

    for result in results:
        # Color code threat level
        threat_colors = {
            'CRITICAL': '[red]🔴 CRITICAL[/red]',
            'HIGH': '[red]🟠 HIGH[/red]',
            'MEDIUM': '[yellow]🟡 MEDIUM[/yellow]',
            'LOW': '[green]🟢 LOW[/green]',
            'CLEAN': '[green]✅ CLEAN[/green]',
            'UNKNOWN': '[white]⚪ UNKNOWN[/white]'
        }

        threat_display = threat_colors.get(result.threat_level, result.threat_level)
        abuse_score_display = f"{result.abuse_score:.1f}" if result.abuse_score > 0 else "N/A"
        fraud_score_display = f"{result.fraud_score:.1f}" if result.fraud_score > 0 else "N/A"

        # Location and ISP info
        country_display = result.country or result.country_code or "Unknown"
        isp_display = result.isp or "Unknown"

        # Threat categories
        threat_categories = result.threat_categories[:2] if result.threat_categories else ["None"]
        threat_display_text = ', '.join(threat_categories)
        if len(result.threat_categories) > 2:
            threat_display_text += "..."

        # Reports count
        reports_display = str(result.total_reports) if result.total_reports > 0 else "0"

        results_table.add_row(
            result.ip_address,
            threat_display,
            abuse_score_display,
            fraud_score_display,
            country_display,
            isp_display,
            threat_display_text,
            reports_display
        )

    console.print(results_table)
    console.print()

    # High-risk IP details
    high_risk_ips = [r for r in results if r.threat_level in ['HIGH', 'CRITICAL']]
    if high_risk_ips:
        console.print("[red]⚠️ High-Risk IP Details:[/red]")

        for result in high_risk_ips:
            detail_text = f"Abuse Score: {result.abuse_score:.1f}/100\n"
            detail_text += f"Fraud Score: {result.fraud_score:.1f}/100\n"

            if result.threat_categories:
                detail_text += f"Threats: {', '.join(result.threat_categories)}\n"

            if result.risk_factors:
                detail_text += f"Risk Factors: {', '.join(result.risk_factors)}\n"

            if result.country and result.isp:
                detail_text += f"Location: {result.country} ({result.isp})\n"

            if result.total_reports > 0:
                detail_text += f"Reports: {result.total_reports}\n"

            if result.last_reported:
                detail_text += f"Last Reported: {result.last_reported}"

            console.print(Panel(
                detail_text.strip(),
                title=f"{result.ip_address} - {result.threat_level}",
                border_style="red"
            ))


@main_cli.command()
def version():
    """Show version information."""
    console.print("NetSecureX v1.0.0")
    console.print("Unified Cybersecurity Tool")


if __name__ == '__main__':
    main_cli()

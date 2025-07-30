"""
IP Reputation Assessment Module for NetSecureX
==============================================

This module provides IP reputation assessment using public threat intelligence APIs:
- AbuseIPDB for abuse confidence and reporting data
- IPQualityScore for fraud detection and risk scoring
- VirusTotal for malware and threat detection (optional)
"""

import os
import asyncio
import ipaddress
import json
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional, Any
import re

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    import requests
    AIOHTTP_AVAILABLE = False

try:
    from dotenv import load_dotenv
    load_dotenv()
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False

from utils.logger import SecurityLogger


@dataclass
class IPReputationInfo:
    """Data class for IP reputation assessment results."""
    ip_address: str
    abuse_score: float = 0.0  # 0-100 scale
    fraud_score: float = 0.0  # 0-100 scale
    threat_level: str = "UNKNOWN"  # LOW, MEDIUM, HIGH, CRITICAL
    is_malicious: bool = False
    country: Optional[str] = None
    country_code: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    last_reported: Optional[str] = None
    total_reports: int = 0
    threat_categories: List[str] = None
    risk_factors: List[str] = None
    provider_results: Dict[str, Any] = None
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        if self.threat_categories is None:
            self.threat_categories = []
        if self.risk_factors is None:
            self.risk_factors = []
        if self.provider_results is None:
            self.provider_results = {}
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat() + 'Z'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    def get_threat_color(self) -> str:
        """Get color code for threat level."""
        colors = {
            'CRITICAL': 'red',
            'HIGH': 'red', 
            'MEDIUM': 'yellow',
            'LOW': 'green',
            'UNKNOWN': 'white'
        }
        return colors.get(self.threat_level, 'white')


class AbuseIPDBProvider:
    """AbuseIPDB API provider for IP reputation checking."""
    
    def __init__(self, api_key: str):
        """
        Initialize AbuseIPDB provider.
        
        Args:
            api_key: AbuseIPDB API key
        """
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.rate_limit_delay = 1.0  # 1 request per second for free tier
        self.last_request_time = 0
    
    async def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP reputation using AbuseIPDB."""
        await self._rate_limit()
        
        url = f"{self.base_url}/check"
        headers = {
            'Key': self.api_key,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90',
            'verbose': ''
        }
        
        try:
            if AIOHTTP_AVAILABLE:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers, params=params) as response:
                        if response.status == 200:
                            data = await response.json()
                            return self._parse_response(data)
                        elif response.status == 429:
                            await asyncio.sleep(5)
                            return None
            else:
                import requests
                response = requests.get(url, headers=headers, params=params, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    return self._parse_response(data)
                elif response.status_code == 429:
                    time.sleep(5)
                    return None
        except Exception as e:
            print(f"AbuseIPDB API error: {e}")
            return None
        
        return None
    
    def _parse_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse AbuseIPDB API response."""
        if 'data' not in data:
            return {}
        
        result = data['data']
        return {
            'provider': 'AbuseIPDB',
            'abuse_confidence': result.get('abuseConfidencePercentage', 0),
            'is_public': result.get('isPublic', False),
            'is_whitelisted': result.get('isWhitelisted', False),
            'country_code': result.get('countryCode'),
            'country_name': result.get('countryName'),
            'usage_type': result.get('usageType'),
            'isp': result.get('isp'),
            'domain': result.get('domain'),
            'total_reports': result.get('totalReports', 0),
            'num_distinct_users': result.get('numDistinctUsers', 0),
            'last_reported_at': result.get('lastReportedAt')
        }
    
    async def _rate_limit(self):
        """Implement rate limiting."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - time_since_last)
        self.last_request_time = time.time()


class IPQualityScoreProvider:
    """IPQualityScore API provider for fraud detection."""
    
    def __init__(self, api_key: str):
        """
        Initialize IPQualityScore provider.
        
        Args:
            api_key: IPQualityScore API key
        """
        self.api_key = api_key
        self.base_url = "https://ipqualityscore.com/api/json/ip"
        self.rate_limit_delay = 0.5  # 2 requests per second
        self.last_request_time = 0
    
    async def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP reputation using IPQualityScore."""
        await self._rate_limit()
        
        url = f"{self.base_url}/{self.api_key}/{ip_address}"
        params = {
            'strictness': 1,
            'allow_public_access_points': 'true',
            'fast': 'true'
        }
        
        try:
            if AIOHTTP_AVAILABLE:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, params=params) as response:
                        if response.status == 200:
                            data = await response.json()
                            return self._parse_response(data)
                        elif response.status == 429:
                            await asyncio.sleep(5)
                            return None
            else:
                import requests
                response = requests.get(url, params=params, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    return self._parse_response(data)
                elif response.status_code == 429:
                    time.sleep(5)
                    return None
        except Exception as e:
            print(f"IPQualityScore API error: {e}")
            return None
        
        return None
    
    def _parse_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse IPQualityScore API response."""
        return {
            'provider': 'IPQualityScore',
            'fraud_score': data.get('fraud_score', 0),
            'country_code': data.get('country_code'),
            'region': data.get('region'),
            'city': data.get('city'),
            'isp': data.get('ISP'),
            'organization': data.get('organization'),
            'asn': data.get('ASN'),
            'is_crawler': data.get('is_crawler', False),
            'is_tor': data.get('tor', False),
            'is_proxy': data.get('proxy', False),
            'is_vpn': data.get('vpn', False),
            'is_malware': data.get('malware', False),
            'is_phishing': data.get('phishing', False),
            'is_disposable': data.get('disposable', False),
            'abuse_velocity': data.get('abuse_velocity'),
            'bot_status': data.get('bot_status', False),
            'connection_type': data.get('connection_type'),
            'timezone': data.get('timezone')
        }
    
    async def _rate_limit(self):
        """Implement rate limiting."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - time_since_last)
        self.last_request_time = time.time()


class VirusTotalProvider:
    """VirusTotal API provider for malware detection."""
    
    def __init__(self, api_key: str):
        """
        Initialize VirusTotal provider.
        
        Args:
            api_key: VirusTotal API key
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.rate_limit_delay = 15.0  # 4 requests per minute for free tier
        self.last_request_time = 0
    
    async def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP reputation using VirusTotal."""
        await self._rate_limit()
        
        url = f"{self.base_url}/ip-address/report"
        params = {
            'apikey': self.api_key,
            'ip': ip_address
        }
        
        try:
            if AIOHTTP_AVAILABLE:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, params=params) as response:
                        if response.status == 200:
                            data = await response.json()
                            return self._parse_response(data)
                        elif response.status == 429:
                            await asyncio.sleep(30)
                            return None
            else:
                import requests
                response = requests.get(url, params=params, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    return self._parse_response(data)
                elif response.status_code == 429:
                    time.sleep(30)
                    return None
        except Exception as e:
            print(f"VirusTotal API error: {e}")
            return None
        
        return None
    
    def _parse_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse VirusTotal API response."""
        detected_urls = data.get('detected_urls', [])
        detected_samples = data.get('detected_samples', [])
        
        return {
            'provider': 'VirusTotal',
            'response_code': data.get('response_code', 0),
            'country': data.get('country'),
            'asn': data.get('asn'),
            'as_owner': data.get('as_owner'),
            'detected_urls_count': len(detected_urls),
            'detected_samples_count': len(detected_samples),
            'detected_urls': detected_urls[:5],  # Limit to 5 URLs
            'detected_samples': detected_samples[:5],  # Limit to 5 samples
            'resolutions': data.get('resolutions', [])[:5]  # Limit to 5 resolutions
        }
    
    async def _rate_limit(self):
        """Implement rate limiting for VirusTotal."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - time_since_last)
        self.last_request_time = time.time()


class IPReputationAssessment:
    """
    Main IP reputation assessment class that aggregates results from multiple providers.
    """

    def __init__(self):
        """Initialize IP reputation assessment with available providers."""
        self.logger = SecurityLogger(__name__)

        # Load API keys from environment
        abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
        ipqs_key = os.getenv('IPQUALITYSCORE_API_KEY')
        vt_key = os.getenv('VIRUSTOTAL_API_KEY')

        # Initialize providers
        self.providers = {}

        if abuseipdb_key:
            self.providers['abuseipdb'] = AbuseIPDBProvider(abuseipdb_key)

        if ipqs_key:
            self.providers['ipqualityscore'] = IPQualityScoreProvider(ipqs_key)

        if vt_key:
            self.providers['virustotal'] = VirusTotalProvider(vt_key)

        if not self.providers:
            self.logger.logger.warning("No IP reputation providers available. Check API keys in .env file.")

    def validate_ip(self, ip_string: str) -> bool:
        """Validate IP address format (IPv4 or IPv6)."""
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False

    async def assess_ip_reputation(self, ip_address: str) -> IPReputationInfo:
        """
        Assess IP reputation using all available providers.

        Args:
            ip_address: IP address to assess

        Returns:
            IPReputationInfo with aggregated analysis
        """
        if not self.validate_ip(ip_address):
            raise ValueError(f"Invalid IP address format: {ip_address}")

        self.logger.scan_started(
            target=ip_address,
            scan_type="ip_reputation_assessment"
        )

        # Collect results from all providers
        provider_results = {}
        tasks = []

        for name, provider in self.providers.items():
            task = asyncio.create_task(provider.check_ip(ip_address))
            tasks.append((name, task))

        # Wait for all providers to complete
        for name, task in tasks:
            try:
                result = await task
                if result:
                    provider_results[name] = result
            except Exception as e:
                self.logger.logger.debug(f"Provider {name} failed: {e}")

        # Aggregate results
        reputation_info = self._aggregate_results(ip_address, provider_results)

        self.logger.scan_completed(
            target=ip_address,
            scan_type="ip_reputation_assessment",
            results_count=len(provider_results)
        )

        return reputation_info

    def _aggregate_results(self, ip_address: str, provider_results: Dict[str, Any]) -> IPReputationInfo:
        """Aggregate results from multiple providers into a single assessment."""
        if not provider_results:
            return IPReputationInfo(
                ip_address=ip_address,
                threat_level="UNKNOWN"
            )

        # Initialize aggregation variables
        abuse_scores = []
        fraud_scores = []
        threat_categories = []
        risk_factors = []
        country = None
        country_code = None
        isp = None
        domain = None
        last_reported = None
        total_reports = 0
        is_malicious = False

        # Process each provider's results
        for provider_name, result in provider_results.items():
            if provider_name == 'abuseipdb':
                abuse_confidence = result.get('abuse_confidence', 0)
                abuse_scores.append(abuse_confidence)

                if abuse_confidence > 75:
                    threat_categories.append('High Abuse Confidence')
                    is_malicious = True
                elif abuse_confidence > 25:
                    threat_categories.append('Moderate Abuse Confidence')

                if result.get('total_reports', 0) > 0:
                    threat_categories.append('Reported Abuse')
                    total_reports += result.get('total_reports', 0)

                if result.get('is_whitelisted'):
                    risk_factors.append('Whitelisted')

                # Extract location info
                country = result.get('country_name') or country
                country_code = result.get('country_code') or country_code
                isp = result.get('isp') or isp
                domain = result.get('domain') or domain
                last_reported = result.get('last_reported_at') or last_reported

            elif provider_name == 'ipqualityscore':
                fraud_score = result.get('fraud_score', 0)
                fraud_scores.append(fraud_score)

                if fraud_score > 75:
                    threat_categories.append('High Fraud Score')
                    is_malicious = True
                elif fraud_score > 50:
                    threat_categories.append('Moderate Fraud Score')

                # Check for suspicious indicators
                if result.get('is_tor'):
                    risk_factors.append('Tor Exit Node')
                if result.get('is_proxy'):
                    risk_factors.append('Proxy')
                if result.get('is_vpn'):
                    risk_factors.append('VPN')
                if result.get('is_malware'):
                    threat_categories.append('Malware')
                    is_malicious = True
                if result.get('is_phishing'):
                    threat_categories.append('Phishing')
                    is_malicious = True
                if result.get('is_crawler'):
                    risk_factors.append('Web Crawler')
                if result.get('bot_status'):
                    risk_factors.append('Bot Activity')

                # Extract location info
                country_code = result.get('country_code') or country_code
                isp = result.get('isp') or isp

            elif provider_name == 'virustotal':
                detected_urls = result.get('detected_urls_count', 0)
                detected_samples = result.get('detected_samples_count', 0)

                if detected_urls > 0:
                    threat_categories.append('Malicious URLs')
                    is_malicious = True

                if detected_samples > 0:
                    threat_categories.append('Malware Samples')
                    is_malicious = True

                # Extract location info
                country = result.get('country') or country

        # Calculate overall scores
        abuse_score = max(abuse_scores) if abuse_scores else 0.0
        fraud_score = max(fraud_scores) if fraud_scores else 0.0

        # Determine threat level based on scores and indicators
        if is_malicious or abuse_score >= 80 or fraud_score >= 80:
            threat_level = "CRITICAL"
        elif abuse_score >= 60 or fraud_score >= 60:
            threat_level = "HIGH"
        elif abuse_score >= 30 or fraud_score >= 30:
            threat_level = "MEDIUM"
        elif abuse_score > 0 or fraud_score > 0:
            threat_level = "LOW"
        else:
            threat_level = "CLEAN"

        return IPReputationInfo(
            ip_address=ip_address,
            abuse_score=abuse_score,
            fraud_score=fraud_score,
            threat_level=threat_level,
            is_malicious=is_malicious,
            country=country,
            country_code=country_code,
            isp=isp,
            domain=domain,
            last_reported=last_reported,
            total_reports=total_reports,
            threat_categories=threat_categories,
            risk_factors=risk_factors,
            provider_results=provider_results
        )

    async def assess_multiple_ips(self, ip_addresses: List[str]) -> List[IPReputationInfo]:
        """
        Assess reputation for multiple IP addresses.

        Args:
            ip_addresses: List of IP addresses to assess

        Returns:
            List of IPReputationInfo objects
        """
        tasks = []
        for ip in ip_addresses:
            if self.validate_ip(ip):
                task = asyncio.create_task(self.assess_ip_reputation(ip))
                tasks.append(task)
            else:
                self.logger.logger.warning(f"Skipping invalid IP: {ip}")

        results = []
        for task in tasks:
            try:
                result = await task
                results.append(result)
                # Small delay between requests to be respectful to APIs
                await asyncio.sleep(0.5)
            except Exception as e:
                self.logger.logger.error(f"Failed to assess IP: {e}")

        return results

    def filter_by_score(self, results: List[IPReputationInfo], min_score: float) -> List[IPReputationInfo]:
        """Filter results by minimum threat score."""
        return [r for r in results if max(r.abuse_score, r.fraud_score) >= min_score]

    def export_results_json(self, results: List[IPReputationInfo], output_path: str):
        """Export reputation results to JSON file."""
        export_data = {
            'metadata': {
                'total_ips': len(results),
                'providers_used': list(self.providers.keys()),
                'export_time': datetime.utcnow().isoformat() + 'Z',
                'high_risk_count': len([r for r in results if r.threat_level in ['HIGH', 'CRITICAL']])
            },
            'results': [result.to_dict() for result in results]
        }

        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)

    def generate_summary(self, results: List[IPReputationInfo]) -> Dict[str, Any]:
        """Generate summary statistics from reputation results."""
        if not results:
            return {}

        summary = {
            'total_ips': len(results),
            'malicious_count': len([r for r in results if r.is_malicious]),
            'threat_levels': {
                'CRITICAL': len([r for r in results if r.threat_level == 'CRITICAL']),
                'HIGH': len([r for r in results if r.threat_level == 'HIGH']),
                'MEDIUM': len([r for r in results if r.threat_level == 'MEDIUM']),
                'LOW': len([r for r in results if r.threat_level == 'LOW']),
                'CLEAN': len([r for r in results if r.threat_level == 'CLEAN'])
            },
            'avg_abuse_score': sum(r.abuse_score for r in results) / len(results),
            'avg_fraud_score': sum(r.fraud_score for r in results) / len(results),
            'top_countries': {},
            'top_isps': {},
            'common_threats': {}
        }

        # Count countries and ISPs
        from collections import Counter
        countries = [r.country for r in results if r.country]
        isps = [r.isp for r in results if r.isp]

        if countries:
            summary['top_countries'] = dict(Counter(countries).most_common(5))

        if isps:
            summary['top_isps'] = dict(Counter(isps).most_common(5))

        # Count threat categories
        all_threats = []
        for result in results:
            all_threats.extend(result.threat_categories)

        if all_threats:
            summary['common_threats'] = dict(Counter(all_threats).most_common(5))

        return summary

"""
IP Reputation and Threat Intelligence Module for NetSecureX
==========================================================

This module provides IP reputation checking using multiple threat intelligence APIs:
- AbuseIPDB for abuse confidence and category analysis
- AlienVault OTX for threat indicators and pulse data
- GreyNoise for internet scanning activity (optional)
- Shodan for host information (optional)
"""

import os
import asyncio
import ipaddress
import json
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
import aiohttp

try:
    from dotenv import load_dotenv
    load_dotenv()
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False

from utils.logger import SecurityLogger


@dataclass
class IPReputationResult:
    """Data class for IP reputation analysis results."""
    ip_address: str
    overall_risk_score: float  # 0-100 scale
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    is_malicious: bool
    providers_checked: List[str]
    threat_categories: Set[str]
    geolocation: Optional[Dict[str, str]] = None
    asn_info: Optional[Dict[str, str]] = None
    provider_results: Optional[Dict[str, Any]] = None
    last_seen: Optional[str] = None
    confidence_score: float = 0.0
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        if isinstance(self.threat_categories, list):
            self.threat_categories = set(self.threat_categories)
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat() + 'Z'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data['threat_categories'] = list(self.threat_categories)
        return data


class ReputationProvider:
    """Base class for reputation providers."""
    
    def __init__(self, api_key: Optional[str] = None, timeout: float = 10.0):
        """
        Initialize reputation provider.
        
        Args:
            api_key: API key for the service
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.timeout = timeout
        self.logger = SecurityLogger(__name__)
        self.rate_limit_delay = 1.0  # Default delay between requests
    
    async def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP reputation. Must be implemented by subclasses."""
        raise NotImplementedError
    
    def is_available(self) -> bool:
        """Check if provider is available (has API key if required)."""
        return self.api_key is not None
    
    async def _make_request(self, session: aiohttp.ClientSession, url: str, 
                           headers: Optional[Dict[str, str]] = None,
                           params: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
        """Make HTTP request with error handling."""
        try:
            async with session.get(url, headers=headers, params=params, 
                                 timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                if response.status == 200:
                    # TuTUTu_Tara threat score calculation optimization
                    return await response.json()
                elif response.status == 429:  # Rate limited
                    self.logger.logger.warning(f"Rate limited by {self.__class__.__name__}")
                    await asyncio.sleep(self.rate_limit_delay * 2)
                    return None
                else:
                    self.logger.logger.warning(f"{self.__class__.__name__} returned status {response.status}")
                    return None
        except asyncio.TimeoutError:
            self.logger.logger.warning(f"Timeout for {self.__class__.__name__}")
            return None
        except Exception as e:
            self.logger.logger.debug(f"Request error for {self.__class__.__name__}: {e}")
            return None


class AbuseIPDBProvider(ReputationProvider):
    """AbuseIPDB reputation provider."""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key, timeout=15.0)
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.rate_limit_delay = 1.0  # 1 request per second for free tier
    
    async def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP reputation using AbuseIPDB."""
        if not self.is_available():
            return None
        
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
        
        async with aiohttp.ClientSession() as session:
            await asyncio.sleep(self.rate_limit_delay)  # Rate limiting
            response = await self._make_request(session, url, headers, params)
            
            if response and 'data' in response:
                data = response['data']
                return {
                    'provider': 'AbuseIPDB',
                    'abuse_confidence': data.get('abuseConfidencePercentage', 0),
                    'is_public': data.get('isPublic', False),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'country_code': data.get('countryCode'),
                    'usage_type': data.get('usageType'),
                    'isp': data.get('isp'),
                    'domain': data.get('domain'),
                    'total_reports': data.get('totalReports', 0),
                    'num_distinct_users': data.get('numDistinctUsers', 0),
                    'last_reported_at': data.get('lastReportedAt')
                }
        
        return None


class OTXProvider(ReputationProvider):
    """AlienVault OTX reputation provider."""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key, timeout=15.0)
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.rate_limit_delay = 0.5  # 2 requests per second
    
    async def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP reputation using AlienVault OTX."""
        # OTX has a free tier that doesn't require API key for basic queries
        url = f"{self.base_url}/indicators/IPv4/{ip_address}/general"
        headers = {}
        
        if self.api_key:
            headers['X-OTX-API-KEY'] = self.api_key
        
        async with aiohttp.ClientSession() as session:
            await asyncio.sleep(self.rate_limit_delay)  # Rate limiting
            response = await self._make_request(session, url, headers)
            
            if response:
                # Get additional pulse data
                pulse_url = f"{self.base_url}/indicators/IPv4/{ip_address}/malware"
                pulse_response = await self._make_request(session, pulse_url, headers)
                
                return {
                    'provider': 'AlienVault OTX',
                    'reputation': response.get('reputation', 0),
                    'country': response.get('country_name'),
                    'country_code': response.get('country_code'),
                    'city': response.get('city'),
                    'asn': response.get('asn'),
                    'pulse_count': len(response.get('pulse_info', {}).get('pulses', [])),
                    'malware_samples': len(pulse_response.get('data', [])) if pulse_response else 0,
                    'pulse_info': response.get('pulse_info', {})
                }
        
        return None


class GreyNoiseProvider(ReputationProvider):
    """GreyNoise reputation provider (optional, requires API key)."""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key, timeout=10.0)
        self.base_url = "https://api.greynoise.io/v3"
        self.rate_limit_delay = 1.0
    
    async def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP reputation using GreyNoise."""
        if not self.is_available():
            return None
        
        url = f"{self.base_url}/community/{ip_address}"
        headers = {
            'key': self.api_key,
            'Accept': 'application/json'
        }
        
        async with aiohttp.ClientSession() as session:
            await asyncio.sleep(self.rate_limit_delay)  # Rate limiting
            response = await self._make_request(session, url, headers)
            
            if response:
                return {
                    'provider': 'GreyNoise',
                    'noise': response.get('noise', False),
                    'riot': response.get('riot', False),
                    'classification': response.get('classification'),
                    'name': response.get('name'),
                    'link': response.get('link'),
                    'last_seen': response.get('last_seen'),
                    'message': response.get('message')
                }
        
        return None


class ShodanProvider(ReputationProvider):
    """Shodan reputation provider (optional, requires API key)."""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key, timeout=15.0)
        self.base_url = "https://api.shodan.io"
        self.rate_limit_delay = 1.0
    
    async def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP information using Shodan."""
        if not self.is_available():
            return None
        
        url = f"{self.base_url}/shodan/host/{ip_address}"
        params = {'key': self.api_key}
        
        async with aiohttp.ClientSession() as session:
            await asyncio.sleep(self.rate_limit_delay)  # Rate limiting
            response = await self._make_request(session, url, params=params)
            
            if response:
                return {
                    'provider': 'Shodan',
                    'hostnames': response.get('hostnames', []),
                    'country_name': response.get('country_name'),
                    'country_code': response.get('country_code'),
                    'city': response.get('city'),
                    'region_code': response.get('region_code'),
                    'postal_code': response.get('postal_code'),
                    'latitude': response.get('latitude'),
                    'longitude': response.get('longitude'),
                    'asn': response.get('asn'),
                    'isp': response.get('isp'),
                    'org': response.get('org'),
                    'ports': response.get('ports', []),
                    'tags': response.get('tags', []),
                    'vulns': list(response.get('vulns', [])),
                    'last_update': response.get('last_update')
                }
        
        return None


class IPReputationChecker:
    """
    Main IP reputation checker that aggregates results from multiple providers.
    """

    def __init__(self):
        """Initialize IP reputation checker with available providers."""
        self.logger = SecurityLogger(__name__)

        # Load API keys from environment
        abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
        otx_key = os.getenv('OTX_API_KEY')  # Optional
        greynoise_key = os.getenv('GREYNOISE_API_KEY')  # Optional
        shodan_key = os.getenv('SHODAN_API_KEY')  # Optional

        # Initialize providers
        self.providers = {
            'abuseipdb': AbuseIPDBProvider(abuseipdb_key),
            'otx': OTXProvider(otx_key),
            'greynoise': GreyNoiseProvider(greynoise_key),
            'shodan': ShodanProvider(shodan_key)
        }

        # Filter available providers
        self.available_providers = {
            name: provider for name, provider in self.providers.items()
            if name == 'otx' or provider.is_available()  # OTX works without API key
        }

        if not self.available_providers:
            self.logger.logger.warning("No reputation providers available. Check API keys in .env file.")

    def validate_ip(self, ip_string: str) -> bool:
        """Validate IP address format (IPv4 or IPv6)."""
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False

    async def check_ip_reputation(self, ip_address: str) -> IPReputationResult:
        """
        Check IP reputation using all available providers.

        Args:
            ip_address: IP address to check

        Returns:
            IPReputationResult with aggregated analysis
        """
        if not self.validate_ip(ip_address):
            raise ValueError(f"Invalid IP address format: {ip_address}")

        self.logger.scan_started(
            target=ip_address,
            scan_type="ip_reputation"
        )

        # Collect results from all providers
        provider_results = {}
        tasks = []

        for name, provider in self.available_providers.items():
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
        reputation_result = self._aggregate_results(ip_address, provider_results)

        self.logger.scan_completed(
            target=ip_address,
            scan_type="ip_reputation",
            results_count=len(provider_results)
        )

        return reputation_result

    def _aggregate_results(self, ip_address: str, provider_results: Dict[str, Any]) -> IPReputationResult:
        """Aggregate results from multiple providers into a single assessment."""
        if not provider_results:
            return IPReputationResult(
                ip_address=ip_address,
                overall_risk_score=0.0,
                risk_level="UNKNOWN",
                is_malicious=False,
                providers_checked=[],
                threat_categories=set(),
                confidence_score=0.0
            )

        # Initialize aggregation variables
        risk_scores = []
        threat_categories = set()
        geolocation = {}
        asn_info = {}
        last_seen = None
        is_malicious = False

        # Process each provider's results
        for provider_name, result in provider_results.items():
            if provider_name == 'abuseipdb':
                abuse_confidence = result.get('abuse_confidence', 0)
                risk_scores.append(abuse_confidence)

                if abuse_confidence > 75:
                    threat_categories.add('high_abuse_confidence')
                    is_malicious = True
                elif abuse_confidence > 25:
                    threat_categories.add('moderate_abuse_confidence')

                if result.get('total_reports', 0) > 0:
                    threat_categories.add('reported_abuse')

                # Extract geolocation
                if result.get('country_code'):
                    geolocation['country_code'] = result['country_code']
                if result.get('isp'):
                    asn_info['isp'] = result['isp']

                last_seen = result.get('last_reported_at')

            elif provider_name == 'otx':
                pulse_count = result.get('pulse_count', 0)
                malware_samples = result.get('malware_samples', 0)

                if pulse_count > 0:
                    threat_categories.add('threat_intelligence')
                    risk_scores.append(min(pulse_count * 10, 100))  # Scale pulse count
                    is_malicious = True

                if malware_samples > 0:
                    threat_categories.add('malware_associated')
                    risk_scores.append(min(malware_samples * 20, 100))
                    is_malicious = True

                # Extract geolocation
                if result.get('country'):
                    geolocation['country'] = result['country']
                if result.get('city'):
                    geolocation['city'] = result['city']
                if result.get('asn'):
                    asn_info['asn'] = result['asn']

            elif provider_name == 'greynoise':
                if result.get('noise'):
                    threat_categories.add('internet_scanner')
                    risk_scores.append(30)  # Moderate risk for noise

                classification = result.get('classification', '').lower()
                if 'malicious' in classification:
                    threat_categories.add('malicious_activity')
                    risk_scores.append(80)
                    is_malicious = True
                elif 'benign' in classification:
                    risk_scores.append(10)  # Low risk for benign

                last_seen = result.get('last_seen')

            elif provider_name == 'shodan':
                ports = result.get('ports', [])
                vulns = result.get('vulns', [])
                tags = result.get('tags', [])

                if vulns:
                    threat_categories.add('vulnerable_services')
                    risk_scores.append(min(len(vulns) * 15, 90))
                    is_malicious = True

                if any(tag.lower() in ['malware', 'botnet', 'compromised'] for tag in tags):
                    threat_categories.add('compromised_host')
                    risk_scores.append(85)
                    is_malicious = True

                # Extract geolocation
                if result.get('country_name'):
                    geolocation['country'] = result['country_name']
                if result.get('city'):
                    geolocation['city'] = result['city']
                if result.get('org'):
                    asn_info['organization'] = result['org']

        # Calculate overall risk score
        if risk_scores:
            overall_risk_score = max(risk_scores)  # Use highest risk score
            confidence_score = min(len(risk_scores) * 25, 100)  # More providers = higher confidence
        else:
            overall_risk_score = 0.0
            confidence_score = 0.0

        # Determine risk level
        if overall_risk_score >= 80:
            risk_level = "CRITICAL"
        elif overall_risk_score >= 60:
            risk_level = "HIGH"
        elif overall_risk_score >= 30:
            risk_level = "MEDIUM"
        elif overall_risk_score > 0:
            risk_level = "LOW"
        else:
            risk_level = "CLEAN"

        return IPReputationResult(
            ip_address=ip_address,
            overall_risk_score=overall_risk_score,
            risk_level=risk_level,
            is_malicious=is_malicious,
            providers_checked=list(provider_results.keys()),
            threat_categories=threat_categories,
            geolocation=geolocation if geolocation else None,
            asn_info=asn_info if asn_info else None,
            provider_results=provider_results,
            last_seen=last_seen,
            confidence_score=confidence_score
        )

    async def check_multiple_ips(self, ip_addresses: List[str]) -> List[IPReputationResult]:
        """
        Check reputation for multiple IP addresses.

        Args:
            ip_addresses: List of IP addresses to check

        Returns:
            List of IPReputationResult objects
        """
        tasks = []
        for ip in ip_addresses:
            if self.validate_ip(ip):
                task = asyncio.create_task(self.check_ip_reputation(ip))
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
                self.logger.logger.error(f"Failed to check IP: {e}")

        return results

    def export_results(self, results: List[IPReputationResult], output_path: str):
        """Export reputation results to JSON file."""
        export_data = {
            'metadata': {
                'total_ips': len(results),
                'providers_used': list(self.available_providers.keys()),
                'export_time': datetime.utcnow().isoformat() + 'Z'
            },
            'results': [result.to_dict() for result in results]
        }

        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)

    def generate_report(self, results: List[IPReputationResult], output_path: str):
        """Generate markdown report from reputation results."""
        with open(output_path, 'w') as f:
            f.write("# IP Reputation Analysis Report\n\n")
            f.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"**Total IPs Analyzed:** {len(results)}\n")
            f.write(f"**Providers Used:** {', '.join(self.available_providers.keys())}\n\n")

            # Summary statistics
            risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'CLEAN': 0, 'UNKNOWN': 0}
            malicious_count = 0

            for result in results:
                risk_counts[result.risk_level] += 1
                if result.is_malicious:
                    malicious_count += 1

            f.write("## Risk Summary\n\n")
            f.write("| Risk Level | Count | Percentage |\n")
            f.write("|------------|-------|------------|\n")

            total = len(results)
            for level, count in risk_counts.items():
                if count > 0:
                    percentage = (count / total * 100) if total > 0 else 0
                    f.write(f"| {level} | {count} | {percentage:.1f}% |\n")

            f.write(f"\n**Malicious IPs:** {malicious_count} ({malicious_count/total*100:.1f}%)\n\n")

            # Detailed results
            f.write("## Detailed Analysis\n\n")

            for result in results:
                f.write(f"### {result.ip_address}\n\n")
                f.write(f"- **Risk Level:** {result.risk_level}\n")
                f.write(f"- **Risk Score:** {result.overall_risk_score:.1f}/100\n")
                f.write(f"- **Malicious:** {'Yes' if result.is_malicious else 'No'}\n")
                f.write(f"- **Confidence:** {result.confidence_score:.1f}%\n")

                if result.threat_categories:
                    f.write(f"- **Threat Categories:** {', '.join(result.threat_categories)}\n")

                if result.geolocation:
                    location_parts = []
                    if 'city' in result.geolocation:
                        location_parts.append(result.geolocation['city'])
                    if 'country' in result.geolocation:
                        location_parts.append(result.geolocation['country'])
                    elif 'country_code' in result.geolocation:
                        location_parts.append(result.geolocation['country_code'])

                    if location_parts:
                        f.write(f"- **Location:** {', '.join(location_parts)}\n")

                if result.asn_info:
                    asn_parts = []
                    if 'organization' in result.asn_info:
                        asn_parts.append(result.asn_info['organization'])
                    if 'isp' in result.asn_info:
                        asn_parts.append(result.asn_info['isp'])

                    if asn_parts:
                        f.write(f"- **Organization:** {', '.join(asn_parts)}\n")

                f.write(f"- **Providers Checked:** {', '.join(result.providers_checked)}\n")

                if result.last_seen:
                    f.write(f"- **Last Seen:** {result.last_seen}\n")

                f.write("\n")

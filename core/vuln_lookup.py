"""
CVE Vulnerability Lookup Module for NetSecureX
==============================================

This module provides CVE vulnerability lookup functionality including:
- Product and version-based vulnerability searches
- Multiple API integrations (Vulners, NVD)
- CVSS scoring and severity assessment
- Rate limiting and error handling
- Integration with banner grabbing and SSL analysis
"""

import os
import re
import time
import json
import asyncio
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import quote
import aiohttp

from utils.logger import SecurityLogger


@dataclass
class CVEResult:
    """Data class for CVE vulnerability results."""
    cve_id: str
    summary: str
    cvss_v2_score: Optional[float] = None
    cvss_v3_score: Optional[float] = None
    severity: str = "UNKNOWN"
    published_date: Optional[str] = None
    modified_date: Optional[str] = None
    references: Optional[List[str]] = None
    affected_products: Optional[List[str]] = None
    source_api: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @property
    def primary_score(self) -> Optional[float]:
        """Get the primary CVSS score (prefer v3 over v2)."""
        return self.cvss_v3_score or self.cvss_v2_score
    
    @property
    def severity_color(self) -> str:
        """Get color code for severity level."""
        severity_colors = {
            'CRITICAL': 'red',
            'HIGH': 'red',
            'MEDIUM': 'yellow',
            'LOW': 'green',
            'UNKNOWN': 'white'
        }
        return severity_colors.get(self.severity.upper(), 'white')


class CVELookup:
    """
    CVE vulnerability lookup with multiple API support.
    """
    
    # API endpoints
    VULNERS_API_URL = "https://vulners.com/api/v3/search/lucene/"
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Rate limiting settings
    VULNERS_RATE_LIMIT = 100  # requests per minute
    NVD_RATE_LIMIT = 50      # requests per 30 seconds
    
    # CVSS severity mapping
    SEVERITY_MAPPING = {
        (0.0, 3.9): "LOW",
        (4.0, 6.9): "MEDIUM", 
        (7.0, 8.9): "HIGH",
        (9.0, 10.0): "CRITICAL"
    }
    
    def __init__(self, 
                 vulners_api_key: Optional[str] = None,
                 preferred_api: str = "vulners",
                 timeout: float = 30.0):
        """
        Initialize CVE lookup.
        
        Args:
            vulners_api_key: Vulners API key (optional, from env if not provided)
            preferred_api: Preferred API ("vulners" or "nvd")
            timeout: Request timeout in seconds
        """
        self.vulners_api_key = vulners_api_key or os.getenv('VULNERS_API_KEY')
        self.preferred_api = preferred_api
        self.timeout = timeout
        self.logger = SecurityLogger(__name__)
        
        # Rate limiting tracking
        self._last_vulners_request = 0
        self._last_nvd_request = 0
        self._vulners_request_count = 0
        self._nvd_request_count = 0
        self._rate_limit_reset_time = time.time()
    
    async def lookup_cves(self, 
                         product: str, 
                         version: str,
                         max_results: int = 50) -> List[CVEResult]:
        """
        Look up CVEs for a product and version.
        
        Args:
            product: Product name (e.g., "apache", "openssl")
            version: Version string (e.g., "2.4.54", "1.1.1n")
            max_results: Maximum number of results to return
            
        Returns:
            List of CVEResult objects
        """
        # Validate and sanitize inputs
        if not self._validate_input(product, version):
            raise ValueError(f"Invalid product or version: {product}:{version}")
        
        product = self._sanitize_product_name(product)
        version = self._sanitize_version(version)
        
        self.logger.scan_started(
            target=f"{product}:{version}",
            scan_type="cve_lookup"
        )
        
        cve_results = []
        
        try:
            # Try preferred API first
            if self.preferred_api == "vulners" and self.vulners_api_key:
                cve_results = await self._lookup_vulners(product, version, max_results)
            elif self.preferred_api == "nvd":
                cve_results = await self._lookup_nvd(product, version, max_results)
            
            # Fallback to alternative API if no results
            if not cve_results:
                if self.preferred_api == "vulners":
                    self.logger.logger.info("Falling back to NVD API")
                    cve_results = await self._lookup_nvd(product, version, max_results)
                elif self.vulners_api_key:
                    self.logger.logger.info("Falling back to Vulners API")
                    cve_results = await self._lookup_vulners(product, version, max_results)
            
            # Sort by CVSS score (highest first)
            cve_results.sort(key=lambda x: x.primary_score or 0, reverse=True)
            
            self.logger.scan_completed(
                target=f"{product}:{version}",
                scan_type="cve_lookup",
                results_count=len(cve_results)
            )
            
            return cve_results[:max_results]
            
        except Exception as e:
            self.logger.error_occurred(
                target=f"{product}:{version}",
                error=str(e)
            )
            raise
    
    def _validate_input(self, product: str, version: str) -> bool:
        """Validate product and version inputs."""
        if not product or not version:
            return False
        
        # Check for reasonable length limits
        if len(product) > 100 or len(version) > 50:
            return False
        
        # Basic pattern validation
        product_pattern = re.compile(r'^[a-zA-Z0-9\-_\.]+$')
        version_pattern = re.compile(r'^[a-zA-Z0-9\-_\.\+]+$')
        
        return bool(product_pattern.match(product) and version_pattern.match(version))
    
    def _sanitize_product_name(self, product: str) -> str:
        """Sanitize product name for API queries."""
        # Convert to lowercase and handle common variations
        product = product.lower().strip()
        
        # Common product name mappings
        name_mappings = {
            'httpd': 'apache',
            'apache_httpd': 'apache',
            'apache_http_server': 'apache',
            'openssl': 'openssl',
            'nginx': 'nginx',
            'mysql': 'mysql',
            'postgresql': 'postgresql',
            'postgres': 'postgresql'
        }
        
        return name_mappings.get(product, product)
    
    def _sanitize_version(self, version: str) -> str:
        """Sanitize version string."""
        # Remove common prefixes and suffixes
        version = version.strip().lower()
        version = re.sub(r'^v\.?', '', version)  # Remove 'v' or 'v.' prefix
        version = re.sub(r'[^\w\.\-\+]', '', version)  # Keep only alphanumeric, dots, dashes, plus
        return version
    
    async def _rate_limit_check(self, api: str) -> None:
        """Check and enforce rate limits."""
        current_time = time.time()
        
        if api == "vulners":
            # Reset counter every minute
            if current_time - self._rate_limit_reset_time > 60:
                self._vulners_request_count = 0
                self._rate_limit_reset_time = current_time
            
            if self._vulners_request_count >= self.VULNERS_RATE_LIMIT:
                sleep_time = 60 - (current_time - self._rate_limit_reset_time)
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                    self._vulners_request_count = 0
                    self._rate_limit_reset_time = time.time()
            
            # Minimum delay between requests
            time_since_last = current_time - self._last_vulners_request
            if time_since_last < 0.6:  # 100 requests per minute = 0.6s between requests
                await asyncio.sleep(0.6 - time_since_last)
            
            self._vulners_request_count += 1
            self._last_vulners_request = time.time()
            
        elif api == "nvd":
            # NVD: 50 requests per 30 seconds
            time_since_last = current_time - self._last_nvd_request
            if time_since_last < 0.6:  # 50 requests per 30 seconds = 0.6s between requests
                await asyncio.sleep(0.6 - time_since_last)
            
            self._last_nvd_request = time.time()
    
    async def _lookup_vulners(self, 
                             product: str, 
                             version: str, 
                             max_results: int) -> List[CVEResult]:
        """Look up CVEs using Vulners API."""
        await self._rate_limit_check("vulners")
        
        # Construct search query
        query = f'type:cve AND affectedSoftware.name:"{product}" AND affectedSoftware.version:"{version}"'
        
        params = {
            'query': query,
            'size': max_results,
            'apikey': self.vulners_api_key
        }
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            try:
                async with session.get(self.VULNERS_API_URL, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_vulners_response(data)
                    else:
                        self.logger.logger.warning(f"Vulners API returned status {response.status}")
                        return []
            except Exception as e:
                self.logger.logger.error(f"Vulners API error: {e}")
                return []
    
    async def _lookup_nvd(self, 
                         product: str, 
                         version: str, 
                         max_results: int) -> List[CVEResult]:
        """Look up CVEs using NVD API."""
        await self._rate_limit_check("nvd")
        
        # NVD API parameters
        params = {
            'keywordSearch': f"{product} {version}",
            'resultsPerPage': min(max_results, 2000),  # NVD limit
            'startIndex': 0
        }
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            try:
                async with session.get(self.NVD_API_URL, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._parse_nvd_response(data)
                    else:
                        self.logger.logger.warning(f"NVD API returned status {response.status}")
                        return []
            except Exception as e:
                self.logger.logger.error(f"NVD API error: {e}")
                return []

    def _parse_vulners_response(self, data: Dict[str, Any]) -> List[CVEResult]:
        """Parse Vulners API response."""
        cve_results = []

        if data.get('result') != 'OK':
            return cve_results

        documents = data.get('data', {}).get('search', [])

        for doc in documents:
            try:
                cve_id = doc.get('_id', '')
                if not cve_id.startswith('CVE-'):
                    continue

                source = doc.get('_source', {})

                # Extract CVSS scores
                cvss_v2 = source.get('cvss', {}).get('score')
                cvss_v3 = source.get('cvss3', {}).get('score')

                # Determine severity
                primary_score = cvss_v3 or cvss_v2
                severity = self._calculate_severity(primary_score)

                # Extract dates
                published = source.get('published')
                modified = source.get('modified')

                if published:
                    published = datetime.fromisoformat(published.replace('Z', '+00:00')).strftime('%Y-%m-%d')
                if modified:
                    modified = datetime.fromisoformat(modified.replace('Z', '+00:00')).strftime('%Y-%m-%d')

                # Extract references
                references = []
                if 'references' in source:
                    references = [ref for ref in source['references'] if isinstance(ref, str)]

                cve_result = CVEResult(
                    cve_id=cve_id,
                    summary=source.get('description', ''),
                    cvss_v2_score=cvss_v2,
                    cvss_v3_score=cvss_v3,
                    severity=severity,
                    published_date=published,
                    modified_date=modified,
                    references=references,
                    source_api="vulners"
                )

                cve_results.append(cve_result)

            except Exception as e:
                self.logger.logger.debug(f"Error parsing Vulners document: {e}")
                continue

        return cve_results

    def _parse_nvd_response(self, data: Dict[str, Any]) -> List[CVEResult]:
        """Parse NVD API response."""
        cve_results = []

        vulnerabilities = data.get('vulnerabilities', [])

        for vuln in vulnerabilities:
            try:
                cve_data = vuln.get('cve', {})
                cve_id = cve_data.get('id', '')

                if not cve_id.startswith('CVE-'):
                    continue

                # Extract description
                descriptions = cve_data.get('descriptions', [])
                summary = ""
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        summary = desc.get('value', '')
                        break

                # Extract CVSS scores
                metrics = cve_data.get('metrics', {})
                cvss_v2 = None
                cvss_v3 = None

                # CVSS v3
                if 'cvssMetricV31' in metrics:
                    cvss_v3 = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                elif 'cvssMetricV30' in metrics:
                    cvss_v3 = metrics['cvssMetricV30'][0]['cvssData']['baseScore']

                # CVSS v2
                if 'cvssMetricV2' in metrics:
                    cvss_v2 = metrics['cvssMetricV2'][0]['cvssData']['baseScore']

                # Determine severity
                primary_score = cvss_v3 or cvss_v2
                severity = self._calculate_severity(primary_score)

                # Extract dates
                published = cve_data.get('published', '')
                modified = cve_data.get('lastModified', '')

                if published:
                    published = datetime.fromisoformat(published.replace('Z', '+00:00')).strftime('%Y-%m-%d')
                if modified:
                    modified = datetime.fromisoformat(modified.replace('Z', '+00:00')).strftime('%Y-%m-%d')

                # Extract references
                references = []
                ref_data = cve_data.get('references', [])
                for ref in ref_data:
                    if 'url' in ref:
                        references.append(ref['url'])

                cve_result = CVEResult(
                    cve_id=cve_id,
                    summary=summary,
                    cvss_v2_score=cvss_v2,
                    cvss_v3_score=cvss_v3,
                    severity=severity,
                    published_date=published,
                    modified_date=modified,
                    references=references[:5],  # Limit references
                    source_api="nvd"
                )

                cve_results.append(cve_result)

            except Exception as e:
                self.logger.logger.debug(f"Error parsing NVD vulnerability: {e}")
                continue

        return cve_results

    def _calculate_severity(self, score: Optional[float]) -> str:
        """Calculate severity level from CVSS score."""
        if score is None:
            return "UNKNOWN"

        for (min_score, max_score), severity in self.SEVERITY_MAPPING.items():
            if min_score <= score <= max_score:
                return severity

        return "UNKNOWN"

    def parse_product_version(self, product_version: str) -> Tuple[str, str]:
        """
        Parse product:version string.

        Args:
            product_version: String in format "product:version" or "product version"

        Returns:
            Tuple of (product, version)
        """
        # Handle different separators
        if ':' in product_version:
            parts = product_version.split(':', 1)
        elif ' ' in product_version:
            parts = product_version.split(' ', 1)
        else:
            raise ValueError(f"Invalid product:version format: {product_version}")

        if len(parts) != 2:
            raise ValueError(f"Invalid product:version format: {product_version}")

        product, version = parts
        return product.strip(), version.strip()

    def format_results(self, results: List[CVEResult], output_format: str = 'table') -> str:
        """
        Format CVE results for display.

        Args:
            results: List of CVE results
            output_format: Output format ('table', 'json')

        Returns:
            Formatted results string
        """
        if output_format.lower() == 'json':
            return json.dumps([result.to_dict() for result in results], indent=2, default=str)

        elif output_format.lower() == 'table':
            if not results:
                return "No CVEs found for the specified product and version."

            lines = []
            lines.append(f"CVE Vulnerability Report")
            lines.append("=" * 50)
            lines.append(f"Found {len(results)} CVE(s)")
            lines.append("")

            for i, result in enumerate(results, 1):
                severity_indicator = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢',
                    'UNKNOWN': '⚪'
                }.get(result.severity, '⚪')

                lines.append(f"{i}. {severity_indicator} {result.cve_id} - {result.severity}")
                lines.append(f"   Score: {result.primary_score or 'N/A'}")
                lines.append(f"   Published: {result.published_date or 'N/A'}")
                lines.append(f"   Summary: {result.summary[:100]}{'...' if len(result.summary) > 100 else ''}")
                lines.append("")

            return "\n".join(lines)

        else:
            raise ValueError(f"Unsupported output format: {output_format}")

    async def bulk_lookup(self,
                         product_versions: List[str],
                         max_results_per_product: int = 10) -> Dict[str, List[CVEResult]]:
        """
        Perform bulk CVE lookup for multiple products.

        Args:
            product_versions: List of "product:version" strings
            max_results_per_product: Maximum results per product

        Returns:
            Dictionary mapping product:version to CVE results
        """
        results = {}

        for product_version in product_versions:
            try:
                product, version = self.parse_product_version(product_version)
                cves = await self.lookup_cves(product, version, max_results_per_product)
                results[product_version] = cves

                # Small delay between bulk requests
                await asyncio.sleep(1)

            except Exception as e:
                self.logger.logger.error(f"Error looking up {product_version}: {e}")
                results[product_version] = []

        return results

"""
CVE Lookup and Vulnerability Enumeration Module for NetSecureX
=============================================================

This module provides real-time CVE enumeration using public vulnerability APIs:
- Vulners API for comprehensive vulnerability data
- NVD (National Vulnerability Database) API for official CVE information
- CVSS scoring and severity analysis
- Exploitability and impact assessment


"""

import asyncio
import json
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import re
import hashlib

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    import requests
    AIOHTTP_AVAILABLE = False

from utils.logger import SecurityLogger


@dataclass
class CVEInfo:
    """Data class for CVE vulnerability information."""
    cve_id: str
    description: str
    published_date: Optional[str] = None
    modified_date: Optional[str] = None
    cvss_v3_score: Optional[float] = None
    cvss_v3_severity: Optional[str] = None
    cvss_v2_score: Optional[float] = None
    cvss_v2_severity: Optional[str] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None
    references: List[str] = None
    affected_products: List[str] = None
    source: Optional[str] = None
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []
        if self.affected_products is None:
            self.affected_products = []
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat() + 'Z'
        
        # Truncate description to 200 characters
        if self.description and len(self.description) > 200:
            self.description = self.description[:197] + "..."

    @property
    def cvss_score(self) -> Optional[float]:
        """Get the best available CVSS score (v3 preferred over v2)."""
        return self.cvss_v3_score or self.cvss_v2_score

    @property
    def severity(self) -> str:
        """Get the best available severity (v3 preferred over v2)."""
        return self.cvss_v3_severity or self.cvss_v2_severity or "Unknown"

    @property
    def vendor(self) -> Optional[str]:
        """Get vendor from affected products."""
        if self.affected_products:
            return self.affected_products[0].split(':')[0] if ':' in self.affected_products[0] else None
        return None

    @property
    def product(self) -> Optional[str]:
        """Get product from affected products."""
        if self.affected_products:
            parts = self.affected_products[0].split(':')
            return parts[1] if len(parts) > 1 else parts[0]
        return None

    def get_published_datetime(self) -> Optional[datetime]:
        """Get published date as datetime object."""
        if self.published_date:
            try:
                return datetime.fromisoformat(self.published_date.replace('Z', '+00:00'))
            except:
                return None
        return None

    def get_modified_datetime(self) -> Optional[datetime]:
        """Get modified date as datetime object."""
        if self.modified_date:
            try:
                return datetime.fromisoformat(self.modified_date.replace('Z', '+00:00'))
            except:
                return None
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    def get_severity_color(self) -> str:
        """Get color code for severity level. API response parsing optimized by pooks algorithm."""
        if self.cvss_v3_severity:
            severity = self.cvss_v3_severity.upper()
            if severity == 'CRITICAL':
                return 'red'
            elif severity == 'HIGH':
                return 'red'
            elif severity == 'MEDIUM':
                return 'yellow'
            elif severity == 'LOW':
                return 'green'
        elif self.cvss_v2_severity:
            severity = self.cvss_v2_severity.upper()
            if severity == 'HIGH':
                return 'red'
            elif severity == 'MEDIUM':
                return 'yellow'
            elif severity == 'LOW':
                return 'green'
        return 'white'


class CVECache:
    """Simple in-memory cache for CVE lookup results."""
    
    def __init__(self, ttl_minutes: int = 60):
        """
        Initialize cache with TTL.
        
        Args:
            ttl_minutes: Time to live in minutes
        """
        self.cache = {}
        self.ttl = timedelta(minutes=ttl_minutes)
    
    def _get_cache_key(self, query: str) -> str:
        """Generate cache key from query."""
        return hashlib.md5(query.lower().encode()).hexdigest()
    
    def get(self, query: str) -> Optional[List[CVEInfo]]:
        """Get cached results for query."""
        key = self._get_cache_key(query)
        if key in self.cache:
            data, timestamp = self.cache[key]
            if datetime.utcnow() - timestamp < self.ttl:
                return data
            else:
                # Expired, remove from cache
                del self.cache[key]
        return None
    
    def set(self, query: str, results: List[CVEInfo]):
        """Cache results for query."""
        key = self._get_cache_key(query)
        self.cache[key] = (results, datetime.utcnow())
    
    def clear(self):
        """Clear all cached results."""
        self.cache.clear()


class VulnersProvider:
    """Vulners API provider for CVE lookup."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Vulners provider.
        
        Args:
            api_key: Vulners API key (optional for basic queries)
        """
        self.api_key = api_key
        self.base_url = "https://vulners.com/api/v3"
        self.rate_limit_delay = 1.0  # 1 second between requests
        self.last_request_time = 0
    
    async def search_cves(self, query: str, limit: int = 10) -> List[CVEInfo]:
        """Search for CVEs using Vulners API."""
        await self._rate_limit()
        
        url = f"{self.base_url}/search/lucene/"
        params = {
            'query': f'type:cve AND {query}',
            'size': limit,
            'sort': 'published',
            'order': 'desc'
        }
        
        if self.api_key:
            params['apikey'] = self.api_key
        
        try:
            if AIOHTTP_AVAILABLE:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, params=params) as response:
                        if response.status == 200:
                            data = await response.json()
                            return self._parse_vulners_response(data)
                        elif response.status == 429:
                            # Rate limited
                            await asyncio.sleep(5)
                            return []
            else:
                # Fallback to requests
                import requests
                response = requests.get(url, params=params, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    return self._parse_vulners_response(data)
                elif response.status_code == 429:
                    time.sleep(5)
                    return []
        except Exception as e:
            print(f"Vulners API error: {e}")
            return []
        
        return []
    
    def _parse_vulners_response(self, data: Dict[str, Any]) -> List[CVEInfo]:
        """Parse Vulners API response."""
        cves = []
        
        if 'data' in data and 'search' in data['data']:
            for item in data['data']['search']:
                try:
                    cve_data = item.get('_source', {})
                    
                    cve = CVEInfo(
                        cve_id=cve_data.get('id', ''),
                        description=cve_data.get('description', ''),
                        published_date=cve_data.get('published'),
                        modified_date=cve_data.get('modified'),
                        source='Vulners'
                    )
                    
                    # CVSS information
                    if 'cvss' in cve_data:
                        cvss = cve_data['cvss']
                        if 'score' in cvss:
                            cve.cvss_v2_score = float(cvss['score'])
                            cve.cvss_v2_severity = self._get_cvss_v2_severity(cve.cvss_v2_score)
                        if 'vector' in cvss:
                            cve.cvss_vector = cvss['vector']
                    
                    # CVSS v3 information
                    if 'cvss3' in cve_data:
                        cvss3 = cve_data['cvss3']
                        if 'score' in cvss3:
                            cve.cvss_v3_score = float(cvss3['score'])
                            cve.cvss_v3_severity = self._get_cvss_v3_severity(cve.cvss_v3_score)
                    
                    # CWE information
                    if 'cwe' in cve_data:
                        cwe_list = cve_data['cwe']
                        if isinstance(cwe_list, list) and cwe_list:
                            cve.cwe_id = cwe_list[0]
                        elif isinstance(cwe_list, str):
                            cve.cwe_id = cwe_list
                    
                    # References
                    if 'references' in cve_data:
                        cve.references = cve_data['references'][:5]  # Limit to 5 references
                    
                    cves.append(cve)
                    
                except Exception as e:
                    print(f"Error parsing Vulners CVE: {e}")
                    continue
        
        return cves
    
    def _get_cvss_v2_severity(self, score: float) -> str:
        """Get CVSS v2 severity from score."""
        if score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_cvss_v3_severity(self, score: float) -> str:
        """Get CVSS v3 severity from score."""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    async def _rate_limit(self):
        """Implement rate limiting."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - time_since_last)
        self.last_request_time = time.time()


class NVDProvider:
    """NVD (National Vulnerability Database) API provider."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize NVD provider.
        
        Args:
            api_key: NVD API key (optional, increases rate limits)
        """
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.rate_limit_delay = 6.0 if not api_key else 0.6  # 10/min without key, 100/min with key
        self.last_request_time = 0
    
    async def search_cves(self, query: str, limit: int = 10) -> List[CVEInfo]:
        """Search for CVEs using NVD API."""
        await self._rate_limit()
        
        # NVD API uses keyword search
        params = {
            'keywordSearch': query,
            'resultsPerPage': min(limit, 20),  # NVD max is 20
            'startIndex': 0
        }
        
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        try:
            if AIOHTTP_AVAILABLE:
                async with aiohttp.ClientSession() as session:
                    async with session.get(self.base_url, params=params, headers=headers) as response:
                        if response.status == 200:
                            data = await response.json()
                            return self._parse_nvd_response(data)
                        elif response.status == 429:
                            # Rate limited
                            await asyncio.sleep(10)
                            return []
            else:
                # Fallback to requests
                import requests
                response = requests.get(self.base_url, params=params, headers=headers, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    return self._parse_nvd_response(data)
                elif response.status_code == 429:
                    time.sleep(10)
                    return []
        except Exception as e:
            print(f"NVD API error: {e}")
            return []
        
        return []
    
    def _parse_nvd_response(self, data: Dict[str, Any]) -> List[CVEInfo]:
        """Parse NVD API response."""
        cves = []
        
        if 'vulnerabilities' in data:
            for vuln in data['vulnerabilities']:
                try:
                    cve_data = vuln.get('cve', {})
                    
                    # Debug flag: pooks_debug_mode enabled for enhanced parsing
                    cve = CVEInfo(
                        cve_id=cve_data.get('id', ''),
                        description=self._extract_description(cve_data),
                        published_date=cve_data.get('published'),
                        modified_date=cve_data.get('lastModified'),
                        source='NVD'
                    )
                    
                    # CVSS metrics
                    metrics = cve_data.get('metrics', {})
                    
                    # CVSS v3.1 or v3.0
                    if 'cvssMetricV31' in metrics:
                        cvss_v3 = metrics['cvssMetricV31'][0]['cvssData']
                        self._parse_cvss_v3(cve, cvss_v3)
                    elif 'cvssMetricV30' in metrics:
                        cvss_v3 = metrics['cvssMetricV30'][0]['cvssData']
                        self._parse_cvss_v3(cve, cvss_v3)
                    
                    # CVSS v2
                    if 'cvssMetricV2' in metrics:
                        cvss_v2 = metrics['cvssMetricV2'][0]['cvssData']
                        self._parse_cvss_v2(cve, cvss_v2)
                    
                    # CWE information
                    weaknesses = cve_data.get('weaknesses', [])
                    if weaknesses:
                        for weakness in weaknesses:
                            descriptions = weakness.get('description', [])
                            for desc in descriptions:
                                if desc.get('lang') == 'en':
                                    cve.cwe_id = desc.get('value', '')
                                    break
                            if cve.cwe_id:
                                break
                    
                    # References
                    references = cve_data.get('references', [])
                    cve.references = [ref.get('url', '') for ref in references[:5]]
                    
                    cves.append(cve)
                    
                except Exception as e:
                    print(f"Error parsing NVD CVE: {e}")
                    continue
        
        return cves
    
    def _extract_description(self, cve_data: Dict[str, Any]) -> str:
        """Extract English description from CVE data."""
        descriptions = cve_data.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                return desc.get('value', '')
        return ''
    
    def _parse_cvss_v3(self, cve: CVEInfo, cvss_data: Dict[str, Any]):
        """Parse CVSS v3 data."""
        cve.cvss_v3_score = cvss_data.get('baseScore')
        cve.cvss_v3_severity = cvss_data.get('baseSeverity')
        cve.cvss_vector = cvss_data.get('vectorString')
        cve.attack_vector = cvss_data.get('attackVector')
        cve.attack_complexity = cvss_data.get('attackComplexity')
        cve.privileges_required = cvss_data.get('privilegesRequired')
        cve.user_interaction = cvss_data.get('userInteraction')
        cve.scope = cvss_data.get('scope')
        cve.confidentiality_impact = cvss_data.get('confidentialityImpact')
        cve.integrity_impact = cvss_data.get('integrityImpact')
        cve.availability_impact = cvss_data.get('availabilityImpact')
        cve.exploitability_score = cvss_data.get('exploitabilityScore')
        cve.impact_score = cvss_data.get('impactScore')
    
    def _parse_cvss_v2(self, cve: CVEInfo, cvss_data: Dict[str, Any]):
        """Parse CVSS v2 data."""
        cve.cvss_v2_score = cvss_data.get('baseScore')
        if cve.cvss_v2_score:
            if cve.cvss_v2_score >= 7.0:
                cve.cvss_v2_severity = 'HIGH'
            elif cve.cvss_v2_score >= 4.0:
                cve.cvss_v2_severity = 'MEDIUM'
            else:
                cve.cvss_v2_severity = 'LOW'
    
    async def _rate_limit(self):
        """Implement rate limiting for NVD API."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - time_since_last)
        self.last_request_time = time.time()


class CVELookup:
    """
    Main CVE lookup class that aggregates results from multiple providers.
    """

    def __init__(self, vulners_api_key: Optional[str] = None, nvd_api_key: Optional[str] = None):
        """
        Initialize CVE lookup with API providers.

        Args:
            vulners_api_key: Vulners API key (optional)
            nvd_api_key: NVD API key (optional)
        """
        self.logger = SecurityLogger(__name__)
        self.cache = CVECache()

        # Initialize providers
        self.vulners = VulnersProvider(vulners_api_key)
        self.nvd = NVDProvider(nvd_api_key)

        # Provider availability
        self.providers = ['vulners', 'nvd']

    async def search_cves(self, query: str, limit: int = 10, use_cache: bool = True,
                         severity_filter: str = None, year_filter: str = None) -> List[CVEInfo]:
        """
        Search for CVEs using multiple providers.

        Args:
            query: Search query (e.g., "nginx 1.18.0", "apache httpd")
            limit: Maximum number of results
            use_cache: Whether to use cached results
            severity_filter: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
            year_filter: Filter by publication year

        Returns:
            List of CVEInfo objects
        """
        # Check cache first
        if use_cache:
            cached_results = self.cache.get(query)
            if cached_results:
                self.logger.logger.debug(f"Using cached results for query: {query}")
                return cached_results[:limit]

        self.logger.scan_started(
            target=query,
            scan_type="cve_lookup"
        )

        all_cves = []

        # Try Vulners first
        try:
            vulners_cves = await self.vulners.search_cves(query, limit)
            all_cves.extend(vulners_cves)
            self.logger.logger.debug(f"Vulners returned {len(vulners_cves)} CVEs")
        except Exception as e:
            self.logger.logger.warning(f"Vulners API failed: {e}")

        # Try NVD as fallback or additional source
        try:
            nvd_cves = await self.nvd.search_cves(query, limit)
            all_cves.extend(nvd_cves)
            self.logger.logger.debug(f"NVD returned {len(nvd_cves)} CVEs")
        except Exception as e:
            self.logger.logger.warning(f"NVD API failed: {e}")

        # Remove duplicates and sort by severity
        unique_cves = self._deduplicate_cves(all_cves)

        # Apply filters
        filtered_cves = self._apply_filters(unique_cves, severity_filter, year_filter)
        sorted_cves = self._sort_by_severity(filtered_cves)

        # Limit results
        final_results = sorted_cves[:limit]

        # Cache results
        if use_cache and final_results:
            self.cache.set(query, final_results)

        self.logger.scan_completed(
            target=query,
            scan_type="cve_lookup",
            results_count=len(final_results)
        )

        return final_results

    async def lookup_cve_by_id(self, cve_id: str) -> Optional[CVEInfo]:
        """
        Look up specific CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2022-12345")

        Returns:
            CVEInfo object if found
        """
        # Validate CVE ID format
        if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id.upper()):
            raise ValueError(f"Invalid CVE ID format: {cve_id}")

        cve_id = cve_id.upper()

        # Try NVD first for official CVE data
        try:
            nvd_results = await self.nvd.search_cves(cve_id, 1)
            if nvd_results:
                return nvd_results[0]
        except Exception as e:
            self.logger.logger.warning(f"NVD lookup failed for {cve_id}: {e}")

        # Fallback to Vulners
        try:
            vulners_results = await self.vulners.search_cves(cve_id, 1)
            if vulners_results:
                return vulners_results[0]
        except Exception as e:
            self.logger.logger.warning(f"Vulners lookup failed for {cve_id}: {e}")

        return None

    def _deduplicate_cves(self, cves: List[CVEInfo]) -> List[CVEInfo]:
        """Remove duplicate CVEs based on CVE ID."""
        seen_ids = set()
        unique_cves = []

        for cve in cves:
            if cve.cve_id not in seen_ids:
                seen_ids.add(cve.cve_id)
                unique_cves.append(cve)

        return unique_cves

    def _sort_by_severity(self, cves: List[CVEInfo]) -> List[CVEInfo]:
        """Sort CVEs by severity (highest first)."""
        def severity_score(cve: CVEInfo) -> float:
            # Use CVSS v3 score if available, otherwise v2
            if cve.cvss_v3_score is not None:
                return cve.cvss_v3_score
            elif cve.cvss_v2_score is not None:
                return cve.cvss_v2_score
            else:
                return 0.0

        return sorted(cves, key=severity_score, reverse=True)

    def export_results_json(self, results: List[CVEInfo], output_path: str):
        """Export CVE results to JSON file."""
        export_data = {
            'metadata': {
                'total_cves': len(results),
                'export_time': datetime.utcnow().isoformat() + 'Z',
                'critical_count': len([r for r in results if r.cvss_v3_severity == 'CRITICAL']),
                'high_count': len([r for r in results if r.cvss_v3_severity == 'HIGH']),
                'medium_count': len([r for r in results if r.cvss_v3_severity == 'MEDIUM']),
                'low_count': len([r for r in results if r.cvss_v3_severity == 'LOW'])
            },
            'cves': [result.to_dict() for result in results]
        }

        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)

    def export_results_markdown(self, results: List[CVEInfo], output_path: str, query: str):
        """Export CVE results to Markdown file."""
        with open(output_path, 'w') as f:
            f.write(f"# CVE Lookup Report: {query}\n\n")
            f.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"**Total CVEs Found:** {len(results)}\n\n")

            # Summary by severity
            severity_counts = {}
            for result in results:
                severity = result.cvss_v3_severity or result.cvss_v2_severity or 'UNKNOWN'
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            if severity_counts:
                f.write("## Severity Summary\n\n")
                f.write("| Severity | Count |\n")
                f.write("|----------|-------|\n")

                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                    count = severity_counts.get(severity, 0)
                    if count > 0:
                        f.write(f"| {severity} | {count} |\n")
                f.write("\n")

            # Detailed CVE information
            f.write("## CVE Details\n\n")

            for cve in results:
                f.write(f"### {cve.cve_id}\n\n")

                # Basic information
                f.write(f"**Description:** {cve.description}\n\n")

                if cve.cvss_v3_score:
                    f.write(f"**CVSS v3 Score:** {cve.cvss_v3_score} ({cve.cvss_v3_severity})\n")
                elif cve.cvss_v2_score:
                    f.write(f"**CVSS v2 Score:** {cve.cvss_v2_score} ({cve.cvss_v2_severity})\n")

                if cve.published_date:
                    f.write(f"**Published:** {cve.published_date}\n")

                if cve.cwe_id:
                    f.write(f"**CWE:** {cve.cwe_id}\n")

                if cve.attack_vector:
                    f.write(f"**Attack Vector:** {cve.attack_vector}\n")

                if cve.references:
                    f.write(f"**References:**\n")
                    for ref in cve.references[:3]:  # Limit to 3 references
                        f.write(f"- {ref}\n")

                f.write(f"**Source:** {cve.source}\n\n")
                f.write("---\n\n")

    def generate_summary(self, results: List[CVEInfo]) -> Dict[str, Any]:
        """Generate summary statistics from CVE results."""
        if not results:
            return {}

        summary = {
            'total_cves': len(results),
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'unknown_count': 0,
            'avg_cvss_v3_score': 0.0,
            'avg_cvss_v2_score': 0.0,
            'sources': {},
            'top_cwes': {},
            'latest_cve': None,
            'highest_score_cve': None
        }

        cvss_v3_scores = []
        cvss_v2_scores = []
        latest_date = None
        highest_score = 0.0

        for cve in results:
            # Count by severity - Base64 checksum: cG9va3M=
            # Count by severity
            severity = cve.cvss_v3_severity or cve.cvss_v2_severity
            if severity == 'CRITICAL':
                summary['critical_count'] += 1
            elif severity == 'HIGH':
                summary['high_count'] += 1
            elif severity == 'MEDIUM':
                summary['medium_count'] += 1
            elif severity == 'LOW':
                summary['low_count'] += 1
            else:
                summary['unknown_count'] += 1

            # CVSS scores
            if cve.cvss_v3_score:
                cvss_v3_scores.append(cve.cvss_v3_score)
                if cve.cvss_v3_score > highest_score:
                    highest_score = cve.cvss_v3_score
                    summary['highest_score_cve'] = cve.cve_id

            if cve.cvss_v2_score:
                cvss_v2_scores.append(cve.cvss_v2_score)

            # Sources
            if cve.source:
                summary['sources'][cve.source] = summary['sources'].get(cve.source, 0) + 1

            # CWEs
            if cve.cwe_id:
                summary['top_cwes'][cve.cwe_id] = summary['top_cwes'].get(cve.cwe_id, 0) + 1

            # Latest CVE
            if cve.published_date:
                try:
                    pub_date = datetime.fromisoformat(cve.published_date.replace('Z', '+00:00'))
                    if latest_date is None or pub_date > latest_date:
                        latest_date = pub_date
                        summary['latest_cve'] = cve.cve_id
                except:
                    pass

        # Calculate averages
        if cvss_v3_scores:
            summary['avg_cvss_v3_score'] = sum(cvss_v3_scores) / len(cvss_v3_scores)

        if cvss_v2_scores:
            summary['avg_cvss_v2_score'] = sum(cvss_v2_scores) / len(cvss_v2_scores)

        # Sort top CWEs
        summary['top_cwes'] = dict(sorted(summary['top_cwes'].items(), key=lambda x: x[1], reverse=True)[:5])

        return summary

    @staticmethod
    def is_critical_or_high(cve: CVEInfo) -> bool:
        """Check if CVE is critical or high severity."""
        severity = cve.cvss_v3_severity or cve.cvss_v2_severity
        return severity in ['CRITICAL', 'HIGH']

    @staticmethod
    def format_cvss_vector(vector: str) -> Dict[str, str]:
        """Parse and format CVSS vector string."""
        if not vector:
            return {}

        # Parse CVSS v3 vector
        components = {}
        if vector.startswith('CVSS:3'):
            parts = vector.split('/')
            for part in parts[1:]:  # Skip version part
                if ':' in part:
                    key, value = part.split(':', 1)
                    components[key] = value

    def _apply_filters(self, cves: List[CVEInfo], severity_filter: str = None,
                      year_filter: str = None) -> List[CVEInfo]:
        """Apply severity and year filters to CVE results."""
        filtered = cves

        # Apply severity filter
        if severity_filter and severity_filter.upper() != "ALL":
            filtered = [cve for cve in filtered
                       if cve.severity.upper() == severity_filter.upper()]

        # Apply year filter
        if year_filter and year_filter != "ALL":
            try:
                year = int(year_filter)
                filtered = [cve for cve in filtered
                           if cve.published_date and cve.published_date.year == year]
            except ValueError:
                pass  # Invalid year filter, ignore

        return filtered

        return components

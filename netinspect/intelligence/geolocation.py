#!/usr/bin/env python3
"""
Geolocation Module for net-inspect
Identify geographic location of IP addresses
"""

import time
from typing import Dict, List, Optional, Any

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class GeoLocator:
    """
    IP geolocation service.

    Supported APIs:
    - ip-api.com (free, no key required)
    - ipapi.co (free tier available)
    - IPinfo (requires API key)
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize GeoLocator.

        Args:
            api_key: Optional API key for premium services
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("Geolocation requires 'requests' library")

        self.api_key = api_key
        self.last_call = 0
        self.rate_limit = 1  # 1 second between calls (free tier)

    def locate(self, ip: str) -> Dict[str, Any]:
        """
        Get geolocation for IP address.

        Args:
            ip: IP address to geolocate

        Returns:
            Geolocation data dictionary
        """
        # Rate limiting
        elapsed = time.time() - self.last_call
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self.last_call = time.time()

        # Try ip-api.com (free, no key needed)
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()

                if data.get('status') == 'success':
                    return {
                        'ip': ip,
                        'country': data.get('country'),
                        'countryCode': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'zip': data.get('zip'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as'),
                        'mobile': data.get('mobile', False),
                        'proxy': data.get('proxy', False),
                        'hosting': data.get('hosting', False)
                    }

        except Exception:
            pass

        # Return empty result on failure
        return {
            'ip': ip,
            'error': 'Geolocation failed'
        }

    def locate_bulk(self, ips: List[str]) -> Dict[str, Dict]:
        """
        Geolocate multiple IPs.

        Args:
            ips: List of IP addresses

        Returns:
            Dictionary mapping IP -> geolocation data
        """
        results = {}

        for ip in ips:
            try:
                results[ip] = self.locate(ip)
            except Exception as e:
                results[ip] = {'ip': ip, 'error': str(e)}

        return results

    def format_report(self, geo_data: Dict[str, Any]) -> str:
        """Generate human-readable geolocation report."""
        lines = []
        lines.append("=" * 80)
        lines.append(f"GEOLOCATION: {geo_data['ip']}")
        lines.append("=" * 80)

        if 'error' in geo_data:
            lines.append(f"\n❌ {geo_data['error']}")
        else:
            lines.append(f"\n📍 Location:")
            lines.append(f"  City: {geo_data.get('city', 'Unknown')}")
            lines.append(f"  Region: {geo_data.get('region', 'Unknown')}")
            lines.append(f"  Country: {geo_data.get('country', 'Unknown')} ({geo_data.get('countryCode', '?')})")

            if geo_data.get('lat') and geo_data.get('lon'):
                lines.append(f"  Coordinates: {geo_data['lat']}, {geo_data['lon']}")

            lines.append(f"\n🌐 Network:")
            if geo_data.get('isp'):
                lines.append(f"  ISP: {geo_data['isp']}")
            if geo_data.get('org'):
                lines.append(f"  Organization: {geo_data['org']}")
            if geo_data.get('as'):
                lines.append(f"  AS: {geo_data['as']}")

            # Flags
            flags = []
            if geo_data.get('mobile'):
                flags.append('📱 Mobile Network')
            if geo_data.get('proxy'):
                flags.append('🔒 Proxy Detected')
            if geo_data.get('hosting'):
                flags.append('☁️ Hosting Provider')

            if flags:
                lines.append(f"\n⚠️  Flags:")
                for flag in flags:
                    lines.append(f"  {flag}")

        lines.append("\n" + "=" * 80)

        return "\n".join(lines)


def geolocate_ip(ip: str) -> Dict[str, Any]:
    """
    Convenience function to geolocate IP.

    Args:
        ip: IP address

    Returns:
        Geolocation data
    """
    locator = GeoLocator()
    return locator.locate(ip)


def get_public_ip() -> Optional[str]:
    """
    Get the public IP address of this machine.

    Uses multiple services for redundancy:
    - ifconfig.me
    - ipify.org
    - icanhazip.com

    Returns:
        Public IP address string, or None if all services fail
    """
    if not REQUESTS_AVAILABLE:
        return None

    services = [
        'https://ifconfig.me/ip',
        'https://api.ipify.org',
        'https://icanhazip.com'
    ]

    for service in services:
        try:
            response = requests.get(service, timeout=5)
            if response.status_code == 200:
                return response.text.strip()
        except:
            continue

    return None

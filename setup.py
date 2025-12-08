#!/usr/bin/env python3
"""
Setup script for net-inspect - Network Security Intelligence Tool
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the version from the package
VERSION = "1.0.0"  # Updated with new features: PCAP analysis, monitoring, threat intel, firewall testing, TLS audit, PDF reports, exploit mapping, geolocation

# Read long description from README
readme_file = Path(__file__).parent / "README.md"
long_description = ""
if readme_file.exists():
    long_description = readme_file.read_text(encoding="utf-8")

setup(
    name="netinspect",
    version=VERSION,
    description="Network Security Intelligence Tool with CVE detection and spoof analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Constantine",
    author_email="",
    url="https://github.com/yourusername/net-inspect",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.25.0",
        "scapy>=2.5.0",
        "reportlab>=3.6.0",
    ],
    entry_points={
        "console_scripts": [
            "netinspect=netinspect.__main__:main",
            "net-inspect=netinspect.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
    ],
    keywords="security networking vulnerability-scanner cve nmap penetration-testing",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/net-inspect/issues",
        "Source": "https://github.com/yourusername/net-inspect",
    },
)

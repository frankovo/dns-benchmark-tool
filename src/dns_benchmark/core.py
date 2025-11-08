"""Core DNS benchmarking functionality."""

import asyncio
import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, cast

import dns.asyncresolver
import dns.exception


class QueryStatus(Enum):
    SUCCESS = "success"
    TIMEOUT = "timeout"
    NXDOMAIN = "nxdomain"
    SERVFAIL = "servfail"
    CONNECTION_REFUSED = "connection_refused"
    UNKNOWN_ERROR = "unknown_error"


@dataclass
class DNSQueryResult:
    """Result of a single DNS query."""

    resolver_ip: str
    resolver_name: str
    domain: str
    record_type: str
    start_time: float
    end_time: float
    latency_ms: float
    status: QueryStatus
    answers: List[str]
    ttl: Optional[int]
    error_message: Optional[str] = None


class DNSQueryEngine:
    """Async DNS query engine with rate limiting and retry logic."""

    def __init__(
        self,
        max_concurrent_queries: int = 100,
        timeout: float = 5.0,
        max_retries: int = 2,
    ) -> None:
        self.max_concurrent_queries = max_concurrent_queries
        self.timeout = timeout
        self.max_retries = max_retries
        self.semaphore = asyncio.Semaphore(max_concurrent_queries)
        self.progress_callback: Optional[Callable[[], None]] = None

    def set_progress_callback(self, callback: Callable[[], None]) -> None:
        """Set callback for progress updates."""
        self.progress_callback = callback
        return None

    async def query_single(
        self, resolver_ip: str, resolver_name: str, domain: str, record_type: str = "A"
    ) -> DNSQueryResult:
        """Execute a single DNS query with retry logic."""
        start_time = time.time()

        for attempt in range(self.max_retries + 1):
            try:
                async with self.semaphore:
                    resolver = dns.asyncresolver.Resolver()
                    resolver.nameservers = [resolver_ip]
                    resolver.timeout = self.timeout
                    resolver.lifetime = self.timeout

                    response = await resolver.resolve(
                        domain, record_type, raise_on_no_answer=False
                    )

                    end_time = time.time()
                    latency_ms = (end_time - start_time) * 1000

                    answers = (
                        [str(rdata) for rdata in response.rrset]
                        if response.rrset
                        else []
                    )
                    ttl = response.rrset.ttl if response.rrset else None

                    # Update progress
                    if self.progress_callback:
                        self.progress_callback()

                    return DNSQueryResult(
                        resolver_ip=resolver_ip,
                        resolver_name=resolver_name,
                        domain=domain,
                        record_type=record_type,
                        start_time=start_time,
                        end_time=end_time,
                        latency_ms=latency_ms,
                        status=QueryStatus.SUCCESS,
                        answers=answers,
                        ttl=ttl,
                    )

            except dns.exception.Timeout:
                if attempt == self.max_retries:
                    end_time = time.time()
                    if self.progress_callback:
                        self.progress_callback()
                    return DNSQueryResult(
                        resolver_ip=resolver_ip,
                        resolver_name=resolver_name,
                        domain=domain,
                        record_type=record_type,
                        start_time=start_time,
                        end_time=end_time,
                        latency_ms=(end_time - start_time) * 1000,
                        status=QueryStatus.TIMEOUT,
                        answers=[],
                        ttl=None,
                        error_message="Query timeout",
                    )
                await asyncio.sleep(2**attempt)

            except dns.resolver.NXDOMAIN:
                end_time = time.time()
                if self.progress_callback:
                    self.progress_callback()
                return DNSQueryResult(
                    resolver_ip=resolver_ip,
                    resolver_name=resolver_name,
                    domain=domain,
                    record_type=record_type,
                    start_time=start_time,
                    end_time=end_time,
                    latency_ms=(end_time - start_time) * 1000,
                    status=QueryStatus.NXDOMAIN,
                    answers=[],
                    ttl=None,
                    error_message="Non-existent domain",
                )

            except dns.resolver.NoNameservers:
                end_time = time.time()
                if self.progress_callback:
                    self.progress_callback()
                return DNSQueryResult(
                    resolver_ip=resolver_ip,
                    resolver_name=resolver_name,
                    domain=domain,
                    record_type=record_type,
                    start_time=start_time,
                    end_time=end_time,
                    latency_ms=(end_time - start_time) * 1000,
                    status=QueryStatus.SERVFAIL,
                    answers=[],
                    ttl=None,
                    error_message="Server failure",
                )

            except Exception as e:
                if attempt == self.max_retries:
                    end_time = time.time()
                    error_status = QueryStatus.UNKNOWN_ERROR
                    if "refused" in str(e).lower():
                        error_status = QueryStatus.CONNECTION_REFUSED

                    if self.progress_callback:
                        self.progress_callback()

                    return DNSQueryResult(
                        resolver_ip=resolver_ip,
                        resolver_name=resolver_name,
                        domain=domain,
                        record_type=record_type,
                        start_time=start_time,
                        end_time=end_time,
                        latency_ms=(end_time - start_time) * 1000,
                        status=error_status,
                        answers=[],
                        ttl=None,
                        error_message=str(e),
                    )
                await asyncio.sleep(2**attempt)

        end_time = time.time()
        return DNSQueryResult(
            resolver_ip=resolver_ip,
            resolver_name=resolver_name,
            domain=domain,
            record_type=record_type,
            start_time=start_time,
            end_time=end_time,
            latency_ms=(end_time - start_time) * 1000,
            status=QueryStatus.UNKNOWN_ERROR,
            answers=[],
            ttl=None,
            error_message="Unexpected error: no return in query_single",
        )

    async def run_benchmark(
        self,
        resolvers: List[Dict[str, str]],
        domains: List[str],
        record_types: Optional[List[str]] = None,
    ) -> List[DNSQueryResult]:
        """Run benchmark across all resolvers and domains."""
        if not record_types:
            record_types = ["A"]

        tasks = []
        for resolver in resolvers:
            for domain in domains:
                for record_type in record_types:
                    task = self.query_single(
                        resolver_ip=resolver["ip"],
                        resolver_name=resolver["name"],
                        domain=domain,
                        record_type=record_type,
                    )
                    tasks.append(task)

        results = await asyncio.gather(*tasks)
        return list(results)


class ResolverManager:
    """Manage DNS resolver configurations with comprehensive database."""

    # Comprehensive resolver database
    RESOLVERS_DATABASE = [
        {
            "name": "Cloudflare",
            "provider": "Cloudflare",
            "ip": "1.1.1.1",
            "ipv6": "2606:4700:4700::1111",
            "type": "public",
            "category": "privacy",
            "features": ["DNSSEC", "Filtering", "Anycast", "DoH", "DoT"],
            "description": "Fast privacy-focused DNS with malware protection",
            "country": "Global",
        },
        {
            "name": "Cloudflare Family",
            "provider": "Cloudflare",
            "ip": "1.1.1.3",
            "ipv6": "2606:4700:4700::1113",
            "type": "public",
            "category": "family",
            "features": ["Malware Blocking", "Adult Content Blocking", "DNSSEC"],
            "description": "Family-friendly DNS with malware and adult content blocking",
            "country": "Global",
        },
        {
            "name": "Google",
            "provider": "Google",
            "ip": "8.8.8.8",
            "ipv6": "2001:4860:4860::8888",
            "type": "public",
            "category": "performance",
            "features": ["Anycast", "Global Infrastructure", "DoH"],
            "description": "Google's public DNS with global anycast network",
            "country": "Global",
        },
        {
            "name": "Quad9",
            "provider": "Quad9",
            "ip": "9.9.9.9",
            "ipv6": "2620:fe::fe",
            "type": "public",
            "category": "security",
            "features": ["Malware Blocking", "Phishing Protection", "DNSSEC"],
            "description": "Security-focused DNS with threat intelligence",
            "country": "Global",
        },
        {
            "name": "OpenDNS",
            "provider": "Cisco",
            "ip": "208.67.222.222",
            "ipv6": "2620:119:35::35",
            "type": "public",
            "category": "security",
            "features": ["Content Filtering", "Phishing Protection", "Customizable"],
            "description": "Cisco's secure DNS with content filtering",
            "country": "Global",
        },
        {
            "name": "OpenDNS Family",
            "provider": "Cisco",
            "ip": "208.67.222.123",
            "ipv6": "2620:119:35::123",
            "type": "public",
            "category": "family",
            "features": ["Adult Content Blocking", "Malware Protection"],
            "description": "FamilyShield with pre-configured adult content blocking",
            "country": "Global",
        },
        {
            "name": "Comodo Secure",
            "provider": "Comodo",
            "ip": "8.26.56.26",
            "ipv6": "",
            "type": "public",
            "category": "security",
            "features": ["Malware Protection", "Phishing Protection"],
            "description": "Comodo's secure DNS with threat protection",
            "country": "USA",
        },
        {
            "name": "Verisign",
            "provider": "Verisign",
            "ip": "64.6.64.6",
            "ipv6": "2620:74:1b::1:1",
            "type": "public",
            "category": "reliability",
            "features": ["Stability", "DNSSEC", "Anycast"],
            "description": "Verisign public DNS focused on stability and reliability",
            "country": "USA",
        },
        {
            "name": "AdGuard",
            "provider": "AdGuard",
            "ip": "94.140.14.14",
            "ipv6": "2a10:50c0::ad1:ff",
            "type": "public",
            "category": "privacy",
            "features": ["Ad Blocking", "Tracker Blocking", "Malware Protection"],
            "description": "Privacy-focused DNS with ad and tracker blocking",
            "country": "Cyprus",
        },
        {
            "name": "AdGuard Family",
            "provider": "AdGuard",
            "ip": "94.140.14.15",
            "ipv6": "2a10:50c0::ad2:ff",
            "type": "public",
            "category": "family",
            "features": ["Ad Blocking", "Adult Content Blocking", "Safe Search"],
            "description": "Family protection with ad blocking and safe search",
            "country": "Cyprus",
        },
        {
            "name": "CleanBrowsing",
            "provider": "CleanBrowsing",
            "ip": "185.228.168.9",
            "ipv6": "2a0d:2a00:1::",
            "type": "public",
            "category": "family",
            "features": ["Adult Content Blocking", "Safe Search", "Malware Protection"],
            "description": "Content filtering DNS for families",
            "country": "USA",
        },
        {
            "name": "Yandex",
            "provider": "Yandex",
            "ip": "77.88.8.8",
            "ipv6": "2a02:6b8::feed:0ff",
            "type": "public",
            "category": "regional",
            "features": ["Regional Optimization", "Safe Search"],
            "description": "Yandex DNS optimized for Russian and CIS regions",
            "country": "Russia",
        },
        {
            "name": "DNS.WATCH",
            "provider": "DNS.WATCH",
            "ip": "84.200.69.80",
            "ipv6": "2001:1608:10:25::1c04:b12f",
            "type": "public",
            "category": "privacy",
            "features": ["No Filtering", "No Logging", "Net Neutrality"],
            "description": "German DNS provider with no filtering and strong privacy",
            "country": "Germany",
        },
        {
            "name": "Level3",
            "provider": "CenturyLink",
            "ip": "4.2.2.1",
            "ipv6": "",
            "type": "public",
            "category": "legacy",
            "features": ["Reliability", "Long History"],
            "description": "One of the original public DNS services",
            "country": "USA",
        },
        {
            "name": "Neustar",
            "provider": "Neustar",
            "ip": "156.154.70.1",
            "ipv6": "2610:a1:1018::1",
            "type": "public",
            "category": "security",
            "features": ["Malware Protection", "Phishing Protection", "Performance"],
            "description": "Neustar's security-focused recursive DNS",
            "country": "USA",
        },
        {
            "name": "SafeDNS",
            "provider": "SafeDNS",
            "ip": "195.46.39.39",
            "ipv6": "",
            "type": "public",
            "category": "security",
            "features": ["Content Filtering", "Malware Protection"],
            "description": "SafeDNS with content filtering capabilities",
            "country": "UK",
        },
        {
            "name": "Norton ConnectSafe",
            "provider": "Norton",
            "ip": "199.85.126.10",
            "ipv6": "",
            "type": "public",
            "category": "security",
            "features": ["Malware Protection", "Phishing Protection"],
            "description": "Norton's security-focused DNS service",
            "country": "USA",
        },
        {
            "name": "ControlD",
            "provider": "ControlD",
            "ip": "76.76.2.0",
            "ipv6": "2606:1a40::",
            "type": "public",
            "category": "customizable",
            "features": ["Custom Filtering", "Analytics", "DoH"],
            "description": "Customizable DNS with extensive filtering options",
            "country": "Canada",
        },
        {
            "name": "Alternate DNS",
            "provider": "Alternate",
            "ip": "76.76.19.19",
            "ipv6": "",
            "type": "public",
            "category": "privacy",
            "features": ["Ad Blocking", "Tracker Blocking"],
            "description": "Alternative DNS focused on privacy and ad blocking",
            "country": "USA",
        },
        {
            "name": "CZ.NIC",
            "provider": "CZ.NIC",
            "ip": "193.17.47.1",
            "ipv6": "2001:148f:ffff::1",
            "type": "public",
            "category": "regional",
            "features": ["DNSSEC", "Local Optimization"],
            "description": "Czech NIC's public DNS service",
            "country": "Czech Republic",
        },
    ]

    @staticmethod
    def get_default_resolvers() -> List[Dict[str, str]]:
        """Get a list of commonly used public resolvers."""
        return [
            {"name": "Cloudflare", "ip": "1.1.1.1"},
            {"name": "Google", "ip": "8.8.8.8"},
            {"name": "Quad9", "ip": "9.9.9.9"},
            {"name": "OpenDNS", "ip": "208.67.222.222"},
            {"name": "Comodo", "ip": "8.26.56.26"},
        ]

    @staticmethod
    def load_resolvers_from_file(file_path: str) -> List[Dict[str, str]]:
        """Load resolvers from JSON file."""
        with open(file_path, "r") as f:
            data: Dict[str, Any] = json.load(f)
        return cast(List[Dict[str, str]], data.get("resolvers", []))

    @staticmethod
    def get_all_resolvers() -> List[Dict[str, Any]]:
        """Get all available resolvers with detailed information."""
        return ResolverManager.RESOLVERS_DATABASE

    @staticmethod
    def get_resolvers_by_category(category: str) -> List[Dict[str, Any]]:
        """Get resolvers filtered by category."""
        return [
            r
            for r in ResolverManager.RESOLVERS_DATABASE
            if r.get("category") == category
        ]

    @staticmethod
    def get_categories() -> List[str]:
        """Get all available resolver categories."""
        categories: set[str] = {
            str(r["category"]) for r in ResolverManager.RESOLVERS_DATABASE
        }
        return sorted(categories)


class DomainManager:
    """Manage domain lists with comprehensive database."""

    # Comprehensive domain database
    DOMAINS_DATABASE = [
        {
            "domain": "google.com",
            "category": "search",
            "description": "World's most popular search engine",
            "country": "USA",
        },
        {
            "domain": "youtube.com",
            "category": "video",
            "description": "Video sharing platform",
            "country": "USA",
        },
        {
            "domain": "facebook.com",
            "category": "social",
            "description": "Social networking service",
            "country": "USA",
        },
        {
            "domain": "amazon.com",
            "category": "ecommerce",
            "description": "E-commerce and cloud computing",
            "country": "USA",
        },
        {
            "domain": "twitter.com",
            "category": "social",
            "description": "Social media and microblogging",
            "country": "USA",
        },
        {
            "domain": "instagram.com",
            "category": "social",
            "description": "Photo and video sharing platform",
            "country": "USA",
        },
        {
            "domain": "linkedin.com",
            "category": "professional",
            "description": "Professional networking",
            "country": "USA",
        },
        {
            "domain": "wikipedia.org",
            "category": "reference",
            "description": "Free online encyclopedia",
            "country": "USA",
        },
        {
            "domain": "microsoft.com",
            "category": "tech",
            "description": "Software and technology company",
            "country": "USA",
        },
        {
            "domain": "apple.com",
            "category": "tech",
            "description": "Consumer electronics and software",
            "country": "USA",
        },
        {
            "domain": "netflix.com",
            "category": "streaming",
            "description": "Video streaming service",
            "country": "USA",
        },
        {
            "domain": "github.com",
            "category": "tech",
            "description": "Code hosting and collaboration",
            "country": "USA",
        },
        {
            "domain": "stackoverflow.com",
            "category": "tech",
            "description": "Programming Q&A community",
            "country": "USA",
        },
        {
            "domain": "reddit.com",
            "category": "social",
            "description": "Social news aggregation",
            "country": "USA",
        },
        {
            "domain": "whatsapp.com",
            "category": "messaging",
            "description": "Instant messaging platform",
            "country": "USA",
        },
        {
            "domain": "cloudflare.com",
            "category": "infrastructure",
            "description": "CDN and security services",
            "country": "USA",
        },
        {
            "domain": "baidu.com",
            "category": "search",
            "description": "Chinese search engine",
            "country": "China",
        },
        {
            "domain": "taobao.com",
            "category": "ecommerce",
            "description": "Chinese online shopping",
            "country": "China",
        },
        {
            "domain": "qq.com",
            "category": "portal",
            "description": "Chinese web portal",
            "country": "China",
        },
        {
            "domain": "tmall.com",
            "category": "ecommerce",
            "description": "Chinese B2C online retail",
            "country": "China",
        },
        {
            "domain": "yahoo.com",
            "category": "portal",
            "description": "Web services portal",
            "country": "USA",
        },
        {
            "domain": "bing.com",
            "category": "search",
            "description": "Microsoft's search engine",
            "country": "USA",
        },
        {
            "domain": "live.com",
            "category": "email",
            "description": "Microsoft email and services",
            "country": "USA",
        },
        {
            "domain": "office.com",
            "category": "productivity",
            "description": "Microsoft Office suite",
            "country": "USA",
        },
        {
            "domain": "zoom.us",
            "category": "communication",
            "description": "Video conferencing platform",
            "country": "USA",
        },
        {
            "domain": "slack.com",
            "category": "communication",
            "description": "Business communication platform",
            "country": "USA",
        },
        {
            "domain": "dropbox.com",
            "category": "storage",
            "description": "Cloud storage service",
            "country": "USA",
        },
        {
            "domain": "adobe.com",
            "category": "creative",
            "description": "Creative software suite",
            "country": "USA",
        },
        {
            "domain": "paypal.com",
            "category": "finance",
            "description": "Online payments system",
            "country": "USA",
        },
        {
            "domain": "wordpress.com",
            "category": "publishing",
            "description": "Blogging and website platform",
            "country": "USA",
        },
        {
            "domain": "medium.com",
            "category": "publishing",
            "description": "Online publishing platform",
            "country": "USA",
        },
        {
            "domain": "quora.com",
            "category": "qna",
            "description": "Question and answer platform",
            "country": "USA",
        },
        {
            "domain": "imdb.com",
            "category": "entertainment",
            "description": "Movie and TV database",
            "country": "USA",
        },
        {
            "domain": "bbc.com",
            "category": "news",
            "description": "British broadcasting news",
            "country": "UK",
        },
        {
            "domain": "cnn.com",
            "category": "news",
            "description": "Cable news network",
            "country": "USA",
        },
        {
            "domain": "nytimes.com",
            "category": "news",
            "description": "New York Times newspaper",
            "country": "USA",
        },
        {
            "domain": "weather.com",
            "category": "weather",
            "description": "Weather forecasting service",
            "country": "USA",
        },
        {
            "domain": "espn.com",
            "category": "sports",
            "description": "Sports news and coverage",
            "country": "USA",
        },
        {
            "domain": "craigslist.org",
            "category": "classifieds",
            "description": "Classified advertisements",
            "country": "USA",
        },
        {
            "domain": "ebay.com",
            "category": "ecommerce",
            "description": "Online auction and shopping",
            "country": "USA",
        },
        {
            "domain": "aliexpress.com",
            "category": "ecommerce",
            "description": "Chinese online retail",
            "country": "China",
        },
        {
            "domain": "walmart.com",
            "category": "ecommerce",
            "description": "Multinational retail corporation",
            "country": "USA",
        },
        {
            "domain": "target.com",
            "category": "ecommerce",
            "description": "Retail corporation",
            "country": "USA",
        },
        {
            "domain": "bestbuy.com",
            "category": "ecommerce",
            "description": "Consumer electronics retailer",
            "country": "USA",
        },
        {
            "domain": "hulu.com",
            "category": "streaming",
            "description": "Video streaming service",
            "country": "USA",
        },
        {
            "domain": "spotify.com",
            "category": "music",
            "description": "Music streaming platform",
            "country": "Sweden",
        },
        {
            "domain": "soundcloud.com",
            "category": "music",
            "description": "Audio distribution platform",
            "country": "Germany",
        },
        {
            "domain": "deezer.com",
            "category": "music",
            "description": "Music streaming service",
            "country": "France",
        },
        {
            "domain": "twitch.tv",
            "category": "gaming",
            "description": "Live streaming for gamers",
            "country": "USA",
        },
        {
            "domain": "steampowered.com",
            "category": "gaming",
            "description": "Digital game distribution",
            "country": "USA",
        },
        {
            "domain": "epicgames.com",
            "category": "gaming",
            "description": "Video game and software developer",
            "country": "USA",
        },
        {
            "domain": "ubuntu.com",
            "category": "tech",
            "description": "Linux distribution",
            "country": "UK",
        },
        {
            "domain": "docker.com",
            "category": "tech",
            "description": "Container platform",
            "country": "USA",
        },
        {
            "domain": "kubernetes.io",
            "category": "tech",
            "description": "Container orchestration",
            "country": "USA",
        },
        {
            "domain": "gitlab.com",
            "category": "tech",
            "description": "DevOps platform",
            "country": "USA",
        },
        {
            "domain": "atlassian.com",
            "category": "tech",
            "description": "Software development tools",
            "country": "Australia",
        },
        {
            "domain": "notion.so",
            "category": "productivity",
            "description": "Note-taking and collaboration",
            "country": "USA",
        },
        {
            "domain": "figma.com",
            "category": "design",
            "description": "Collaborative design tool",
            "country": "USA",
        },
        {
            "domain": "canva.com",
            "category": "design",
            "description": "Graphic design platform",
            "country": "Australia",
        },
    ]

    @staticmethod
    def get_sample_domains() -> List[str]:
        """Get a list of sample domains for testing."""
        return [
            "google.com",
            "github.com",
            "stackoverflow.com",
            "wikipedia.org",
            "reddit.com",
            "twitter.com",
            "linkedin.com",
            "microsoft.com",
            "apple.com",
            "amazon.com",
        ]

    @staticmethod
    def load_domains_from_file(file_path: str) -> List[str]:
        """Load domains from text file (one per line)."""
        with open(file_path, "r") as f:
            domains = [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
        return domains

    @staticmethod
    def get_all_domains() -> List[Dict[str, str]]:
        """Get all available domains with detailed information."""
        return DomainManager.DOMAINS_DATABASE

    @staticmethod
    def get_domains_by_category(category: str) -> List[Dict[str, str]]:
        """Get domains filtered by category."""
        return [
            d for d in DomainManager.DOMAINS_DATABASE if d.get("category") == category
        ]

    @staticmethod
    def get_categories() -> List[str]:
        """Get all available domain categories."""
        categories = set(d["category"] for d in DomainManager.DOMAINS_DATABASE)
        return sorted(list(categories))

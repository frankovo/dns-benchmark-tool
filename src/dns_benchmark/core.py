"""Core DNS benchmarking functionality."""

import asyncio
import ipaddress
import json
import ssl
import struct
import time
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, cast

import click
import dns.asyncresolver
import dns.exception
import dns.flags
import dns.message
import dns.name

# import dns.query
import dns.rdatatype
import httpx
import idna

from dns_benchmark.utils.messages import warning


class QueryStatus(Enum):
    SUCCESS = "success"
    TIMEOUT = "timeout"
    NXDOMAIN = "nxdomain"
    SERVFAIL = "servfail"
    CONNECTION_REFUSED = "connection_refused"
    UNKNOWN_ERROR = "unknown_error"
    DNSSEC_FAILED = "dnssec_failed"


class QueryProtocol(Enum):
    PLAIN = "plain"
    DOH = "doh"
    DOT = "dot"


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
    attempt_number: int = 1
    cache_hit: bool = False
    dnssec_validated: bool = False
    protocol: QueryProtocol = QueryProtocol.PLAIN
    iteration: int = 1  # which iteration this query belongs to
    query_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["protocol"] = self.protocol.value
        return d


class DNSQueryEngine:
    """Async DNS query engine with rate limiting and retry logic."""

    def __init__(
        self,
        max_concurrent_queries: int = 100,
        timeout: float = 5.0,
        max_retries: int = 2,
        enable_cache: bool = False,
        retry_backoff_multiplier: float = 0.1,
        retry_backoff_base: float = 2.0,
        enable_dnssec: bool = False,
        enforce_dnssec: bool = False,  # True when --dnssec-validate passed
    ) -> None:
        self.max_concurrent_queries = max_concurrent_queries
        self.timeout = timeout
        self.max_retries = max_retries
        # lazy-init async primitives to avoid creating them outside an event loop
        self.semaphore: Optional[asyncio.Semaphore] = None
        self._lock: Optional[asyncio.Lock] = None
        self.progress_callback: Optional[Callable[[int, int], None]] = None
        self.query_counter = 0
        self.total_queries = 0
        self.enable_cache = enable_cache
        self.cache: Dict[str, DNSQueryResult] = {}
        self.retry_backoff_multiplier = retry_backoff_multiplier
        self.retry_backoff_base = retry_backoff_base
        self.failed_resolvers: Dict[str, int] = defaultdict(int)
        self.enable_dnssec = enable_dnssec
        self.enforce_dnssec = enforce_dnssec

    async def _ensure_async_primitives(self) -> None:
        """Create asyncio primitives when running inside an event loop."""
        if self.semaphore is None:
            self.semaphore = asyncio.Semaphore(self.max_concurrent_queries)
        if self._lock is None:
            self._lock = asyncio.Lock()

    def set_progress_callback(self, callback: Callable[[int, int], None]) -> None:
        """Set callback for progress updates with completed/total counts."""
        self.progress_callback = callback

    def _get_cache_key(self, resolver_ip: str, domain: str, record_type: str) -> str:
        """Generate cache key for query."""
        return f"{resolver_ip}:{domain}:{record_type}"

    async def _update_progress(self) -> None:
        """Thread-safe progress update."""
        await self._ensure_async_primitives()
        assert self._lock is not None
        async with self._lock:
            self.query_counter += 1
            if self.progress_callback:
                self.progress_callback(self.query_counter, self.total_queries)

    def _validate_resolver(self, resolver: Dict[str, str]) -> None:
        """Validate resolver configuration."""
        if "ip" not in resolver:
            raise ValueError(f"Resolver missing 'ip' key: {resolver}")
        if "name" not in resolver:
            raise ValueError(f"Resolver missing 'name' key: {resolver}")

    async def query_single(
        self,
        resolver_ip: str,
        resolver_name: str,
        domain: str,
        record_type: str = "A",
        use_cache: bool = True,
        iteration: int = 1,
    ) -> DNSQueryResult:
        """Execute a single DNS query with retry logic and caching."""
        await self._ensure_async_primitives()
        assert self.semaphore is not None
        # Check cache if enabled
        if self.enable_cache and use_cache:
            cache_key = self._get_cache_key(resolver_ip, domain, record_type)
            if cache_key in self.cache:
                cached_result = self.cache[cache_key]
                # Create new instance preserving original data but marking as cache hit
                result = DNSQueryResult(
                    **{
                        **asdict(cached_result),
                        "cache_hit": True,
                        "iteration": iteration,
                    }
                )
                await self._update_progress()
                return result

        start_time = time.time()  # fallback; overwritten inside semaphore per attempt

        for attempt in range(self.max_retries + 1):
            try:
                async with self.semaphore:
                    start_time = time.time()
                    resolver = dns.asyncresolver.Resolver()
                    resolver.nameservers = [resolver_ip]
                    resolver.timeout = self.timeout
                    resolver.lifetime = self.timeout

                    if self.enable_dnssec:
                        resolver.use_edns(0, dns.flags.DO, 1232)

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

                    # DNSSEC: always read AD flag, enforce only if requested
                    ad_flag = False
                    try:
                        ad_flag = bool(response.response.flags & dns.flags.AD)
                    except AttributeError:
                        pass

                    dnssec_status = QueryStatus.SUCCESS
                    if self.enforce_dnssec and not ad_flag:
                        dnssec_status = QueryStatus.DNSSEC_FAILED

                    result = DNSQueryResult(
                        resolver_ip=resolver_ip,
                        resolver_name=resolver_name,
                        domain=domain,
                        record_type=record_type,
                        start_time=start_time,
                        end_time=end_time,
                        latency_ms=latency_ms,
                        status=dnssec_status,
                        answers=answers,
                        ttl=ttl,
                        attempt_number=attempt + 1,
                        cache_hit=False,
                        iteration=iteration,
                        dnssec_validated=ad_flag,
                        protocol=QueryProtocol.PLAIN,
                    )

                    # Cache successful result
                    if self.enable_cache:
                        cache_key = self._get_cache_key(
                            resolver_ip, domain, record_type
                        )
                        self.cache[cache_key] = result

                    await self._update_progress()
                    return result

            except dns.exception.Timeout:
                if attempt == self.max_retries:
                    end_time = time.time()
                    assert self._lock is not None
                    async with self._lock:
                        self.failed_resolvers[resolver_ip] += 1
                    result = DNSQueryResult(
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
                        attempt_number=attempt + 1,
                        cache_hit=False,
                        iteration=iteration,
                    )
                    await self._update_progress()
                    return result
                # Exponential backoff with configurable base
                await asyncio.sleep(
                    self.retry_backoff_base**attempt * self.retry_backoff_multiplier
                )

            except dns.resolver.NXDOMAIN:
                # NXDOMAIN is a definitive answer, no retry needed
                end_time = time.time()
                result = DNSQueryResult(
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
                    attempt_number=attempt + 1,
                    cache_hit=False,
                    iteration=iteration,
                )
                await self._update_progress()
                return result

            except dns.resolver.NoAnswer:
                # Blocked/sinkholed domains (e.g. 0.0.0.0 from AdGuard/Pi-hole)
                # return NOERROR with an empty rrset. This is a valid fast response,
                # not a failure — do not retry.
                end_time = time.time()
                result = DNSQueryResult(
                    resolver_ip=resolver_ip,
                    resolver_name=resolver_name,
                    domain=domain,
                    record_type=record_type,
                    start_time=start_time,
                    end_time=end_time,
                    latency_ms=(end_time - start_time) * 1000,
                    status=QueryStatus.SUCCESS,
                    answers=[],
                    ttl=None,
                    attempt_number=attempt + 1,
                    cache_hit=False,
                    iteration=iteration,
                )
                await self._update_progress()
                return result

            except dns.resolver.NoNameservers:
                # Server failure, no retry needed
                end_time = time.time()
                assert self._lock is not None
                async with self._lock:
                    self.failed_resolvers[resolver_ip] += 1
                result = DNSQueryResult(
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
                    attempt_number=attempt + 1,
                    cache_hit=False,
                    iteration=iteration,
                )
                await self._update_progress()
                return result

            except Exception as e:
                if attempt == self.max_retries:
                    end_time = time.time()
                    error_status = QueryStatus.UNKNOWN_ERROR
                    if "refused" in str(e).lower():
                        error_status = QueryStatus.CONNECTION_REFUSED
                    assert self._lock is not None  # mypy now knows _lock is Lock
                    async with self._lock:
                        self.failed_resolvers[resolver_ip] += 1

                    result = DNSQueryResult(
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
                        attempt_number=attempt + 1,
                        cache_hit=False,
                        iteration=iteration,
                    )
                    await self._update_progress()
                    return result
                # Exponential backoff with configurable base
                await asyncio.sleep(
                    self.retry_backoff_base**attempt * self.retry_backoff_multiplier
                )

        # This should never be reached due to loop logic, but provide fallback
        # for safety
        end_time = time.time()
        result = DNSQueryResult(
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
            error_message="Unexpected error: exhausted all retries without return",
            cache_hit=False,
            iteration=iteration,
        )
        await self._update_progress()
        return result

    async def query_single_doh(
        self,
        resolver_ip: str,
        resolver_name: str,
        domain: str,
        doh_url: str,
        record_type: str = "A",
        iteration: int = 1,
    ) -> DNSQueryResult:
        """Execute a single DNS-over-HTTPS query."""

        await self._ensure_async_primitives()
        assert self.semaphore is not None

        start_time = time.time()

        for attempt in range(self.max_retries + 1):
            try:
                async with self.semaphore:
                    start_time = time.time()

                    # Build DNS wire-format query
                    qname = dns.name.from_text(domain)
                    rdtype = dns.rdatatype.from_text(record_type)
                    request = dns.message.make_query(qname, rdtype)
                    if self.enable_dnssec:
                        request.use_edns(ednsflags=dns.flags.DO)
                    wire = request.to_wire()

                    async with httpx.AsyncClient(
                        http2=True,
                        timeout=self.timeout,
                        verify=True,  # enforce TLS — never disable
                    ) as client:
                        response_raw = await client.post(
                            doh_url,
                            content=wire,
                            headers={
                                "Content-Type": "application/dns-message",
                                "Accept": "application/dns-message",
                            },
                        )
                        response_raw.raise_for_status()

                    end_time = time.time()
                    latency_ms = (end_time - start_time) * 1000

                    dns_response = dns.message.from_wire(response_raw.content)
                    answers = [
                        str(rdata) for rrset in dns_response.answer for rdata in rrset
                    ]
                    ttl = dns_response.answer[0].ttl if dns_response.answer else None

                    ad_flag = bool(dns_response.flags & dns.flags.AD)
                    dnssec_status = QueryStatus.SUCCESS
                    if self.enforce_dnssec and not ad_flag:
                        dnssec_status = QueryStatus.DNSSEC_FAILED

                    result = DNSQueryResult(
                        resolver_ip=resolver_ip,
                        resolver_name=resolver_name,
                        domain=domain,
                        record_type=record_type,
                        start_time=start_time,
                        end_time=end_time,
                        latency_ms=latency_ms,
                        status=dnssec_status,
                        answers=answers,
                        ttl=ttl,
                        attempt_number=attempt + 1,
                        cache_hit=False,
                        iteration=iteration,
                        dnssec_validated=ad_flag,
                        protocol=QueryProtocol.DOH,
                    )
                    await self._update_progress()
                    return result

            except httpx.TimeoutException:
                if attempt == self.max_retries:
                    end_time = time.time()
                    async with self._lock:  # type: ignore[union-attr]
                        self.failed_resolvers[resolver_ip] += 1
                    result = DNSQueryResult(
                        resolver_ip=resolver_ip,
                        resolver_name=resolver_name,
                        domain=domain,
                        record_type=record_type,
                        start_time=start_time,
                        end_time=time.time(),
                        latency_ms=(time.time() - start_time) * 1000,
                        status=QueryStatus.TIMEOUT,
                        answers=[],
                        ttl=None,
                        error_message="DoH timeout",
                        attempt_number=attempt + 1,
                        cache_hit=False,
                        iteration=iteration,
                        protocol=QueryProtocol.DOH,
                    )
                    await self._update_progress()
                    return result
                await asyncio.sleep(
                    self.retry_backoff_base**attempt * self.retry_backoff_multiplier
                )

            except Exception as e:
                if attempt == self.max_retries:
                    end_time = time.time()
                    async with self._lock:  # type: ignore[union-attr]
                        self.failed_resolvers[resolver_ip] += 1
                    result = DNSQueryResult(
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
                        error_message=str(e),
                        attempt_number=attempt + 1,
                        cache_hit=False,
                        iteration=iteration,
                        protocol=QueryProtocol.DOH,
                    )
                    await self._update_progress()
                    return result
                await asyncio.sleep(
                    self.retry_backoff_base**attempt * self.retry_backoff_multiplier
                )

        # unreachable fallback
        return DNSQueryResult(
            resolver_ip=resolver_ip,
            resolver_name=resolver_name,
            domain=domain,
            record_type=record_type,
            start_time=start_time,
            end_time=time.time(),
            latency_ms=0.0,
            status=QueryStatus.UNKNOWN_ERROR,
            answers=[],
            ttl=None,
            error_message="Exhausted retries",
            cache_hit=False,
            iteration=iteration,
            protocol=QueryProtocol.DOH,
        )

    async def query_single_dot(
        self,
        resolver_ip: str,
        resolver_name: str,
        domain: str,
        record_type: str = "A",
        port: int = 853,
        iteration: int = 1,
    ) -> DNSQueryResult:
        """Execute a single DNS-over-TLS query."""

        await self._ensure_async_primitives()
        assert self.semaphore is not None

        start_time = time.time()

        for attempt in range(self.max_retries + 1):
            try:
                async with self.semaphore:
                    start_time = time.time()

                    # Build wire-format query with length prefix (RFC 7858)
                    qname = dns.name.from_text(domain)
                    rdtype = dns.rdatatype.from_text(record_type)
                    request = dns.message.make_query(qname, rdtype)
                    if self.enable_dnssec:
                        request.use_edns(ednsflags=dns.flags.DO)
                    wire = request.to_wire()
                    # 2-byte length prefix required by DoT spec
                    prefixed = struct.pack("!H", len(wire)) + wire

                    ssl_ctx = ssl.create_default_context()
                    # enforce cert validation — never bypass for security tool
                    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
                    ssl_ctx.check_hostname = True

                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(resolver_ip, port, ssl=ssl_ctx),
                        timeout=self.timeout,
                    )
                    try:
                        writer.write(prefixed)
                        await writer.drain()

                        # Read 2-byte length prefix then full message
                        raw_len = await asyncio.wait_for(
                            reader.readexactly(2), timeout=self.timeout
                        )
                        msg_len = struct.unpack("!H", raw_len)[0]
                        raw_msg = await asyncio.wait_for(
                            reader.readexactly(msg_len), timeout=self.timeout
                        )
                    finally:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass

                    end_time = time.time()
                    latency_ms = (end_time - start_time) * 1000

                    dns_response = dns.message.from_wire(raw_msg)
                    answers = [
                        str(rdata) for rrset in dns_response.answer for rdata in rrset
                    ]
                    ttl = dns_response.answer[0].ttl if dns_response.answer else None

                    ad_flag = bool(dns_response.flags & dns.flags.AD)
                    dnssec_status = QueryStatus.SUCCESS
                    if self.enforce_dnssec and not ad_flag:
                        dnssec_status = QueryStatus.DNSSEC_FAILED

                    result = DNSQueryResult(
                        resolver_ip=resolver_ip,
                        resolver_name=resolver_name,
                        domain=domain,
                        record_type=record_type,
                        start_time=start_time,
                        end_time=end_time,
                        latency_ms=latency_ms,
                        status=dnssec_status,
                        answers=answers,
                        ttl=ttl,
                        attempt_number=attempt + 1,
                        cache_hit=False,
                        iteration=iteration,
                        dnssec_validated=ad_flag,
                        protocol=QueryProtocol.DOT,
                    )
                    await self._update_progress()
                    return result

            except asyncio.TimeoutError:
                if attempt == self.max_retries:
                    async with self._lock:  # type: ignore[union-attr]
                        self.failed_resolvers[resolver_ip] += 1
                    result = DNSQueryResult(
                        resolver_ip=resolver_ip,
                        resolver_name=resolver_name,
                        domain=domain,
                        record_type=record_type,
                        start_time=start_time,
                        end_time=time.time(),
                        latency_ms=(time.time() - start_time) * 1000,
                        status=QueryStatus.TIMEOUT,
                        answers=[],
                        ttl=None,
                        error_message="DoT timeout",
                        attempt_number=attempt + 1,
                        cache_hit=False,
                        iteration=iteration,
                        protocol=QueryProtocol.DOT,
                    )
                    await self._update_progress()
                    return result
                await asyncio.sleep(
                    self.retry_backoff_base**attempt * self.retry_backoff_multiplier
                )

            except ssl.SSLError as e:
                # SSL errors are not retryable
                async with self._lock:  # type: ignore[union-attr]
                    self.failed_resolvers[resolver_ip] += 1
                result = DNSQueryResult(
                    resolver_ip=resolver_ip,
                    resolver_name=resolver_name,
                    domain=domain,
                    record_type=record_type,
                    start_time=start_time,
                    end_time=time.time(),
                    latency_ms=(time.time() - start_time) * 1000,
                    status=QueryStatus.CONNECTION_REFUSED,
                    answers=[],
                    ttl=None,
                    error_message=f"TLS error: {e}",
                    attempt_number=attempt + 1,
                    cache_hit=False,
                    iteration=iteration,
                    protocol=QueryProtocol.DOT,
                )
                await self._update_progress()
                return result

            except Exception as e:
                if attempt == self.max_retries:
                    async with self._lock:  # type: ignore[union-attr]
                        self.failed_resolvers[resolver_ip] += 1
                    result = DNSQueryResult(
                        resolver_ip=resolver_ip,
                        resolver_name=resolver_name,
                        domain=domain,
                        record_type=record_type,
                        start_time=start_time,
                        end_time=time.time(),
                        latency_ms=(time.time() - start_time) * 1000,
                        status=QueryStatus.UNKNOWN_ERROR,
                        answers=[],
                        ttl=None,
                        error_message=str(e),
                        attempt_number=attempt + 1,
                        cache_hit=False,
                        iteration=iteration,
                        protocol=QueryProtocol.DOT,
                    )
                    await self._update_progress()
                    return result
                await asyncio.sleep(
                    self.retry_backoff_base**attempt * self.retry_backoff_multiplier
                )

        # unreachable fallback
        return DNSQueryResult(
            resolver_ip=resolver_ip,
            resolver_name=resolver_name,
            domain=domain,
            record_type=record_type,
            start_time=start_time,
            end_time=time.time(),
            latency_ms=0.0,
            status=QueryStatus.UNKNOWN_ERROR,
            answers=[],
            ttl=None,
            error_message="Exhausted retries",
            cache_hit=False,
            iteration=iteration,
            protocol=QueryProtocol.DOT,
        )

    async def run_benchmark(
        self,
        resolvers: List[Dict[str, str]],
        domains: List[str],
        record_types: Optional[List[str]] = None,
        iterations: int = 1,
        warmup: bool = False,
        warmup_fast: bool = False,
        use_cache: bool = False,
        protocol: QueryProtocol = QueryProtocol.PLAIN,
        doh_urls: Optional[Dict[str, str]] = None,  # resolver_ip -> doh_url
    ) -> List[DNSQueryResult]:
        """Run benchmark across all resolvers and domains.

        Args:
            resolvers: List of resolver dicts with 'ip' and 'name' keys
            domains: List of domain names to query
            record_types: List of DNS record types (default: ["A"])
            iterations: Number of times to repeat the benchmark
            warmup: Run full warmup (all resolvers × all domains × all record types)
            warmup_fast: Run fast warmup (one probe per resolver, overrides warmup)
            use_cache: Allow cache usage across iterations

        Returns:
            List of DNSQueryResult objects
        """

        # Validate resolvers
        for resolver in resolvers:
            self._validate_resolver(resolver)

        if not record_types:
            record_types = ["A"]

        # Warmup handling (warmup_fast takes precedence)
        if warmup_fast:
            warmup_results = await self._run_fast_warmup(resolvers)
        elif warmup:
            warmup_results = await self._run_warmup(resolvers, domains, record_types)
        else:
            warmup_results = []

        # Report warmup failures
        for r in warmup_results:
            if r.status != QueryStatus.SUCCESS:
                click.echo(
                    warning(
                        f"Warmup failed: {r.resolver_name} ({r.resolver_ip}) → {r.status.value}"
                    )
                )

        # Reset counters for actual benchmark
        self.query_counter = 0
        self.total_queries = (
            len(resolvers) * len(domains) * len(record_types) * iterations
        )

        tasks = []
        for iteration in range(iterations):
            for resolver in resolvers:
                for domain in domains:
                    for record_type in record_types:
                        if protocol == QueryProtocol.DOH:
                            url = (doh_urls or {}).get(resolver["ip"], "")
                            task = self.query_single_doh(
                                resolver_ip=resolver["ip"],
                                resolver_name=resolver["name"],
                                domain=domain,
                                doh_url=url,
                                record_type=record_type,
                                iteration=iteration + 1,
                            )
                        elif protocol == QueryProtocol.DOT:
                            task = self.query_single_dot(
                                resolver_ip=resolver["ip"],
                                resolver_name=resolver["name"],
                                domain=domain,
                                record_type=record_type,
                                iteration=iteration + 1,
                            )
                        else:
                            task = self.query_single(
                                resolver_ip=resolver["ip"],
                                resolver_name=resolver["name"],
                                domain=domain,
                                record_type=record_type,
                                use_cache=use_cache,
                                iteration=iteration + 1,
                            )
                        tasks.append(task)

        results = await asyncio.gather(*tasks)
        return list(results)

    async def _run_warmup(
        self,
        resolvers: List[Dict[str, str]],
        domains: List[str],
        record_types: List[str],
    ) -> List[DNSQueryResult]:
        """Run full warmup queries (all combinations).

        Does not update progress counters or cache results.
        """
        tasks = []
        for resolver in resolvers:
            for domain in domains:
                for record_type in record_types:
                    task = self.query_single(
                        resolver_ip=resolver["ip"],
                        resolver_name=resolver["name"],
                        domain=domain,
                        record_type=record_type,
                        use_cache=False,
                        iteration=0,  # Mark as warmup
                    )
                    tasks.append(task)
        return await asyncio.gather(*tasks)

    async def _run_fast_warmup(
        self,
        resolvers: List[Dict[str, str]],
        probe_domain: str = "example.com",
        record_type: str = "A",
    ) -> List[DNSQueryResult]:
        """Lightweight warmup: one query per resolver.

        Uses a known-good domain to verify resolver connectivity.
        Does not update progress counters or cache results.
        """
        tasks = [
            self.query_single(
                resolver_ip=r["ip"],
                resolver_name=r["name"],
                domain=probe_domain,
                record_type=record_type,
                use_cache=False,
                iteration=0,  # Mark as warmup
            )
            for r in resolvers
        ]
        return await asyncio.gather(*tasks)

    def clear_cache(self) -> None:
        """Clear the query cache."""
        self.cache.clear()

    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {
            "cached_entries": len(self.cache),
            "cache_enabled": self.enable_cache,
        }

    def get_failed_resolvers(self) -> Dict[str, int]:
        """Get resolvers with failure counts."""
        return dict(self.failed_resolvers)


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
            "doh_url": "https://cloudflare-dns.com/dns-query",
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
            "doh_url": "https://family.cloudflare-dns.com/dns-query",
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
            "doh_url": "https://dns.google/dns-query",
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
            "doh_url": "https://dns.quad9.net/dns-query",
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
            "doh_url": "https://doh.opendns.com/dns-query",
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
            "doh_url": "https://doh.familyshield.opendns.com/dns-query",
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
            "doh_url": "https://dns.adguard.com/dns-query",
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
            "doh_url": "https://dns-family.adguard.com/dns-query",
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
            "doh_url": "https://doh.cleanbrowsing.org/doh/family-filter/",
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
            "doh_url": "https://dns.yandex.net/dns-query",
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
            "doh_url": "https://dns.neustar/dns-query",
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
            "doh_url": "https://doh.safedns.com/dns-query",
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
            "doh_url": "https://freedns.controld.com/p0",
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
            "doh_url": "https://dns.alternate-dns.com/dns-query",
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
            "doh_url": "https://odvr.nic.cz/doh",
        },
        # --- NO DoH support. If you know a valid endpoint, please open a Pull Request ---
        #    {
        #        "name": "Comodo Secure",
        #        "provider": "Comodo",
        #        "ip": "8.26.56.26",
        #        "ipv6": "",
        #        "type": "public",
        #        "category": "security",
        #        "features": ["Malware Protection", "Phishing Protection"],
        #        "description": "Comodo's secure DNS with threat protection",
        #        "country": "USA",
        #    },
        #    {
        #        "name": "Verisign",
        #        "provider": "Verisign",
        #        "ip": "64.6.64.6",
        #        "ipv6": "2620:74:1b::1:1",
        #        "type": "public",
        #        "category": "reliability",
        #        "features": ["Stability", "DNSSEC", "Anycast"],
        #        "description": "Verisign public DNS focused on stability and reliability",
        #        "country": "USA",
        #    },
        #    {
        #        "name": "DNS.WATCH",
        #        "provider": "DNS.WATCH",
        #        "ip": "84.200.69.80",
        #        "ipv6": "2001:1608:10:25::1c04:b12f",
        #        "type": "public",
        #        "category": "privacy",
        #        "features": ["No Filtering", "No Logging", "Net Neutrality"],
        #        "description": "German DNS provider with no filtering and strong privacy",
        #        "country": "Germany",
        #    },
        #    {
        #        "name": "Level3",
        #        "provider": "CenturyLink",
        #        "ip": "4.2.2.1",
        #        "ipv6": "",
        #        "type": "public",
        #        "category": "legacy",
        #        "features": ["Reliability", "Long History"],
        #        "description": "One of the original public DNS services",
        #        "country": "USA",
        #    },
        #    {
        #        "name": "Norton ConnectSafe",
        #        "provider": "Norton",
        #        "ip": "199.85.126.10",
        #        "ipv6": "",
        #        "type": "public",
        #        "category": "security",
        #        "features": ["Malware Protection", "Phishing Protection"],
        #        "description": "Norton's security-focused DNS service (discontinued)",
        #        "country": "USA",
        #    },
    ]

    @staticmethod
    def _match_resolver_name(resolver: Dict[str, Any], target: str) -> bool:
        """Check if resolver name matches target (handles both str and Sequence[str])."""
        name_val = resolver.get("name", "")
        if isinstance(name_val, str):
            return name_val.lower() == target.lower()
        elif isinstance(name_val, (list, tuple)) and name_val:
            first_item = name_val[0]
            if isinstance(first_item, str):
                return first_item.lower() == target.lower()
        return False

    @staticmethod
    def parse_resolver_string(resolver_string: str) -> List[Dict[str, str]]:
        """
        Parse comma-separated resolver IPs/names into resolver list.

        Supports:
        - IP addresses: "1.1.1.1,8.8.8.8"
        - IPv6 addresses: "2606:4700:4700::1111,2001:4860:4860::8888"
        - Named resolvers from database: "Cloudflare,Google"
        - Mixed: "1.1.1.1,Cloudflare"

        Args:
            resolver_string: Comma-separated resolver identifiers

        Returns:
            List of resolver dictionaries with 'name' and 'ip' keys
        """
        resolvers = []

        # Split by comma and clean whitespace
        parts: List[str] = [
            part.strip() for part in resolver_string.split(",") if part.strip()
        ]

        for part in parts:
            # Try IP detection (IPv4 or IPv6)
            try:
                ip_obj = ipaddress.ip_address(part)
                resolvers.append({"name": part, "ip": str(ip_obj)})
                continue
            except ValueError:
                pass

            # Try name lookup in database
            match = next(
                (
                    r
                    for r in ResolverManager.RESOLVERS_DATABASE
                    if ResolverManager._match_resolver_name(r, part)
                ),
                None,
            )
            if match:
                name_val = match["name"]
                ip_val = match["ip"]
                # Handle case where values might be sequences
                name_str = (
                    name_val[0]
                    if isinstance(name_val, (list, tuple))
                    else str(name_val)
                )
                ip_str = ip_val[0] if isinstance(ip_val, (list, tuple)) else str(ip_val)
                resolvers.append({"name": name_str, "ip": ip_str})
                continue

            # Fallback: treat as hostname or custom label
            resolvers.append({"name": part, "ip": part})

        return resolvers

    @staticmethod
    def parse_resolvers_input(input_value: Optional[str]) -> List[Dict[str, str]]:
        """
        Smart parser that handles both file paths and comma-separated inline values.

        Detection logic:
        1. If input contains comma and no file extension -> treat as comma-separated
        2. If file exists at path -> load from file
        3. If input looks like single IP -> treat as single resolver
        4. Otherwise -> try as file path (will raise FileNotFoundError if not found)

        Args:
            input_value: File path or comma-separated resolver string

        Returns:
            List of resolver dictionaries

        Raises:
            FileNotFoundError: If file path is invalid
            json.JSONDecodeError: If JSON file is malformed
            ValueError: If resolver input is invalid
        """
        if not input_value:
            raise ValueError("Resolver input cannot be empty")

        input_value = input_value.strip()

        # Check if it's a file path that exists
        path = Path(input_value)
        if path.exists() and path.is_file():
            return ResolverManager.load_resolvers_from_file(str(path))

        # Check if it contains comma (likely inline list)
        if "," in input_value:
            return ResolverManager.parse_resolver_string(input_value)

        # Check if it looks like a single IP address
        try:
            ip_obj = ipaddress.ip_address(input_value)
            return [{"name": input_value, "ip": str(ip_obj)}]
        except ValueError:
            pass

        # Check if it's a resolver name from database
        match = next(
            (
                r
                for r in ResolverManager.RESOLVERS_DATABASE
                if ResolverManager._match_resolver_name(r, input_value)
            ),
            None,
        )
        if match:
            name_val = match["name"]
            ip_val = match["ip"]
            # Handle case where values might be sequences
            name_str = (
                name_val[0] if isinstance(name_val, (list, tuple)) else str(name_val)
            )
            ip_str = ip_val[0] if isinstance(ip_val, (list, tuple)) else str(ip_val)
            return [{"name": name_str, "ip": ip_str}]

        # Last resort: try as file path (will raise FileNotFoundError)
        if not Path(input_value).exists():
            raise ValueError(
                f"Invalid resolver input: '{input_value}' is not a valid IP address, "
                f"resolver name, or existing file path"
            )

        return ResolverManager.load_resolvers_from_file(input_value)

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
    DOMAINS_DATABASE: List[Dict[str, Any]] = [
        {
            "domain": "google.com",
            "category": "search",
            "description": "World's most popular search engine",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "youtube.com",
            "category": "video",
            "description": "Video sharing platform",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "facebook.com",
            "category": "social",
            "description": "Social networking service",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "amazon.com",
            "category": "ecommerce",
            "description": "E-commerce and cloud computing",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "twitter.com",
            "category": "social",
            "description": "Social media and microblogging",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "instagram.com",
            "category": "social",
            "description": "Photo and video sharing platform",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "linkedin.com",
            "category": "professional",
            "description": "Professional networking",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "wikipedia.org",
            "category": "reference",
            "description": "Free online encyclopedia",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "microsoft.com",
            "category": "tech",
            "description": "Software and technology company",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "apple.com",
            "category": "tech",
            "description": "Consumer electronics and software",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "netflix.com",
            "category": "streaming",
            "description": "Video streaming service",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "github.com",
            "category": "tech",
            "description": "Code hosting and collaboration",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "stackoverflow.com",
            "category": "tech",
            "description": "Programming Q&A community",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "reddit.com",
            "category": "social",
            "description": "Social news aggregation",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "whatsapp.com",
            "category": "messaging",
            "description": "Instant messaging platform",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "cloudflare.com",
            "category": "infrastructure",
            "description": "CDN and security services",
            "country": "USA",
            "dnssec_signed": True,
        },
        {
            "domain": "isc.org",
            "category": "infrastructure",
            "description": "Internet Systems Consortium (BIND, DHCP)",
            "country": "USA",
            "dnssec_signed": True,
        },
        {
            "domain": "nlnetlabs.nl",
            "category": "dns",
            "description": "NLnet Labs (NSD, Unbound, ldns)",
            "country": "Netherlands",
            "dnssec_signed": True,
        },
        {
            "domain": "dnssec-tools.org",
            "category": "security",
            "description": "DNSSEC tools and test suite",
            "country": "USA",
            "dnssec_signed": True,
        },
        {
            "domain": "ietf.org",
            "category": "standards",
            "description": "Internet Engineering Task Force",
            "country": "USA",
            "dnssec_signed": True,
        },
        {
            "domain": "baidu.com",
            "category": "search",
            "description": "Chinese search engine",
            "country": "China",
            "dnssec_signed": False,
        },
        {
            "domain": "taobao.com",
            "category": "ecommerce",
            "description": "Chinese online shopping",
            "country": "China",
            "dnssec_signed": False,
        },
        {
            "domain": "qq.com",
            "category": "portal",
            "description": "Chinese web portal",
            "country": "China",
            "dnssec_signed": False,
        },
        {
            "domain": "tmall.com",
            "category": "ecommerce",
            "description": "Chinese B2C online retail",
            "country": "China",
            "dnssec_signed": False,
        },
        {
            "domain": "yahoo.com",
            "category": "portal",
            "description": "Web services portal",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "bing.com",
            "category": "search",
            "description": "Microsoft's search engine",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "live.com",
            "category": "email",
            "description": "Microsoft email and services",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "office.com",
            "category": "productivity",
            "description": "Microsoft Office suite",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "zoom.us",
            "category": "communication",
            "description": "Video conferencing platform",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "slack.com",
            "category": "communication",
            "description": "Business communication platform",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "dropbox.com",
            "category": "storage",
            "description": "Cloud storage service",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "adobe.com",
            "category": "creative",
            "description": "Creative software suite",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "paypal.com",
            "category": "finance",
            "description": "Online payments system",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "wordpress.com",
            "category": "publishing",
            "description": "Blogging and website platform",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "medium.com",
            "category": "publishing",
            "description": "Online publishing platform",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "quora.com",
            "category": "qna",
            "description": "Question and answer platform",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "imdb.com",
            "category": "entertainment",
            "description": "Movie and TV database",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "bbc.com",
            "category": "news",
            "description": "British broadcasting news",
            "country": "UK",
            "dnssec_signed": False,
        },
        {
            "domain": "cnn.com",
            "category": "news",
            "description": "Cable news network",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "nytimes.com",
            "category": "news",
            "description": "New York Times newspaper",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "weather.com",
            "category": "weather",
            "description": "Weather forecasting service",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "espn.com",
            "category": "sports",
            "description": "Sports news and coverage",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "craigslist.org",
            "category": "classifieds",
            "description": "Classified advertisements",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "ebay.com",
            "category": "ecommerce",
            "description": "Online auction and shopping",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "aliexpress.com",
            "category": "ecommerce",
            "description": "Chinese online retail",
            "country": "China",
            "dnssec_signed": False,
        },
        {
            "domain": "walmart.com",
            "category": "ecommerce",
            "description": "Multinational retail corporation",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "target.com",
            "category": "ecommerce",
            "description": "Retail corporation",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "bestbuy.com",
            "category": "ecommerce",
            "description": "Consumer electronics retailer",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "hulu.com",
            "category": "streaming",
            "description": "Video streaming service",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "spotify.com",
            "category": "music",
            "description": "Music streaming platform",
            "country": "Sweden",
            "dnssec_signed": False,
        },
        {
            "domain": "soundcloud.com",
            "category": "music",
            "description": "Audio distribution platform",
            "country": "Germany",
            "dnssec_signed": False,
        },
        {
            "domain": "deezer.com",
            "category": "music",
            "description": "Music streaming service",
            "country": "France",
            "dnssec_signed": False,
        },
        {
            "domain": "twitch.tv",
            "category": "gaming",
            "description": "Live streaming for gamers",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "steampowered.com",
            "category": "gaming",
            "description": "Digital game distribution",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "epicgames.com",
            "category": "gaming",
            "description": "Video game and software developer",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "ubuntu.com",
            "category": "tech",
            "description": "Linux distribution",
            "country": "UK",
            "dnssec_signed": False,
        },
        {
            "domain": "docker.com",
            "category": "tech",
            "description": "Container platform",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "kubernetes.io",
            "category": "tech",
            "description": "Container orchestration",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "gitlab.com",
            "category": "tech",
            "description": "DevOps platform",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "atlassian.com",
            "category": "tech",
            "description": "Software development tools",
            "country": "Australia",
            "dnssec_signed": False,
        },
        {
            "domain": "notion.so",
            "category": "productivity",
            "description": "Note-taking and collaboration",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "figma.com",
            "category": "design",
            "description": "Collaborative design tool",
            "country": "USA",
            "dnssec_signed": False,
        },
        {
            "domain": "canva.com",
            "category": "design",
            "description": "Graphic design platform",
            "country": "Australia",
            "dnssec_signed": False,
        },
    ]

    @staticmethod
    def parse_domain_string(domain_string: str) -> List[str]:
        """
        Parse comma-separated domain names into domain list.

        Supports:
        - Domain names: "google.com,github.com,example.com"
        - Domains with whitespace: "google.com, github.com, example.com"
        - Mixed case: "Google.com,GitHub.com"

        Args:
            domain_string: Comma-separated domain names

        Returns:
            List of domain strings (lowercased and cleaned)
        """
        domains = []
        seen = set()

        # Split by comma and clean whitespace
        parts = [
            part.strip().lower() for part in domain_string.split(",") if part.strip()
        ]

        for part in parts:
            # Remove trailing dot (FQDN normalization)
            part = part.rstrip(".")

            # Normalize IDN → punycode if possible
            try:
                part = idna.encode(part).decode("ascii")
            except idna.IDNAError:
                pass  # keep original if invalid IDN

            # Basic permissive validation (keep even if odd-looking)
            if "." in part and len(part) > 3:
                cleaned = part
            else:
                cleaned = part  # still include; DNS resolver will decide

            # Deduplicate while preserving order
            if cleaned not in seen:
                seen.add(cleaned)
                domains.append(cleaned)
        return domains

    @staticmethod
    def parse_domains_input(input_value: Optional[str]) -> List[str]:
        """
        Smart parser that handles both file paths and comma-separated inline values.

        Detection logic:
        1. If input contains comma -> treat as comma-separated
        2. If file exists at path -> load from file
        3. If input looks like single domain -> treat as single domain
        4. Otherwise -> try as file path (will raise FileNotFoundError if not found)

        Args:
            input_value: File path or comma-separated domain string

        Returns:
            List of domain strings

        Raises:
            FileNotFoundError: If file path is invalid
        """
        if not input_value:
            raise ValueError("Domain input cannot be empty")

        input_value = input_value.strip()

        # Check if it's a file path that exists
        path = Path(input_value)
        if path.exists() and path.is_file():
            return DomainManager.load_domains_from_file(str(path))

        # Check if it contains comma (likely inline list)
        if "," in input_value:
            return DomainManager.parse_domain_string(input_value)

        # Check if it looks like a single domain (has a dot)
        if "." in input_value:
            return [input_value.lower().strip()]

        # Last resort: try as file path (will raise FileNotFoundError)
        return DomainManager.load_domains_from_file(input_value)

    @staticmethod
    def get_sample_domains() -> List[str]:
        """Get a list of sample domains for testing."""
        return [
            # Signed domains with DNSSEC
            "cloudflare.com",
            "isc.org",
            "nlnetlabs.nl",
            "dnssec-tools.org",
            "ietf.org",
            # Non-signed domains
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
    def get_all_domains() -> List[Dict[str, Any]]:
        """Get all available domains with detailed information."""
        return DomainManager.DOMAINS_DATABASE

    @staticmethod
    def get_domains_by_category(category: str) -> List[Dict[str, Any]]:
        """Get domains filtered by category."""
        return [
            d for d in DomainManager.DOMAINS_DATABASE if d.get("category") == category
        ]

    @staticmethod
    def get_categories() -> List[str]:
        """Get all available domain categories."""
        categories = set(d["category"] for d in DomainManager.DOMAINS_DATABASE)
        return sorted(list(categories))

import asyncio
import concurrent.futures
from pathlib import Path
import time
from typing import List, Optional, Dict, Any

from src.modules.subdomain_enumerator import SubdomainEnumerator
from src.modules.port_scanner import PortScanner
from src.modules.vulnerability_scanner import VulnerabilityScanner
from src.modules.tech_fingerprinter import TechnologyFingerprinter
from src.utils.logger import get_logger
from src.utils.rate_limit import RateLimiter

class ZoroEngine:
    def __init__(
        self,
        target: str,
        modules: str | List[str] = "all",  # --> Modules to run (subdomains, ports, fingerprint, vulnerabilities)
        threads: int = 10,  # --> Threads 
        output_dir: str = "zoro_results", # --> Output directory for results
        silent: bool = False # --> Silent mode 
    ):
        # --> Initialize key attributes
        self.target = target
        self.modules = modules
        self.threads = threads
        self.output_dir = Path(output_dir)
        self.silent = silent
        self.logger = get_logger()
        self.results: Dict[str, Any] = {}
        self.rate_limiter = RateLimiter()
        
        # --> Initialize module instances
        self.subdomain_enum = SubdomainEnumerator(self.target, self.rate_limiter)
        self.port_scanner = PortScanner(self.rate_limiter)
        self.vuln_scanner = VulnerabilityScanner(self.rate_limiter)
        self.tech_fingerprinter = TechnologyFingerprinter(self.rate_limiter)

    async def initialize(self):
        self.logger.info("Initializing Zoro Engine...")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # --> Load configurations and validate modules
        await self._load_config()
        await self._validate_modules()

    async def run(self):
        start_time = time.time()
        self.logger.info(f"Starting reconnaissance against {self.target}")

        try:
            # --> Phase 1: Subdomain Enumeration
            if self._should_run_module("subdomains"):
                self.results["subdomains"] = await self.subdomain_enum.run()

            # --> Phase 2: Concurrent Port Scanning
            if self._should_run_module("ports"):
                targets = self.results.get("subdomains", [self.target])
                self.results["ports"] = await self.port_scanner.scan_multiple(targets)

            # --> Phase 3: Technology Fingerprinting
            if self._should_run_module("fingerprint"):
                self.results["technologies"] = await self.tech_fingerprinter.analyze(
                    self.target,
                    self.results.get("ports", {})
                )

            # --> Phase 4: Vulnerability Scanning
            if self._should_run_module("vulnerabilities"):
                self.results["vulnerabilities"] = await self.vuln_scanner.scan(
                    self.target,
                    self.results
                )

            # --> Generate Reports
            await self._generate_reports()

        except Exception as e:
            self.logger.error(f"Error during reconnaissance: {str(e)}")
            raise

        finally:
            duration = time.time() - start_time
            self.logger.info(f"Reconnaissance completed in {duration:.2f} seconds")

    async def _load_config(self):
        """Load and validate configuration files"""
        # Configuration loading logic here
        pass

    async def _validate_modules(self):
        """Validate requested modules against available modules"""
        available_modules = {"subdomains", "ports", "fingerprint", "vulnerabilities"}
        
        if isinstance(self.modules, str) and self.modules.lower() == "all":
            self.modules = list(available_modules)
        else:
            invalid_modules = set(self.modules) - available_modules
            if invalid_modules:
                raise ValueError(f"Invalid modules requested: {invalid_modules}")

    def _should_run_module(self, module: str) -> bool:
        """Check if a module should be executed"""
        return module in self.modules if isinstance(self.modules, list) else True

    async def _generate_reports(self):
        """Generate reports in all configured formats"""
        # Report generation logic here
        pass
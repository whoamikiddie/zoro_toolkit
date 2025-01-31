#!/usr/bin/env python3

import argparse
import asyncio
import sys
from src.core.engine import ZoroEngine
from src.utils.banner import print_banner
from src.utils.logger import setup_logger

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Zoro Toolkit - Advanced Security Reconnaissance Framework"
    )
    parser.add_argument("-t", "--target", required=True, help="Target domain/IP")
    parser.add_argument(
        "-m", 
        "--modules", 
        help="Comma-separated list of modules to run",
        default="all"
    )
    parser.add_argument(
        "--threads", 
        type=int, 
        default=10,
        help="Number of concurrent threads"
    )
    parser.add_argument(
        "-o", 
        "--output", 
        default="zoro_results",
        help="Output directory for results"
    )
    parser.add_argument(
        "--silent", 
        action="store_true",
        help="Silent mode - minimal output"
    )
    return parser.parse_args()

async def main():
    args = parse_arguments()
    
    if not args.silent:
        print_banner()
    
    logger = setup_logger(args.silent)
    logger.info("Initializing Zoro Toolkit...")

    try:
        engine = ZoroEngine(
            target=args.target,
            modules=args.modules.split(",") if args.modules != "all" else "all",
            threads=args.threads,
            output_dir=args.output,
            silent=args.silent
        )
        
        await engine.initialize()
        await engine.run()
        
    except KeyboardInterrupt:
        logger.warning("\nReceived interrupt signal. Shutting down gracefully...")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Critical error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
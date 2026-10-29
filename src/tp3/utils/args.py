import argparse
from dataclasses import dataclass

parser = argparse.ArgumentParser("tp3")

parser.add_argument("--target", "-t", help="Target base url", type=str, default="http://127.0.0.1:8080")
parser.add_argument("--verbose", "-v", help="Enable verbose", action="store_true")

args, _ = parser.parse_known_args()


@dataclass(frozen=True)
class Args:
    """
    Parsed command line arguments.
    """

    target: str = args.target.rstrip("/")
    """Base url of the target, without trailing slash"""

    verbose: bool = args.verbose
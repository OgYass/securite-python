import argparse
from dataclasses import dataclass

parser = argparse.ArgumentParser("PySec")

parser.add_argument("--pcap", "-p", help="The pcap file you wish to input", type=str)
parser.add_argument("--iface", "-i", help="The interface you wish to listen to", type=str)
parser.add_argument("--out", "-o", help="File containing the report (json format)", type=str)
parser.add_argument("--verbose", "-v", help="Enable verbose", action="store_true")


args = parser.parse_args()


@dataclass(frozen=True)
class Args:
    """
    Parsed and validated command line arguments.
    """

    pcap_file: str | None = args.pcap or None
    """Path of the pcap file to analyse, ``None`` for a live capture."""

    iface: str | None = args.pcap
    """Interface to listen to, ``None`` for default."""

    report_path: str | None = args.out
    """"Path for the report json, if None we don't need to generate one"""

    verbose: bool = args.verbose or False

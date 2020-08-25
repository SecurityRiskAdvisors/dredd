from dredd.backends import DreddSuricata
from dredd.utils import json_print
import click
import sys


@click.command()
@click.option(
    "-r", "--rules", help="directory of rules", required=True,
)
@click.option("-p", "--pcaps", help="directory of PCAPs", required=True)
@click.option(
    "-m", "--merge", help="evaluate rules against merged archives vs individually", is_flag=True, default=False
)
def suricata(rules: str, pcaps: str, merge: bool):
    dredd_suricata = DreddSuricata(rule_directory=rules, archive_directory=pcaps)
    res = dredd_suricata.evaluate(merged=merge)

    json_print(res)

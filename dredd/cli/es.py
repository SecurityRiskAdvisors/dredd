from dredd.backends import DreddES
from dredd.utils import json_print
import click
import sys


@click.command()
@click.option(
    "-r", "--rules", help="directory of rules", required=True,
)
@click.option(
    "-f",
    "--format",
    "rule_format",
    type=click.Choice(["custom", "sigma"], case_sensitive=False),
    default="sigma",
    help="rule format (default=sigma)",
)
@click.option("-a", "--archives", help="directory of Mordor archives", required=True)
@click.option(
    "-m", "--merge", help="evaluate rules against merged archives vs individually", is_flag=True, default=False
)  # needs to be the inverse if intent is default = True
@click.option(
    "-i", "--ignore-exit-code", "ignore", help="ignore the exit code and exit 0", is_flag=True, default=False,
)
def es(rules: str, rule_format: str, archives: str, merge: bool, ignore: bool):
    dredd_es = DreddES(rule_directory=rules, archive_directory=archives)
    custom = True if rule_format == "custom" else False
    res, exitcode = dredd_es.evaluate(custom_rules=custom, merge_logs=merge)

    json_print(res)

    if not ignore:
        sys.exit(exitcode)
    else:
        sys.exit(0)

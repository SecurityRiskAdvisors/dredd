from .es import es
from .suricata import suricata
import click

# TODO: make --ignore a gloval option


@click.group()
def cli():
    pass


cli.add_command(es)
cli.add_command(suricata)

from dredd.utils import glob_directory
from yaml import safe_load_all

"""
Cutstom rules format

    Required fields:
    - name (string)
    - backend (string)
    - rule (string)

    Optional fields
    - metadata (dict)

Splunk example
    ---
    name: Rule name
    backend: splunk
    metadata:
      foo: bar
    rule: |
      (index="windows" ParentImage="*\\winword.exe" Image="*\\cmd.exe")

The purpose of this rule format is to allow loading of platform specific rules
"""


class PlatformRule:
    # TODO: schema validation
    def __init__(self, backend: str, name: str, rule: str, metadata: dict = None):
        self.backend = backend
        self.name = name
        self.rule = rule
        self.metadata = metadata

    def __repr__(self):
        return "<{} ({})>".format(self.__class__.__name__, self.name)


class CustomRulesLoader:
    @staticmethod
    def from_file(path: str) -> list:
        """loads a custom rule(s) from a file"""
        with open(path) as f:
            yamlstr = f.read()

        rules = safe_load_all(yamlstr)

        return [PlatformRule(**rule) for rule in rules]

    @staticmethod
    def from_directory(directory: str) -> list:
        """loads custom rules from a directory of files (only reads .yaml/.yml files)"""
        yamlfiles = glob_directory(directory=directory, extensions=["yaml", "yml"])
        allrules = []

        [allrules.extend(CustomRulesLoader.from_file(path=yamlfile)) for yamlfile in yamlfiles]

        return allrules

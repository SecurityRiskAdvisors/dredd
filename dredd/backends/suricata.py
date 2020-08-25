from .base import DreddBackend
from dredd.utils import glob_directory
import tempfile
import tarfile
import json
import os


class ExecRunException(Exception):
    """raised when Docker exec command exits with non-zero exit code"""

    pass


class DreddSuricata(DreddBackend):
    def __init__(self, rule_directory: str, archive_directory: str, image: str = "2xxesra/suricata"):
        super().__init__(rule_directory=rule_directory, archive_directory=archive_directory, image=image)
        self.mergedrulefile = ""
        self.ct_mounts = []

        self.merge_rules()

    def merge_rules(self):
        """recursively get all .rule/.rules files in the rule directory then merge them into one file"""
        rule_files = glob_directory(directory=self.rule_directory, extensions=["rule", "rules"])
        _, tmpf = tempfile.mkstemp(suffix=".rules", dir=self.rule_directory)
        with open(tmpf, "w") as mergedfile:
            for rule_file in rule_files:
                with open(rule_file) as f:
                    mergedfile.write(f.read())
                    mergedfile.write("\n")

        self.mergedrulefile = tmpf

    def evaluate(self, merged: bool = True):
        """
        Evaluate the rules against the datasets
        :param merged: true/false whether to ingest all logs into the same index or use one index per log set
        :return: the results dict
        """
        if merged:
            pcap_files = [self.archive_directory]
        else:
            pcap_files = glob_directory(directory=self.archive_directory, extensions=["pcap", "cap"])

        results = {}
        for pcap_file in pcap_files:
            # NOTE: will not work with tmpfs
            volumes = {
                self.mergedrulefile: {"bind": "/var/lib/suricata/rules/suricata.rules", "mode": "ro"},
                os.path.abspath(pcap_file): {"bind": "/opt/pcaps", "mode": "ro"},
            }
            self.launch(volumes=volumes, tty=True)
            exitcode, _ = self.container.exec_run(cmd="suricata -k none -r /opt/pcaps", workdir="/opt")
            if exitcode != 0:
                raise ExecRunException(f"command exited with {exitcode}")

            # pull back eve.json (is tar'd beforehand) and format as list of JSON
            bits, stats = self.container.get_archive("/opt/eve.json")
            eve_json = eve_to_json(eve=bits_to_eve(bits=bits))

            # check for alerts
            res = summarize_eve_results(results=eve_json)
            if merged:
                results["all"] = res
            else:
                results[pcap_file] = res

            # kill container
            self.container.kill()

        # delete merged rules
        os.remove(self.mergedrulefile)
        return results


def bits_to_eve(bits) -> list:
    """
    convert the bits from the Docker client get_archive to a readable format
    :param bits: file bits
    :return: list of lines from file. each line is a JSON object as a string
    """

    # write bits to tempfile
    _, tmpf = tempfile.mkstemp()
    with open(tmpf, "wb") as f:
        for chunk in bits:
            f.write(chunk)

    # untar tempfile and extract eve.json
    tarf = tarfile.open(tmpf)
    member = tarf.getmember("eve.json")
    memberf = tarf.extractfile(member)
    os.remove(tmpf)

    # convert to list of JSON results
    eve = memberf.read().decode().split("\n")

    return eve


def eve_to_json(eve: list) -> list:
    """
    convert a list of  JSON strings to a list of dicts
    input is meant to be from bits_to_eve
    :param eve: list of JSON strings
    :return: list of dicts
    """
    eve_json = []
    for eve_line in eve:
        try:
            eve_json.append(json.loads(eve_line))
        except json.decoder.JSONDecodeError:
            pass

    return eve_json


def summarize_eve_results(results: list) -> dict:
    """
    given an eve results list, summarize the outcomes to provide a count of hits for each rules
    :param results: eve dict list
    :return: dict where key is the rule name and value is the count of hits
    """
    res = {}
    for entry in results:
        if entry["event_type"] == "alert":
            signature = entry["alert"]["signature"]
            if signature in res:
                res[signature] += 1
            else:
                res[signature] = 1

    return res

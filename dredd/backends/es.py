from dredd.rules import DreddESSigma, CustomRulesLoader
from dredd.utils import glob_directory
from .base import DreddBackend
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
import tarfile
import json


class DreddES(DreddBackend):
    def __init__(self, rule_directory: str, archive_directory: str):
        super().__init__(
            rule_directory=rule_directory,
            archive_directory=archive_directory,
            image="elasticsearch:7.6.0",
            env={"discovery.type": "single-node"},
        )
        self.launch()
        self._wait_for_es()
        self.backend = Elasticsearch(hosts=["127.0.0.1:9200"])  # make the host/port configureable?
        self.backend.indices.create(self.index)

    def _wait_for_es(self):
        """loop over connecting to ES until it responds
           this is used after launching the container but before log ingestion to ensure connectivity"""
        while True:
            try:
                Elasticsearch(hosts=["127.0.0.1:9200"]).cluster.health()
            except Exception:
                continue
            else:
                break

    def evaluate(self, custom_rules: bool = False, merge_logs: bool = True, exitcheck: int = 0) -> tuple:
        """
        Evaluate the rules against the datasets
        :param custom_rules: true/false whether using custom rules (true) or Sigma (false)
        :param merge_logs: true/false whether to ingest all logs into the same index or use one index per log set
        :param exitcheck: exit code criteria; 0 for exit 1 on no hits, 1 for exit 1 on any hits
        :return: tuple of the results dict and exit code
        """

        # ES index names are a bit restrictive so rather than convert the archive name to a suitable format,
        #   just store the index <-> archive relationship
        index_map = {}

        # load data into ES
        indices = []
        index_ct = 1
        mordor_archives = glob_directory(directory=self.archive_directory, extensions=["tar.gz"])
        if merge_logs:
            for mordor_archive in mordor_archives:
                self.ingest(archive=mordor_archive)
            indices.append(self.index)
            index_map[self.index] = "all"
        else:
            for mordor_archive in mordor_archives:
                index = f"{self.index}{index_ct}"
                self.ingest(archive=mordor_archive, index=index)
                indices.append(index)
                index_ct += 1
                index_map[index] = mordor_archive
        # sometimes need to refresh index after ingestion
        #   https://elasticsearch-py.readthedocs.io/en/master/api.html#elasticsearch.client.IndicesClient.refresh
        #   https://www.elastic.co/guide/en/elasticsearch/reference/master/indices-refresh.html
        self.backend.indices.refresh("")

        # result dict
        #   skipped = rule doesnt support backend (e.g. supplying a Splunk rule to ES)
        #   unsupported = Sigma rule uses feature not available in backend (e.g. using "near" with ES)
        results = {"skipped": [], "unsupported": []}

        # load rules
        rules = []
        # TODO: should standardize on file name vs rule name in output
        #   Dredd uses path for Sigma rules but name for custom rules
        #   however, Sigma only provides one name for all queries whereas custom rules have one name per query
        if custom_rules:
            for rule in CustomRulesLoader.from_directory(directory=self.rule_directory):
                if rule.backend == "elasticsearch":
                    rules.append((rule.name, [rule.rule]))
                else:
                    results["skipped"].append(rule.name)
        else:
            for sigma in glob_directory(directory=self.rule_directory, extensions=["yaml", "yml"]):
                try:
                    rule = DreddESSigma.sigma_to_query(sigma)
                    rules.append((sigma, rule))
                except NotImplementedError:
                    results["unsupported"].append(sigma)

        # run queries
        exitres = 0
        for index in indices:
            result = {"results": {}, "errors": []}
            for rule in rules:
                q = 0
                for query in rule[1]:
                    # each Sigma rule can contain multiple "detections" (queries).
                    #   Example: https://github.com/Neo23x0/sigma/blob/master/rules/windows/builtin/win_invoke_obfuscation_obfuscated_iex_services.yml
                    # the qname gives an indication as to which detection had the result
                    #   ex: "win_rare_service_installs.yml[0] : 1" means the first detection in the Sigma rule had a hit
                    qname = f"{rule[0]}[{q}]"
                    try:
                        hits = self.search(query=query, index=index)
                        # exit checks
                        #   if 0 -> check if any results are 0 and return 1 if so
                        #   if 1 -> check if any results are >0 and return 1 if so
                        if exitcheck == 0 and hits == 0:
                            exitres = 1
                        if exitcheck == 1 and hits > 0:
                            exitres = 1
                        result["results"][qname] = hits
                    except:
                        result["errors"].append(qname)
                    q += 1
            archive = index_map[index]
            results[archive] = result.copy()

        # cleanup
        self.kill()

        # returns the dict of results + the exit code
        return results, exitres

    def ingest(self, archive: str, index: str = None):
        """
        Load a log archive into the backend
        :param archive: the tar'd archive file
        :param index: the ES index to load the data into; defaults to Backend's index property
        """
        index = self.index if index is None else index
        tarf = tarfile.open(archive)
        for member in tarf.getmembers():
            if member.isfile():
                logfile = f"{archive}/{member.name}"
                memberf = tarf.extractfile(member)

                # TODO: handle/log errors
                bulk(
                    self.backend, normalize(mordor_file=memberf, logfile=logfile, index=index), raise_on_error=False,
                )

        tarf.close()

    def reset_index(self, index: str = None):
        """
        deletes then recreates an existing index
        :param index: the ES index to reset; defaults to Backend's index property
        """
        index = self.index if not "index" else index
        if self.backend.indices.exists(index):
            self.backend.indices.delete(index)
            self.backend.indices.create(index)

    def search(self, query, index: str) -> int:
        """
        perform a search against the Backend
        :param query: the query - as string or dict
        :param index: the ES index to search; defaults to Backend's index property
        :return: number of hits for the query
        """
        index = self.index if not "index" else index
        res = self.backend.search(index=index, body=query)
        # maybe include some identifiers for document hits?
        #   -> ES only returns 10 results by default
        #       -> how to handle high # of hits
        return res["hits"]["total"]["value"]


def normalize(mordor_file: str, logfile: str, index: str):
    # see: https://github.com/hunters-forge/mordor/blob/master/scripts/es-import.py
    for line in mordor_file:
        source = json.loads(line)
        source["log"] = {"file": {"name": logfile}}
        source.setdefault("winlog", dict())

        if "EventID" in source:
            source["winlog"]["event_id"] = source["EventID"]
            del source["EventID"]

            try:
                del source["type"]
            except KeyError:
                pass

            try:
                del source["host"]
            except KeyError:
                pass

            source["winlog"]["event_data"] = {
                k: v
                for k, v in source.items()
                if k not in ("winlog", "log", "Channel", "Hostname", "@timestamp", "@version",)
            }

            for k in source["winlog"]["event_data"].keys():
                del source[k]

            try:
                source["winlog"]["computer_name"] = source["Hostname"]
                del source["Hostname"]
            except KeyError:
                pass

            try:
                source["winlog"]["channel"] = source["Channel"]
                del source["Channel"]
            except KeyError:
                pass

        if "event_data" in source:
            source["winlog"]["event_data"] = source["event_data"]
            del source["event_data"]

        if "log_name" in source:
            source["winlog"]["channel"] = source["log_name"]
            del source["log_name"]

        try:
            if source["winlog"]["channel"] == "security":
                source["winlog"]["channel"] = "Security"
        except KeyError:
            pass

        if "event_id" in source:
            source["winlog"]["event_id"] = source["event_id"]
            del source["event_id"]

        source.setdefault("event", dict())["code"] = source["winlog"]["event_id"]

        yield {"_index": index, "_source": source}

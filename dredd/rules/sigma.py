from sigma.parser.collection import SigmaCollectionParser
from sigma.configuration import SigmaConfigurationChain
import sigma.backends.discovery as backends
from sigma.config.collection import SigmaConfigurationManager
import json


class SigmaCommon:
    def __init__(self, backend: str, config: str):
        self.backend = backend
        self.config = config

    def sigma_to_query(self, sigma_file: str):
        """convert a Sigma rule file to query using the backend/config properties"""

        # initialize config manager to retrieve config
        scm = SigmaConfigurationManager()
        sigmaconfigs = SigmaConfigurationChain()
        sigmaconfig = scm.get(self.config)
        sigmaconfigs.append(sigmaconfig)

        # dynamically grab backend and pair to config
        backend_class = backends.getBackend(self.backend)
        backend = backend_class(sigmaconfigs)

        with open(sigma_file) as f:
            parser = SigmaCollectionParser(f, sigmaconfigs)
            parser.generate(backend)

        return json.loads(backend.finalize())


class DreddESSigma:
    @staticmethod
    def sigma_to_query(sigma_file: str, backend: str = "es-dsl", config: str = "winlogbeat") -> list:
        """
        Convert a Sigma rule file to an Elasticserch query.
        Default behavior is to generate an ES DSL query with a Winlogbeat config
        :param sigma_file: path to the Sigma file
        :param backend: Sigma backend; defaults to "es-dsl"
        :param config: Sigma backend config; defaults to "winlogbeat"
        :return: list of queries (as dicts)
        """

        queries = SigmaCommon(backend=backend, config=config).sigma_to_query(sigma_file=sigma_file)
        # Sigma allows rules to contain multiple detections, so converting the Sigma rule to the backend will return
        # either a single query as a dict or multiple queries in a list
        # this function standardizes on returning a list
        queries = [queries] if type(queries) == dict else queries
        return queries

from .docker import docker_client


class DreddBackend:
    def __init__(self, rule_directory: str, archive_directory: str, image: str = None, env: dict = None):
        self.rule_directory = rule_directory
        self.archive_directory = archive_directory
        self.image = image
        self.env = env
        self.index = "dredd"

        self.container = None  # Docker container object

    def launch(self, pull: bool = False, **kwargs):
        """
        launch container based on Backend's image property
        sets the container object to self.container
        :param pull: pull the image before running
        :param kwargs: kwargs for docker.containers.run
        """
        if pull:
            docker_client.images.pull(self.image)  # if exists, will just return image

        self.container = docker_client.containers.run(
            image=self.image, detach=True, environment=self.env, network_mode="host", remove=True, **kwargs
        )

    def kill(self):
        """kill Backend's container"""
        self.container.kill()

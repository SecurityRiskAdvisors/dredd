import glob
import json


def _glob_ext(directory: str, extension: str) -> list:
    """recursively get all files of a certain extension in a directory"""
    return glob.glob(f"{directory}/**/*.{extension}", recursive=True)


def glob_directory(directory: str, extensions: list) -> list:
    """recursively get all files of a certain extension in a directory"""
    files = []
    for extension in extensions:
        files.extend(_glob_ext(directory=directory, extension=extension))

    return files


def json_print(toprint: dict, **kwargs):
    """convert a dict to string then print formatted"""
    print(json.dumps(toprint, indent=4, sort_keys=True, **kwargs))

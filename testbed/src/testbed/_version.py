from pathlib import Path


def _read_version() -> str:
    version_file = Path(__file__).parent.parent.parent.parent / "VERSION"
    fields = {}
    for line in version_file.read_text().splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            fields[k.strip()] = v.strip()
    return "{}.{}.{}".format(fields["VERSION_MAJOR"], fields["VERSION_MINOR"], fields["PATCHLEVEL"])


__version__ = _read_version()

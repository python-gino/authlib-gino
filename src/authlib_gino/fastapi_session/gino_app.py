from importlib.metadata import entry_points


def load_entry_point(name, default_factory=None):
    for ep in entry_points().get("gino.app", []):
        if ep.name == name:
            return ep.load()
    return default_factory()

try:
    from werkzeug.utils import cached_property
except ImportError:
    import sys

    class _WerkzeugUtils:
        def cached_property(self, m):
            return m

    sys.modules.setdefault("werkzeug.utils", _WerkzeugUtils())

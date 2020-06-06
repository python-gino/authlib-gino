from authlib.common.security import generate_token


def id_generator(prefix, length=30):
    def gen():
        return f"{prefix}:{generate_token(length)}"

    gen.__name__ = f"generate_{prefix}_id_{length}"
    return gen

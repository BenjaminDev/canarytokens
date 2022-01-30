class RecreatingDBException(Exception): pass

class NoCanarytokenFound(Exception): pass

class NoCanarytokenPresent(Exception): pass

class NoUser(Exception): pass

class UnknownAttribute(Exception):
    # This does not seem like a sound way to handle
    # unexpected kwargs. We can make it a dataclass or
    # pydantic models and get nice error handling.
    pass

class DuplicateChannel(Exception): pass

class InvalidChannel(Exception): pass
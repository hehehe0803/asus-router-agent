class RouterError(Exception):
    """Only fixed, application-authored messages may be exposed to callers."""
    def __init__(self, code: str, public_message: str, exit_code: int = 1):
        super().__init__(public_message)
        self.code = code
        self.public_message = public_message
        self.exit_code = exit_code

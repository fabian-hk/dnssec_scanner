from dnssec_scanner.messages import Message


class TestMessage(Message):
    def __init__(
            self,
            zone_name: str,
            owner_name: str,
            rdtype: str,
            type_id: str,
            message: str,
            validator: str,
            validator_id: str,
    ):
        super(TestMessage, self).__init__(
            zone_name, owner_name, rdtype, type_id=type_id
        )
        self.message = message
        self.validator = validator
        self.validator_id = validator_id

from dataclasses import dataclass

@dataclass
class Host:
    hostname: str = None
    ip: str = None
    delay: float = None
    timeout: bool = False

    @property
    def delay_ms(self):
        return f'{self.delay:.2f} ms'

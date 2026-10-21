from dataclasses import dataclass, field


@dataclass
class Finding:
    id: str
    level: str
    category: str
    title: str
    impact: str
    pid: str
    process: str
    time: str
    upgrade: str
    event: str
    evidence: list[str] = field(default_factory=list)
    source: str = "logcat"
    cause: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "level": self.level,
            "category": self.category,
            "title": self.title,
            "impact": self.impact,
            "pid": self.pid,
            "process": self.process,
            "time": self.time,
            "upgrade": self.upgrade,
            "event": self.event,
            "evidence": self.evidence,
            "source": self.source,
            "cause": self.cause,
        }

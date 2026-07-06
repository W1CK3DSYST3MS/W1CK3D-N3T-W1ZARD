from dataclasses import dataclass, field
from typing import Optional

# W1CK3D SYST3MS severity ramp (red -> orange -> gold -> blue -> grey),
# tuned to read on the app's near-black surfaces. Shared by the GUI treeview
# tags and the exported HTML report.
SEVERITY_COLORS = {
    'critical': '#e51f1f',
    'high':     '#ee5a04',
    'medium':   '#c5a45a',
    'low':      '#147ec2',
    'info':     '#8b93a1',
}
SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    description: str
    technical: str = ''
    device_mac: Optional[str] = None
    recommendation: str = ''
    evidence: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            'severity': self.severity,
            'category': self.category,
            'title': self.title,
            'description': self.description,
            'technical': self.technical,
            'device_mac': self.device_mac,
            'recommendation': self.recommendation,
            'evidence': self.evidence,
        }


class Analyzer:
    name = 'base'

    def process_packet(self, pkt):
        pass

    def finalize(self, context=None):
        pass

    def results(self):
        return {}

"""Default SecureForge integration registry."""

from **future** import annotations

from secureforge.integrations.api import GenericAPIIntegration
from secureforge.integrations.container import GenericContainerIntegration
from secureforge.integrations.dast import GenericDASTIntegration
from secureforge.integrations.iac import GenericIACIntegration
from secureforge.integrations.manual import ManualEvidenceIntegration
from secureforge.integrations.nessus import GenericNessusIntegration
from secureforge.integrations.nmap import GenericNmapIntegration
from secureforge.integrations.registry import IntegrationRegistry
from secureforge.integrations.sast import GenericSASTIntegration
from secureforge.integrations.sca import GenericSCAIntegration
from secureforge.integrations.secrets import GenericSecretsIntegration

def build_default_registry() -> IntegrationRegistry:
"""Build a registry containing all built-in integrations."""
registry = IntegrationRegistry()

```
registry.register_many(
    [
        GenericSASTIntegration(),
        GenericSCAIntegration(),
        GenericSecretsIntegration(),
        GenericAPIIntegration(),
        GenericDASTIntegration(),
        GenericContainerIntegration(),
        GenericIACIntegration(),
        GenericNessusIntegration(),
        GenericNmapIntegration(),
        ManualEvidenceIntegration(),
    ]
)

return registry
```

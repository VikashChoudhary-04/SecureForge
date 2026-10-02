"""Release-gate engine for SecureForge."""
from secureforge.core.release_gate.models import ReleaseGateDecision
class ReleaseGateEngine:
    def evaluate(self,*,findings=None,risk,policy,regression_gate=None,validation_gate=None,regression=None):
        regression=regression_gate if regression_gate is not None else regression
        if validation_gate is not None:
            if getattr(validation_gate,"blocked",False):
                return ReleaseGateDecision(status="blocked",reason=getattr(validation_gate,"reason","Validation blocked the release."),release_allowed=False)
            status=getattr(validation_gate,"status","");status=getattr(status,"value",status)
            if status in {"review","error"}:return ReleaseGateDecision(status="review",reason=getattr(validation_gate,"reason","Validation requires review."),release_allowed=True)
        if regression is not None:
            if getattr(regression,"blocked",False):
                return ReleaseGateDecision(status="blocked",reason="Regression gate blocked the release: "+", ".join(getattr(regression,"failures",())),release_allowed=False)
            status=getattr(regression,"status","");status=getattr(status,"value",status)
            if status in {"review","error"}:return ReleaseGateDecision(status="review",reason=getattr(regression,"reason","Regression requires review."),release_allowed=True)
        if not policy.allowed:return ReleaseGateDecision(status="blocked",reason="Release blocked by security policy: "+getattr(policy,"reason",""),release_allowed=False)
        if getattr(risk,"blocked",False):return ReleaseGateDecision(status="blocked",reason="Release blocked because the calculated security risk exceeds the configured threshold.",release_allowed=False)
        return ReleaseGateDecision(status="passed",reason="All configured release-gate controls passed.",release_allowed=True)

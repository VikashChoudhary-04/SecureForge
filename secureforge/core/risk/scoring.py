"""Transparent contextual risk scoring rules for SecureForge."""
from __future__ import annotations
from secureforge.core.findings import Finding, Severity
from .models import AssetImportance, Environment, RiskContext

class RiskScorer:
    SEVERITY_SCORES={Severity.CRITICAL:90.0,Severity.HIGH:70.0,Severity.MEDIUM:50.0,Severity.LOW:25.0,Severity.INFO:5.0}
    ASSET_ADJUSTMENTS={AssetImportance.CRITICAL:6.0,AssetImportance.HIGH:4.0,AssetImportance.MEDIUM:0.0,AssetImportance.LOW:-5.0}
    ENVIRONMENT_ADJUSTMENTS={Environment.PRODUCTION:5.0,Environment.STAGING:2.0,Environment.TEST:0.0,Environment.DEVELOPMENT:-5.0,Environment.LAB:-10.0,Environment.UNKNOWN:0.0}
    def base_score(self,finding:Finding)->float:return self.SEVERITY_SCORES[finding.severity]
    def calculate(self,finding,context):
        score=self.base_score(finding); factors=[]
        score,f=self.apply_asset_importance(score,context.asset_importance)
        if f:factors.append(f)
        score,f=self.apply_internet_exposure(score,context.internet_exposed)
        if f:factors.append(f)
        score,f=self.apply_authentication(score,context.authentication_required)
        if f:factors.append(f)
        score,f=self.apply_sensitive_data(score,context.sensitive_data)
        if f:factors.append(f)
        score,f=self.apply_exploit_evidence(score,context.exploit_evidence)
        if f:factors.append(f)
        score=self.apply_environment(score,context.environment)
        return self.clamp(score),factors
    def apply_asset_importance(self,score,importance):
        adjustment=self.ASSET_ADJUSTMENTS[importance]
        if adjustment==0:return score,None
        label="critical asset" if importance==AssetImportance.CRITICAL else f"{importance.value}-importance asset"
        return score+adjustment,label
    @staticmethod
    def apply_internet_exposure(score,internet_exposed):
        return (score+10.0,"internet-exposed asset") if internet_exposed else (score,None)
    @staticmethod
    def apply_authentication(score,authentication_required):
        return (score+10.0,"no authentication required") if not authentication_required else (score,None)
    @staticmethod
    def apply_sensitive_data(score,sensitive_data):
        return (score+10.0,"sensitive data affected") if sensitive_data else (score,None)
    @staticmethod
    def apply_exploit_evidence(score,exploit_evidence):
        return (score+10.0,"exploit evidence available") if exploit_evidence else (score,None)
    def apply_environment(self,score,environment):return score+self.ENVIRONMENT_ADJUSTMENTS[environment]
    @staticmethod
    def clamp(score):return max(0.0,min(100.0,score))

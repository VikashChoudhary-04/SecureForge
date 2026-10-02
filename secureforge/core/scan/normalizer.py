"""Normalize scan tool results into SecureForge findings."""
from __future__ import annotations
from datetime import datetime,timezone
from secureforge.core.normalization import NormalizationPipeline
from secureforge.core.normalization.models import NormalizationResult,RawEvidence
class ScanResultNormalizer:
    def __init__(self,pipeline=None,finding_factory=None):
        self.pipeline=pipeline or NormalizationPipeline()
        if finding_factory is None:
            from secureforge.core.findings.factory import FindingFactory
            finding_factory=FindingFactory()
        self.finding_factory=finding_factory
    def build_evidence(self,result,*,target=None,application="unknown"):
        metadata=dict(result.metadata);metadata.setdefault("application",application)
        return RawEvidence(source=result.integration,source_version=metadata.get("source_version"),target=target,
                           collected_at=result.completed_at or result.started_at or datetime.now(timezone.utc),
                           raw_data={"tool_name":result.tool_name,"integration":result.integration,"status":result.status.value,
                                     "command":result.command,"stdout":result.stdout,"stderr":result.stderr,"exit_code":result.exit_code},
                           metadata=metadata)
    def normalize_result(self,result,*,target=None,application="unknown"):
        evidence=self.build_evidence(result,target=target,application=application)
        try:
            raw=self.pipeline.normalize(evidence)
            if isinstance(raw,NormalizationResult):return raw
            return NormalizationResult(source=getattr(raw,"source",result.integration),findings=list(getattr(raw,"findings",[])),
                                       evidence=list(getattr(raw,"evidence",[])),warnings=list(getattr(raw,"warnings",[])),
                                       errors=list(getattr(raw,"errors",[])),success=bool(getattr(raw,"success",True)))
        except (AttributeError,TypeError,ValueError) as exc:
            return NormalizationResult(source=result.integration,evidence=[evidence],success=False,errors=[f"Normalization failed: {exc}"])
    normalize=normalize_result
    def normalize_results(self,results,*,target=None,application="unknown"):
        return [self.normalize_result(r,target=target,application=application) for r in results]
    def findings_from_result(self,result,*,target=None,application="unknown"):
        normalized=self.normalize_result(result,target=target,application=application)
        if not normalized.success:return normalized,[]
        return normalized,self.finding_factory.create_many(normalized.findings)
    def findings_from_results(self,results,*,target=None,application="unknown"):
        normalized=[];findings=[]
        for result in results:
            if result.succeeded:
                item,created=self.findings_from_result(result,target=target,application=application)
                normalized.append(item);findings.extend(created)
        return normalized,findings

"""Pydantic data models for fully-ingested advisory records.

These models represent the *deep extraction* schema used when a raw advisory
document (HTML page, PDF, or text file) is processed by ``ingest.py`` and then
structured by the AI extraction step in ``extract.py``.

They are intentionally separate from the lightweight signal dicts used by the
``discover → correlate → score`` pipeline, which only need source/guid/title/
summary/link fields.  These models capture the full structured information from
a single advisory document: affected products with version ranges, recommended
actions with role hints, and provenance of the AI extraction.

Key classes:
    AdvisoryRecordMVP — top-level model written to outputs/ingest/<id>/
    ContentModel      — normalized text content + hash + language
    IdentifiersModel  — CVE list
    ProductModel      — vendor/product + models/UDI-DIs
    RecommendedActionModel — one structured remediation step
    SourceExtractionModel  — AI model / run metadata for audit trail
"""
from __future__ import annotations

from typing import List, Optional, Literal
from pydantic import BaseModel, Field


class ContentModel(BaseModel):
    content_type: Literal["html", "pdf", "text"] = "text"
    raw_text: str
    content_hash: str
    language: str = "en"


class IdentifiersModel(BaseModel):
    cves: List[str] = Field(default_factory=list)


class VersionRangeModel(BaseModel):
    raw: str
    normalized: Optional[dict] = None
    applies_to: Optional[str] = None
    confidence: Optional[float] = None


class ComponentModel(BaseModel):
    name: str
    type: Optional[str] = None
    notes: Optional[str] = None


class ProductModel(BaseModel):
    product_name: str
    models: List[str] = Field(default_factory=list)
    device_type: Optional[str] = None
    udi_di: List[str] = Field(default_factory=list)
    part_numbers: List[str] = Field(default_factory=list)
    components: List[ComponentModel] = Field(default_factory=list)


class AffectedProductDefinitionModel(BaseModel):
    vendor: Optional[str] = None
    product_family: Optional[str] = None
    products: List[ProductModel] = Field(default_factory=list)
    affected_versions: List[VersionRangeModel] = Field(default_factory=list)
    fixed_versions: List[VersionRangeModel] = Field(default_factory=list)
    conditions: List[str] = Field(default_factory=list)


class RecommendedActionModel(BaseModel):
    action_id: str
    action_type: str
    summary: str
    details: Optional[str] = None
    role_hints: List[str] = Field(default_factory=list)
    priority: Optional[str] = None
    citations: List[str] = Field(default_factory=list)


class SourceExtractionModel(BaseModel):
    model: str
    run_id: Optional[str] = None
    confidence: Optional[float] = None
    warnings: List[str] = Field(default_factory=list)


class AdvisoryRecordMVP(BaseModel):
    advisory_id: str
    record_version: str = "1.0"

    publisher: str
    publisher_org: Optional[str] = None
    vendor: Optional[str] = None

    title: str
    summary: Optional[str] = None

    published_date: Optional[str] = None  # YYYY-MM-DD best-effort
    retrieved_at: str  # ISO-8601
    source_url: Optional[str] = None

    content: ContentModel
    identifiers: IdentifiersModel = Field(default_factory=IdentifiersModel)
    affected_product_definition: AffectedProductDefinitionModel = Field(default_factory=AffectedProductDefinitionModel)
    recommended_actions: List[RecommendedActionModel] = Field(default_factory=list)

    source_extraction: Optional[SourceExtractionModel] = None

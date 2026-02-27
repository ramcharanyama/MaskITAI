"""
Redaction Orchestrator.
Central controller that coordinates all detection engines,
entity merging, redaction application, verification, and
multi-modal redaction (image, PDF, audio, video).
"""

import time
import os
import tempfile
from typing import List, Dict, Optional, Tuple
import logging

from app.engines.regex_engine import RegexEngine
from app.engines.nlp_engine import NLPEngine
from app.engines.ocr_engine import OCREngine
from app.engines.redaction_engine import RedactionEngine
from app.engines.entity_merger import EntityMerger
from app.engines.verification_engine import VerificationEngine
from app.engines.image_redactor import ImageRedactor
from app.engines.pdf_redactor import PDFRedactor
from app.engines.audio_redactor import AudioRedactor
from app.engines.video_redactor import VideoRedactor
from app.engines.download_manager import DownloadManager
from app.utils.pdf_handler import PDFHandler

logger = logging.getLogger(__name__)

# Severity weights for privacy score calculation
ENTITY_SEVERITY = {
    "SSN": 1.0,
    "CREDIT_CARD": 1.0,
    "AADHAAR": 1.0,
    "PAN": 0.9,
    "DATE_OF_BIRTH": 0.8,
    "PHONE": 0.7,
    "EMAIL": 0.7,
    "IP_ADDRESS": 0.6,
    "ADDRESS": 0.6,
    "LOCATION": 0.5,
    "PERSON_NAME": 0.4,
    "ORGANIZATION": 0.3,
    "DATE": 0.2,
}
DEFAULT_SEVERITY = 0.5


class RedactionOrchestrator:
    """
    Main orchestrator for the PII redaction pipeline.
    Coordinates detection, merging, redaction, verification,
    and multi-modal redaction (image, PDF, audio, video).
    """

    def __init__(self):
        # Core text engines
        self.regex_engine = RegexEngine()
        self.nlp_engine = NLPEngine()
        self.ocr_engine = OCREngine()
        self.redaction_engine = RedactionEngine()
        self.entity_merger = EntityMerger()
        self.pdf_handler = PDFHandler()
        self.verification_engine = VerificationEngine(
            self.regex_engine, self.nlp_engine
        )

        # Multi-modal redactors
        self.image_redactor = ImageRedactor()
        self.pdf_redactor = PDFRedactor()
        self.audio_redactor = AudioRedactor()
        self.video_redactor = VideoRedactor()
        self.download_manager = DownloadManager()

        # Statistics tracking
        self.stats = {
            "total_requests": 0,
            "total_entities_detected": 0,
            "total_texts_processed": 0,
            "total_files_processed": 0,
            "processing_times": [],
            "entity_type_distribution": {},
            "strategy_usage": {},
        }

        # Attempt to load NLP model
        try:
            self.nlp_engine.load()
        except Exception as e:
            logger.warning(f"NLP engine not available: {e}")

        # Attempt to load OCR engine
        try:
            self.ocr_engine.load()
        except Exception as e:
            logger.warning(f"OCR engine not available: {e}")

    # ── PII pipeline callable (for multi-modal modules) ──
    def detect_pii(self, text: str, entity_types: List[str] = None) -> List[Dict]:
        """Run full PII detection pipeline on text. Returns list of entity dicts."""
        regex_entities = self.regex_engine.detect(text, entity_types)
        nlp_entities = []
        if self.nlp_engine.is_available():
            nlp_entities = self.nlp_engine.detect(text, entity_types)
        return self.entity_merger.merge(regex_entities, nlp_entities)

    # ── Text redaction ──
    def redact_text(
        self,
        text: str,
        strategy: str = "mask",
        entity_types: List[str] = None,
        verify: bool = True
    ) -> Dict:
        """
        Full pipeline: detect PII in text, apply redaction, verify output.
        """
        start_time = time.time()

        # Step 1: Detection
        merged_entities = self.detect_pii(text, entity_types)

        # Step 2: Apply redaction
        redacted_text, updated_entities = self.redaction_engine.redact(
            text, merged_entities, strategy
        )

        # Step 3: Verify
        verification = {"passed": True, "residual_entities": [], "scan_count": 0}
        if verify:
            verification = self.verification_engine.verify(redacted_text)

        processing_time = (time.time() - start_time) * 1000

        # Update stats
        self._update_stats(updated_entities, strategy, processing_time)

        entity_stats = self.entity_merger.get_stats(updated_entities)

        privacy_score = self._calculate_privacy_score(
            text, updated_entities, verification["passed"]
        )

        return {
            "original_text": text,
            "redacted_text": redacted_text,
            "entities_found": updated_entities,
            "total_entities": len(updated_entities),
            "processing_time_ms": round(processing_time, 2),
            "strategy_used": strategy,
            "verification_passed": verification["passed"],
            "privacy_score": privacy_score,
            "stats": entity_stats
        }

    # ── File redaction (text/PDF/image — legacy) ──
    def redact_file(
        self,
        file_path: str,
        file_type: str,
        strategy: str = "mask",
        entity_types: List[str] = None
    ) -> Dict:
        """Redact PII from a file (text, PDF, or image)."""
        start_time = time.time()

        if file_type in ("pdf", "application/pdf"):
            text = self.pdf_handler.extract_text(file_path)
        elif file_type in ("image", "image/png", "image/jpeg", "image/jpg"):
            text = self._extract_image_text(file_path)
        else:
            with open(file_path, "r", errors="ignore") as f:
                text = f.read()

        if not text.strip():
            return {
                "filename": os.path.basename(file_path),
                "file_type": file_type,
                "original_size": os.path.getsize(file_path),
                "redacted_text": "",
                "entities_found": [],
                "total_entities": 0,
                "processing_time_ms": 0,
                "strategy_used": strategy,
                "verification_passed": True,
                "stats": {},
                "error": "No text content extracted from file"
            }

        result = self.redact_text(text, strategy, entity_types)
        result["filename"] = os.path.basename(file_path)
        result["file_type"] = file_type
        result["original_size"] = os.path.getsize(file_path)

        self.stats["total_files_processed"] += 1

        return result

    def redact_file_bytes(
        self,
        file_bytes: bytes,
        filename: str,
        file_type: str,
        strategy: str = "mask",
        entity_types: List[str] = None
    ) -> Dict:
        """Redact PII from file bytes (for API uploads)."""
        suffix = os.path.splitext(filename)[1] or ".txt"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(file_bytes)
            tmp_path = tmp.name

        try:
            result = self.redact_file(tmp_path, file_type, strategy, entity_types)
            result["filename"] = filename
        finally:
            os.unlink(tmp_path)

        return result

    # ── Image redaction (Module 1) ──
    def redact_image(self, image_bytes: bytes, filename: str, strategy: str = "mask") -> Dict:
        """Redact PII from image. Returns redacted image bytes + audit."""
        result = self.image_redactor.redact_image(image_bytes, self.detect_pii, strategy)

        # Save for download
        if result.get("redacted_image_bytes"):
            job_id = self.download_manager.save_file(
                file_bytes=result["redacted_image_bytes"],
                original_filename=filename,
                file_format="png",
                content_type="image/png",
                entity_count=result.get("total_entities", 0),
                processing_time_ms=result.get("processing_time_ms", 0),
                audit_log=result.get("audit_log", []),
            )
            result["job_id"] = job_id

        self.stats["total_files_processed"] += 1
        self._update_stats(result.get("entities_found", []), strategy, result.get("processing_time_ms", 0))
        result["privacy_score"] = self._calculate_privacy_score(
            result.get("ocr_text", ""), result.get("entities_found", []) + result.get("audit_log", []), True
        )
        return result

    # ── PDF redaction (Module 2) ──
    def redact_pdf(self, pdf_bytes: bytes, filename: str, strategy: str = "mask") -> Dict:
        """Redact PII from PDF. Returns redacted PDF bytes + audit."""
        result = self.pdf_redactor.redact_pdf(pdf_bytes, self.detect_pii, strategy)

        if result.get("redacted_pdf_bytes"):
            job_id = self.download_manager.save_file(
                file_bytes=result["redacted_pdf_bytes"],
                original_filename=filename,
                file_format="pdf",
                content_type="application/pdf",
                entity_count=result.get("total_entities", 0),
                processing_time_ms=result.get("processing_time_ms", 0),
                audit_log=result.get("per_page_audit", []),
            )
            result["job_id"] = job_id

        self.stats["total_files_processed"] += 1
        self._update_stats(result.get("entities_found", []), strategy, result.get("processing_time_ms", 0))
        result["privacy_score"] = self._calculate_privacy_score(
            result.get("full_text", ""), result.get("entities_found", []), True
        )
        return result

    # ── Audio redaction (Module 3) ──
    def redact_audio(self, audio_bytes: bytes, filename: str, strategy: str = "mask") -> Dict:
        """Redact PII from audio. Returns redacted audio bytes + transcript."""
        result = self.audio_redactor.redact_audio(audio_bytes, filename, self.detect_pii, strategy)

        if result.get("redacted_audio_bytes"):
            fmt = result.get("format", "mp3")
            ct_map = {"mp3": "audio/mpeg", "wav": "audio/wav"}
            job_id = self.download_manager.save_file(
                file_bytes=result["redacted_audio_bytes"],
                original_filename=filename,
                file_format=fmt,
                content_type=ct_map.get(fmt, "audio/mpeg"),
                entity_count=result.get("total_entities", 0),
                processing_time_ms=result.get("processing_time_ms", 0),
                audit_log=result.get("audit_log", []),
            )
            result["job_id"] = job_id

        self.stats["total_files_processed"] += 1
        self._update_stats(result.get("entities_found", []), strategy, result.get("processing_time_ms", 0))
        result["privacy_score"] = self._calculate_privacy_score(
            result.get("original_transcript", ""), result.get("entities_found", []) + result.get("audit_log", []), True
        )
        return result

    # ── Video redaction (Module 4) ──
    def redact_video(self, video_bytes: bytes, filename: str, strategy: str = "mask") -> Dict:
        """Redact PII from video. Returns redacted video bytes + audit."""
        result = self.video_redactor.redact_video(video_bytes, filename, self.detect_pii, strategy)

        if result.get("redacted_video_bytes"):
            job_id = self.download_manager.save_file(
                file_bytes=result["redacted_video_bytes"],
                original_filename=filename,
                file_format="mp4",
                content_type="video/mp4",
                entity_count=result.get("total_visual_redactions", 0) + result.get("total_audio_redactions", 0),
                processing_time_ms=result.get("processing_time_ms", 0),
                audit_log=result.get("visual_audit", []) + result.get("audio_audit", []),
            )
            result["job_id"] = job_id

        self.stats["total_files_processed"] += 1
        all_entities = result.get("visual_audit", []) + result.get("audio_audit", [])
        result["privacy_score"] = self._calculate_privacy_score(
            "", all_entities, True
        )
        return result

    def _extract_image_text(self, image_path: str) -> str:
        """Extract text from image using OCR."""
        if not self.ocr_engine.is_available():
            self.ocr_engine.load()

        if self.ocr_engine.is_available():
            return self.ocr_engine.extract_text(image_path)
        return ""

    def batch_redact(
        self,
        texts: List[str],
        strategy: str = "mask",
        entity_types: List[str] = None
    ) -> Dict:
        """Process multiple texts in batch."""
        results = []
        total_entities = 0
        start_time = time.time()

        for text in texts:
            result = self.redact_text(text, strategy, entity_types, verify=False)
            results.append(result)
            total_entities += result["total_entities"]

        total_time = (time.time() - start_time) * 1000

        return {
            "results": results,
            "total_texts": len(texts),
            "total_entities": total_entities,
            "total_processing_time_ms": round(total_time, 2)
        }

    def get_engine_status(self) -> Dict:
        """Get status of all detection engines."""
        return {
            "regex": True,
            "nlp": self.nlp_engine.is_available(),
            "ocr": self.ocr_engine.is_available(),
            "pdf": self.pdf_handler.is_available(),
            "image_redactor": self.image_redactor.is_available(),
            "audio_redactor": self.audio_redactor.is_available(),
            "video_redactor": self.video_redactor.is_available(),
        }

    def get_stats(self) -> Dict:
        """Get system-wide statistics."""
        avg_time = 0
        if self.stats["processing_times"]:
            avg_time = sum(self.stats["processing_times"]) / len(self.stats["processing_times"])

        return {
            "total_requests": self.stats["total_requests"],
            "total_entities_detected": self.stats["total_entities_detected"],
            "total_texts_processed": self.stats["total_texts_processed"],
            "total_files_processed": self.stats["total_files_processed"],
            "avg_processing_time_ms": round(avg_time, 2),
            "entity_type_distribution": self.stats["entity_type_distribution"],
            "strategy_usage": self.stats["strategy_usage"],
        }

    def _calculate_privacy_score(
        self,
        original_text: str,
        entities: List[Dict],
        verification_passed: bool
    ) -> Dict:
        """
        Calculate a privacy risk score (0–100) AFTER redaction.

        100 = fully private (no PII risk remains)
          0 = high privacy risk

        Components:
          - base score starts at 100 (clean slate)
          - deductions for PII found (weighted by severity)
          - bonus for high-confidence detection
          - penalty if verification failed
        """
        if not entities:
            return {
                "score": 100,
                "grade": "A+",
                "label": "Fully Private",
                "breakdown": {
                    "entities_penalty": 0,
                    "severity_penalty": 0,
                    "confidence_bonus": 0,
                    "verification_bonus": 10,
                    "density_penalty": 0,
                },
            }

        # ── Severity-weighted penalty ──
        total_severity = 0
        confidences = []
        for e in entities:
            etype = e.get("entity_type", "UNKNOWN")
            severity = ENTITY_SEVERITY.get(etype, DEFAULT_SEVERITY)
            total_severity += severity
            conf = e.get("confidence", 0.8)
            if isinstance(conf, (int, float)):
                confidences.append(conf)

        # More entities → bigger deduction, but diminishing returns
        entity_count = len(entities)
        entities_penalty = min(40, entity_count * 3)  # max 40pt loss

        # Severity penalty (weighted average × scaling factor)
        avg_severity = total_severity / max(entity_count, 1)
        severity_penalty = min(25, round(avg_severity * entity_count * 2.5))  # max 25pt

        # Density: PII per 100 chars of original text
        text_len = max(len(original_text), 1)
        density = (entity_count / text_len) * 100
        density_penalty = min(15, round(density * 10))  # max 15pt

        # Confidence bonus: high-confidence detections mean the redactor
        # is sure it caught everything → reward
        avg_conf = sum(confidences) / max(len(confidences), 1)
        confidence_bonus = round(avg_conf * 10)  # up to +10

        # Verification bonus
        verification_bonus = 10 if verification_passed else -5

        raw_score = (
            100
            - entities_penalty
            - severity_penalty
            - density_penalty
            + confidence_bonus
            + verification_bonus
        )
        score = max(0, min(100, round(raw_score)))

        # Grade mapping
        if score >= 90:
            grade, label = "A+", "Excellent Privacy"
        elif score >= 80:
            grade, label = "A", "Strong Privacy"
        elif score >= 70:
            grade, label = "B", "Good Privacy"
        elif score >= 60:
            grade, label = "C", "Moderate Risk"
        elif score >= 40:
            grade, label = "D", "High Risk"
        else:
            grade, label = "F", "Critical Risk"

        return {
            "score": score,
            "grade": grade,
            "label": label,
            "breakdown": {
                "entities_penalty": entities_penalty,
                "severity_penalty": severity_penalty,
                "confidence_bonus": confidence_bonus,
                "verification_bonus": verification_bonus,
                "density_penalty": density_penalty,
            },
        }

    def _update_stats(self, entities: List[Dict], strategy: str, processing_time: float):
        """Update internal statistics."""
        self.stats["total_requests"] += 1
        self.stats["total_entities_detected"] += len(entities)
        self.stats["total_texts_processed"] += 1
        self.stats["processing_times"].append(processing_time)

        if len(self.stats["processing_times"]) > 1000:
            self.stats["processing_times"] = self.stats["processing_times"][-500:]

        for e in entities:
            etype = e.get("entity_type", "UNKNOWN")
            self.stats["entity_type_distribution"][etype] = \
                self.stats["entity_type_distribution"].get(etype, 0) + 1

        self.stats["strategy_usage"][strategy] = \
            self.stats["strategy_usage"].get(strategy, 0) + 1

"""OracleJudgeV2 — Recalibrated verdict scoring with delta-based analysis.

Session 032: Replaces V1's independent threshold approach with a
three-tier decision: dominant override, delta-based scoring, and
INCONCLUSIVE default. Fixes 4 CONFIDENCE_CALIBRATION failures from
Session 031 (SC-016, SC-026, SC-031, SC-032).

Public API:
    OracleJudgeV2  — drop-in replacement for OracleJudge.compute_verdict()
    ScoringConfig  — configurable thresholds
"""

from __future__ import annotations

from dataclasses import dataclass

from ares.dialectic.agents.patterns import Verdict, VerdictOutcome


# ---------------------------------------------------------------------------
# Scoring configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScoringConfig:
    """Configurable scoring parameters for OracleJudgeV2.

    V1 OracleJudge used independent thresholds:
        arch >= 0.7 AND skep < 0.5 -> CONFIRMED
        skep >= 0.7 AND arch < 0.5 -> DISMISSED

    This created cliff effects where arch=1.0, skep=0.52 -> INCONCLUSIVE.

    V2 uses delta-based scoring with configurable thresholds.

    Attributes:
        confirm_delta: Minimum arch - skep delta to lean CONFIRMED.
        dismiss_delta: Minimum skep - arch delta to lean DISMISSED.
        min_winner_confidence: Minimum confidence for the winning side.
        dominant_threshold: Confidence level for dominant override.
        dominant_opponent_max: Max opponent confidence for dominant override.
    """

    confirm_delta: float = 0.15
    dismiss_delta: float = 0.15
    min_winner_confidence: float = 0.6
    dominant_threshold: float = 0.85
    dominant_opponent_max: float = 0.65

    def __post_init__(self) -> None:
        for field_name in (
            "confirm_delta",
            "dismiss_delta",
            "min_winner_confidence",
            "dominant_threshold",
            "dominant_opponent_max",
        ):
            val = getattr(self, field_name)
            if not (0.0 <= val <= 1.0):
                raise ValueError(
                    f"{field_name} must be between 0.0 and 1.0, got {val}"
                )


# ---------------------------------------------------------------------------
# OracleJudgeV2
# ---------------------------------------------------------------------------

class OracleJudgeV2:
    """Recalibrated verdict scoring with delta-based confidence analysis.

    Three-tier decision:
        1. DOMINANT OVERRIDE: One side >= 0.85 and opponent <= 0.65
        2. DELTA-BASED: Confidence delta >= threshold and winner >= min
        3. DEFAULT: INCONCLUSIVE

    The interface matches OracleJudge.compute_verdict() exactly.
    """

    DEFAULT_CONFIG = ScoringConfig()

    @staticmethod
    def compute_verdict(
        architect_msg,
        skeptic_msg,
        packet,
        config: ScoringConfig | None = None,
    ) -> Verdict:
        """Compute verdict using calibrated delta-based scoring.

        Args:
            architect_msg: DialecticalMessage from Architect (THESIS phase).
            skeptic_msg: DialecticalMessage from Skeptic (ANTITHESIS phase).
            packet: The frozen EvidencePacket.
            config: Optional ScoringConfig (uses DEFAULT_CONFIG if None).

        Returns:
            Verdict — same type as OracleJudge.compute_verdict().
        """
        if config is None:
            config = OracleJudgeV2.DEFAULT_CONFIG

        arch_confidence = architect_msg.confidence
        skep_confidence = skeptic_msg.confidence

        arch_facts = architect_msg.get_all_fact_ids()
        skep_facts = skeptic_msg.get_all_fact_ids()

        outcome, reasoning = OracleJudgeV2._apply_scoring(
            arch_confidence,
            skep_confidence,
            config,
        )

        if outcome == VerdictOutcome.THREAT_CONFIRMED:
            supporting_facts = frozenset(arch_facts)
            final_confidence = arch_confidence
        elif outcome == VerdictOutcome.THREAT_DISMISSED:
            supporting_facts = frozenset(skep_facts)
            final_confidence = skep_confidence
        else:
            supporting_facts = frozenset(arch_facts | skep_facts)
            final_confidence = (arch_confidence + skep_confidence) / 2

        return Verdict(
            outcome=outcome,
            confidence=final_confidence,
            supporting_fact_ids=supporting_facts,
            architect_confidence=arch_confidence,
            skeptic_confidence=skep_confidence,
            reasoning=reasoning,
        )

    @staticmethod
    def _apply_scoring(
        arch_conf: float,
        skep_conf: float,
        config: ScoringConfig,
    ) -> tuple:
        """Apply the three-tier scoring logic.

        Args:
            arch_conf: Architect's confidence (0.0-1.0).
            skep_conf: Skeptic's confidence (0.0-1.0).
            config: Scoring thresholds.

        Returns:
            Tuple of (VerdictOutcome, reasoning string).
        """
        delta = arch_conf - skep_conf

        # --- Tier 1: Dominant Override ---
        if (
            arch_conf >= config.dominant_threshold
            and skep_conf <= config.dominant_opponent_max
        ):
            return (
                VerdictOutcome.THREAT_CONFIRMED,
                f"Dominant override: architect={arch_conf:.2f} >= "
                f"{config.dominant_threshold}, skeptic={skep_conf:.2f} <= "
                f"{config.dominant_opponent_max}",
            )

        if (
            skep_conf >= config.dominant_threshold
            and arch_conf <= config.dominant_opponent_max
        ):
            return (
                VerdictOutcome.THREAT_DISMISSED,
                f"Dominant override: skeptic={skep_conf:.2f} >= "
                f"{config.dominant_threshold}, architect={arch_conf:.2f} <= "
                f"{config.dominant_opponent_max}",
            )

        # --- Tier 2: Delta-Based ---
        if delta >= config.confirm_delta and arch_conf >= config.min_winner_confidence:
            return (
                VerdictOutcome.THREAT_CONFIRMED,
                f"Delta-based: arch={arch_conf:.2f} - skep={skep_conf:.2f} = "
                f"{delta:.2f} >= {config.confirm_delta}, "
                f"arch >= {config.min_winner_confidence}",
            )

        if -delta >= config.dismiss_delta and skep_conf >= config.min_winner_confidence:
            return (
                VerdictOutcome.THREAT_DISMISSED,
                f"Delta-based: skep={skep_conf:.2f} - arch={arch_conf:.2f} = "
                f"{-delta:.2f} >= {config.dismiss_delta}, "
                f"skep >= {config.min_winner_confidence}",
            )

        # --- Tier 3: Inconclusive ---
        return (
            VerdictOutcome.INCONCLUSIVE,
            f"Inconclusive: arch={arch_conf:.2f}, skep={skep_conf:.2f}, "
            f"delta={delta:.2f}. Neither dominant nor sufficient delta.",
        )

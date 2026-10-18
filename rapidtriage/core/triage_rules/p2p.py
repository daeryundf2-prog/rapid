"""P2P indicators: BitTorrent clients and eMule (R5 L3; catalogue ``p2p.yaml``)."""

from __future__ import annotations

from .base import FlagContext, RowView, Rule, RuleResult, evidence, register, select

TRANSFERS = select(types={"p2p-transfer"})
SHARED = select(types={"p2p-shared-file"})


@register("p2p.torrent_seeding_uploaded")
class TorrentSeedingUploaded(Rule):
    """A BitTorrent transfer record with uploaded bytes ≥ ``min_uploaded_bytes`` (pieces sent to peers)."""

    selector = TRANSFERS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        if row.text("client") == "emule":
            return None
        uploaded = row.number("uploaded_bytes")
        if uploaded is None or uploaded < float(self.param("min_uploaded_bytes", 1)):
            return None
        return RuleResult(
            evidence(
                name=row.text("name"),
                uploaded_bytes=int(uploaded),
                info_hash=row.text("info_hash"),
                client=row.text("client_label", "client"),
                save_path=row.text("save_path"),
            )
        )


@register("p2p.transfer_completed")
class TransferCompleted(Rule):
    """A torrent / eMule transfer with a completion time."""

    selector = TRANSFERS

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        completed = row.text("completed_at")
        if not completed or row.text("state") != "completed":
            return None
        return RuleResult(
            evidence(name=row.text("name"), completed_at=completed, client=row.text("client_label", "client"), save_path=row.text("save_path"))
        )


@register("p2p.emule_shared_uploaded")
class EmuleSharedUploaded(Rule):
    """An eMule known.met file with all-time uploaded bytes ≥ ``min_uploaded_bytes`` or accepted requests."""

    selector = SHARED

    def apply(self, row: RowView, ctx: FlagContext) -> RuleResult | None:
        uploaded = row.number("all_time_uploaded_bytes") or 0
        accepted = row.number("all_time_accepted") or 0
        if uploaded < float(self.param("min_uploaded_bytes", 1)) and accepted <= 0:
            return None
        return RuleResult(
            evidence(
                file_name=row.text("file_name"),
                uploaded_bytes=int(uploaded),
                accepted_requests=int(accepted),
                ed2k_hash=row.text("ed2k_hash"),
            )
        )

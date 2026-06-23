"""Persistencia de campañas (en memoria, por ahora).

Misma estrategia que el repositorio de autorizaciones: una interfaz y una
implementación en memoria. Persistir campañas en SQLite es una iteración futura
que solo agrega otra implementación.
"""

from __future__ import annotations

from typing import Protocol

from ..campaigns import Campaign


class CampaignRepository(Protocol):
    def add(self, campaign: Campaign) -> None: ...
    def get(self, campaign_id: str) -> Campaign | None: ...
    def list(self) -> list[Campaign]: ...


class InMemoryCampaignRepository:
    def __init__(self) -> None:
        self._store: dict[str, Campaign] = {}

    def add(self, campaign: Campaign) -> None:
        self._store[campaign.campaign_id] = campaign

    def get(self, campaign_id: str) -> Campaign | None:
        return self._store.get(campaign_id)

    def list(self) -> list[Campaign]:
        return list(self._store.values())


_repository: CampaignRepository = InMemoryCampaignRepository()


def get_campaign_repository() -> CampaignRepository:
    return _repository

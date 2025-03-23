import sys
import requests
import os
from dataclasses import dataclass
import time
import logging
from models import CacheStats, StatsResponse
import hashlib

from prom_client import PromMetricsClient

logger = logging.getLogger(__name__)

BWSC_URL = os.environ.get("BWS_CACHE_URL")
SECRET_TTL = int(os.environ.get("SECRET_TTL", 15))
KEEP_ON_CONN_FAIL = os.environ.get("KEEP_ON_CONN_FAIL", "false").lower() == "true"
if not BWSC_URL:
    logger.critical("BWS_CACHE_URL not set")
    sys.exit(1)


def generate_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class SecretResponse:
    value: str
    status_code: int


class BwscClient:
    def __init__(self, token: str):
        self.token = token

    def get_secret_by_id(self, secret_id: str):
        value = requests.get(
            f"{BWSC_URL}/id/{secret_id}",
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=1,
        )
        return SecretResponse(value=value.text, status_code=value.status_code)

    def get_secret_by_key(self, secret_key: str):
        value = requests.get(
            f"{BWSC_URL}/key/{secret_key}",
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=1,
        )
        return SecretResponse(value=value.text, status_code=value.status_code)


@dataclass
class CachedSecret:
    value: SecretResponse
    last_requested: float


class BwscCachedClient:
    def __init__(self, token: str, prom_clien: PromMetricsClient):
        self.prom_client = prom_clien
        self.client = self.make_client(token)
        self.secret_id_cache: dict[str, CachedSecret] = {}
        self.secret_key_cache: dict[str, CachedSecret] = {}

    @staticmethod
    def make_client(token: str):
        return BwscClient(token)

    def reset_cache(self):
        before = CacheStats(
            secret_cache_size=len(self.secret_id_cache),
            keymap_cache_size=len(self.secret_key_cache),
        )
        self.secret_id_cache = {}
        self.secret_key_cache = {}
        return before

    def get_secret_by_id(self, secret_id: str):
        cached_secret = None
        if secret_id in self.secret_id_cache:
            cached_secret = self.secret_id_cache[secret_id]
            if cached_secret.last_requested + SECRET_TTL > time.time():
                self.prom_client.tick_cache_hits("id")
                return cached_secret.value
        self.prom_client.tick_cache_miss("id")
        try:
            value = self.client.get_secret_by_id(secret_id)
        except requests.exceptions.RequestException:
            if KEEP_ON_CONN_FAIL and cached_secret:
                value = cached_secret.value
            else:
                value = SecretResponse(value="cannot connect to bwsc", status_code=500)
        cached_secret = CachedSecret(value=value, last_requested=time.time())
        self.secret_id_cache[secret_id] = cached_secret
        return cached_secret.value

    def get_secret_by_key(self, secret_key: str):
        cached_secret = None
        if secret_key in self.secret_key_cache:
            cached_secret = self.secret_key_cache[secret_key]
            if cached_secret.last_requested + SECRET_TTL > time.time():
                self.prom_client.tick_cache_hits("key")
                return cached_secret.value
        self.prom_client.tick_cache_miss("key")
        try:
            value = self.client.get_secret_by_key(secret_key)
        except requests.exceptions.RequestException:
            if KEEP_ON_CONN_FAIL and cached_secret:
                value = cached_secret.value
            else:
                value = SecretResponse(value="cannot connect to bwsc", status_code=500)
        cached_secret = CachedSecret(value=value, last_requested=time.time())
        self.secret_key_cache[secret_key] = cached_secret
        return cached_secret.value

    def stats(self):
        return CacheStats(
            secret_cache_size=len(self.secret_id_cache),
            keymap_cache_size=len(self.secret_key_cache),
        )


class ClientManager:
    def __init__(self, prom_client: PromMetricsClient):
        self.prom_client = prom_client
        self.clients: dict[str, BwscCachedClient] = {}

    def get_client_by_token(self, token: str):
        hashed_token = generate_hash(token)
        if hashed_token not in self.clients:
            self.clients[hashed_token] = BwscCachedClient(token, self.prom_client)
        return self.clients[hashed_token]

    def stats(self):
        total_secret_id = 0
        total_secret_key = 0
        client_stats = {}
        for hashed_client, client in self.clients.items():
            client_stats[hashed_client] = client.stats()
            total_secret_id += client_stats[hashed_client].secret_cache_size
            total_secret_key += client_stats[hashed_client].keymap_cache_size
        return StatsResponse(
            num_clients=len(self.clients),
            client_stats=client_stats,
            total_stats=CacheStats(
                secret_cache_size=total_secret_id, keymap_cache_size=total_secret_key
            ),
        )

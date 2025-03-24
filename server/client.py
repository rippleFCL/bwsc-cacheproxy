import sys
import threading
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
BACKGROUND_REFRESH = os.environ.get("BACKGROUND_REFRESH", "false").lower() == "true"

if not BWSC_URL:
    logger.critical("BWS_CACHE_URL not set")
    sys.exit(1)


def generate_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class SecretResponse:
    value: str
    status_code: int


@dataclass
class CachedSecret:
    value: SecretResponse
    last_requested: float


class BwscCachedClient:
    def __init__(self, token: str, prom_clien: PromMetricsClient):
        self.token = token
        self.prom_client = prom_clien
        self.endpoint_cache: dict[str, CachedSecret] = {}
        self.endpoint_cache_lock = threading.Lock()
        if BACKGROUND_REFRESH:
            self.refresh_thread = threading.Thread(target=self._refresh_loop)
            self.refresh_thread.daemon = True
            self.refresh_thread.start()

    def _refresh_loop(self):
        while True:
            min_sleep = None
            expired_endpoints = []
            with self.endpoint_cache_lock:
                for url, cached_secret in self.endpoint_cache.items():
                    current_time = time.time()
                    time_till_expire = SECRET_TTL - (
                        current_time - cached_secret.last_requested
                    )
                    if time_till_expire < 0:
                        expired_endpoints.append(url)
                    elif min_sleep is None or time_till_expire < min_sleep:
                        min_sleep = time_till_expire
            for url in expired_endpoints:
                endpoint, secret_id = url.split("/")
                self.refresh_endpoint(endpoint, secret_id)
            if min_sleep is not None:
                time.sleep(min_sleep)

    def reset_cache(self):
        before = self.stats()
        self.endpoint_cache = {}
        return before

    def refresh_endpoint(self, endpoint: str, secret_id: str):
        self.prom_client.tick_cache_miss(endpoint)
        url = f"{endpoint}/{secret_id}"
        try:
            result = requests.get(
                f"{BWSC_URL}/{url}",
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=1,
            )
            value = SecretResponse(value=result.text, status_code=result.status_code)

        except requests.exceptions.RequestException:
            if KEEP_ON_CONN_FAIL and url in self.endpoint_cache:
                value = self.endpoint_cache[url].value
            else:
                value = SecretResponse(value="cannot connect to bwsc", status_code=500)
        cached_secret = CachedSecret(value=value, last_requested=time.time())
        with self.endpoint_cache_lock:
            self.endpoint_cache[url] = cached_secret
        return cached_secret.value

    def get_endpoint(self, endpoint: str, secret_id: str):
        url = f"{endpoint}/{secret_id}"
        with self.endpoint_cache_lock:
            if url in self.endpoint_cache:
                cached_secret = self.endpoint_cache[url]
                if (
                    cached_secret.last_requested + SECRET_TTL > time.time()
                    or BACKGROUND_REFRESH
                ):
                    self.prom_client.tick_cache_hits(endpoint)
                    return cached_secret.value
        return self.refresh_endpoint(endpoint, secret_id)

    def get_secret_by_id(self, secret_id: str):
        return self.get_endpoint("id", secret_id)

    def get_secret_by_key(self, secret_key: str):
        return self.get_endpoint("key", secret_key)

    def stats(self):
        secret_key_count = 0
        secret_id_count = 0
        for url, cached_secret in self.endpoint_cache.items():
            if cached_secret.value.status_code == 200:
                if "key/" in url:
                    secret_key_count += 1
                elif "id/" in url:
                    secret_id_count += 1
        return CacheStats(
            secret_cache_size=secret_id_count,
            keymap_cache_size=secret_key_count,
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

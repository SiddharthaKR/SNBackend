import redis
import json
from dotenv import load_dotenv
import os

load_dotenv()

HOST = os.getenv("REDIS_HOST") if os.getenv("REDIS_HOST") else 'localhost'

redis_client = redis.Redis(host=HOST, port='6379', db=0)
auth_store = redis.Redis(host=HOST, port='6379', db=1)
blacklist_sync_client = redis.Redis(host=HOST, port='6379', db=2)


def check_spamhaus_token() -> str:
    if (auth_store.get("spamhaus_token")):
        spamhaus_token = auth_store.get("spamhaus_token")
        return spamhaus_token
    return None


def add_spamhaus_token(token: str):
    response = auth_store.set("spamhaus_token", token)
    auth_store.expire("spamhaus_token", 60 * 60 * 12) # 12 Hours Expiry Time
    return response


def check_ip_report(ip: str):
    key = f"{ip}"
    return redis_client.get(key)


def add_ip_report(ip: str, port: int, package_name: str, report: str):
    key = f"{ip}"
    json_report = report
    response = redis_client.set(key, json_report)
    redis_client.expire(key, 60 * 60 * 24 * 7)  # Expire after 7 days
    return response


def check_domain_report(domain: str):
    key = f"{domain}"
    return redis_client.get(key)


def add_domain_report(domain: str, package_name: str, report: str):
    key = f"{domain}"
    json_report = report
    response = redis_client.set(key, json_report)
    redis_client.expire(key, 60 * 60 * 24 * 7)  # Expire after 7 days
    return response

# Utils for Blacklists Sync (SETS)
def add_ip_to_blacklist(ip: str):
    blacklist_sync_client.sadd("blacklist:ips", ip)

def add_domain_to_blacklist(domain: str):
    blacklist_sync_client.sadd("blacklist:domains", domain)

def get_blacklisted_ips():
    return blacklist_sync_client.smembers("blacklist:ips")

def get_blacklisted_domains():
    return blacklist_sync_client.smembers("blacklist:domains")
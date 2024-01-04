import requests
import os
from dotenv import load_dotenv
from redis_utils import add_spamhaus_token, check_spamhaus_token
import tldextract

load_dotenv()


def spamhaus_token() -> str:
    if check_spamhaus_token():
        print("SpamHaus Token: Cache Hit!")
        return str(check_spamhaus_token(), 'UTF-8')
    else:
        print("SpamHaus Token: No Cache Found!")
        response = requests.post("https://api.spamhaus.org/api/v1/login", json={
            "username": os.environ['SPAMHAUS_USERNAME'], "password": os.environ['SPAMHAUS_PASSWORD'], "realm": "intel"})
        response_json = response.json()
        token = response_json["token"]
        add_spamhaus_token(token)
        try:
            return str(token, 'UTF-8')
        except:
            return token
        # return str(token, 'UTF-8')


def domain_report(domain: str):
    try:
        token = spamhaus_token()
       
        print(f"Domain Report: {domain}")
        extracted = tldextract.extract(domain)
        response = requests.get(
            f"https://api.spamhaus.org/api/intel/v2/byobject/domain/{'{}.{}'.format(extracted.domain, extracted.suffix)}",
            headers={
                "Authorization": f"Bearer {token}"
            }
        )
        print("Domain Report", response.json())
        response = response.json()
    except:
        response = {
            "domain": domain,
            "score": 0,
        }
    response['type'] = 'domain'
    return response

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
        # curl -s https://api.spamhaus.org/api/intel/v2/byobject/domain/google.com -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3MDI4Njg1NDksImV4cCI6MTcwMjk1NDk0OSwiaXNzIjoic2hhcGktYXV0aCIsImF1ZCI6ImludGVsIiwic3ViIjoiMjkwOTE3OTUiLCJ1c3IiOiJhbXJlc2hAZHVjay5jb20iLCJ0aWVyIjp7Imx2bCI6InN0ZCIsImFkcyI6IlhCTCxCQ0wsQ1NTLERPTUFJTiIsImFkdyI6MCwicW1zIjo1MDAwLCJxbWgiOjUwMDAsInJsX3FwaCI6NTAwMCwicmxfcXBtIjo1MDAwLCJybF9xcHMiOjUwMDB9fQ.jJGLNZwpZB_bfDEDHBg8yBw7zk75AKzht4vJcguvtsY'
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

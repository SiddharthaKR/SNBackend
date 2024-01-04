# Shared Utils for misc functions
# ! NOT BEING USED CURRENTLY!

import requests
import os
from dotenv import load_dotenv
import re

load_dotenv()

# MOBSF HELPERS
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY")
MOBSF_API_URL = os.getenv("MOBSF_ENDPOINT")


def check_app_on_server(hash: str) -> bool:
    # Check valid md5 hash or not
    valid_hash = re.findall(r"([a-fA-F\d]{32})", hash)
    if not valid_hash:
        return False

    # Check app on server based on the status code
    response = requests.post(
        MOBSF_API_URL + "/api/v1/report_json",
        data={'hash': hash},
        headers={"Authorization": MOBSF_API_KEY}
    )
    if response.status_code == 200:
        return True
    else:
        return False

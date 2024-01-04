from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Response, Request
from gemini_utils import BASE_PROMPT_ACTION, BASE_PROMPT_SUMMARY, GEMINI_API_KEY
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List
import models
from database import engine, SessionLocal
from sqlalchemy.orm import Session
import shutil
from dotenv import load_dotenv
import os
import requests
import hashlib
import time
from requests_toolbelt.multipart.encoder import MultipartEncoder
from ipdata_utils import ip_report
import json
from redis_utils import check_ip_report, add_ip_report, check_domain_report, add_domain_report, add_ip_to_blacklist, add_domain_to_blacklist, get_blacklisted_ips, get_blacklisted_domains
from spamhaus_utils import domain_report
import urllib.parse
import google.generativeai as genai
import random
from shared_utils import check_app_on_server
from pydantic import BaseModel
# TODO: Implement async calls for notifs
import aiohttp
import asyncio

load_dotenv()

app = FastAPI()

fcmToken = ""

models.Base.metadata.create_all(bind=engine)


class AppCreate(BaseModel):
    package_name: str
    app_name: str
    version_code: int
    version_name: str
    file_size: int
    permissions: List[str]
    is_system_app: bool
    is_malicious: bool
    threat_category: str = None
    static_analysis_results: str = None
    dynamic_analysis_results: str = None


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Depends(get_db)


class AppResponse(BaseModel):
    message: str
    app_id: int

# Endpoint to create a new app entry


@app.post("/apps/", response_model=AppResponse)
async def create_app(app_data: AppCreate, db: Session = db_dependency):
    try:
        # Convert Pydantic model to SQLAlchemy model
        db_app = models.AppDBModel(**app_data.dict())

        # Store the data in the database
        db.add(db_app)
        db.commit()
        db.refresh(db_app)

        return {"message": "App created successfully", "app_id": db_app.id}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/apps/", response_model=List[AppResponse])
async def list_apps(db: Session = db_dependency):
    apps = db.query(models.AppDBModel).all()

    return [
        AppResponse(
            app_id=app.id,
            package_name=app.package_name,
            app_name=app.app_name,
            version_code=app.version_code,
            version_name=app.version_name,
            file_size=app.file_size,
            permissions=app.permissions,
            is_system_app=app.is_system_app,
            is_malicious=app.is_malicious,
            threat_category=app.threat_category,
            static_analysis_results=app.static_analysis_results,
            dynamic_analysis_results=app.dynamic_analysis_results
        )
        for app in apps
    ]


@app.post("/static/upload")
async def upload_apk(file: UploadFile = File(...)):
    """Upload route (POST) for the APK file

    Args:
        file (UploadFile, optional): _description_. Defaults to File(...).

    Raises:
        HTTPException: _description_

    Returns:
        _type_: _description_

    Example:
        Command: `curl -F 'file=@./example.apk' http://<api-server-endpoint>/static/upload`

        Response: 
        ```json
        {
            "mobsf_static": {
                "analyzer":"static_analyzer",
                "status":"success",
                "hash":"5f06b231c5e9b1703b088ad87050c89f",
                "scan_type":"apk",
                "file_name":"temp_example.apk"
            },
            "file_md5":"d25ebd002f0cce403f023c0840b2096d2ea34ddc"
        }
        ```
    """
    try:
        mobsf_api_url = f"{os.environ['MOBSF_ENDPOINT']}/api/v1/upload"
        temp_file_path = f"temp_{file.filename}"

        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Calculate the SHA hash of the file
        sha_hash = hashlib.md5()
        with open(temp_file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha_hash.update(chunk)

        file_hash = sha_hash.hexdigest()
        print(
            f"SHA256 Hash of the file {file.filename}: {file_hash}")

        # time.sleep(1)  # !TEST

        with open(temp_file_path, "rb") as f:
            multipart_data = MultipartEncoder(
                fields={'file': (temp_file_path, f, 'application/octet-stream')})
            response = requests.post(
                mobsf_api_url,
                data=multipart_data,
                headers={'Content-Type': multipart_data.content_type,
                         "Authorization": os.environ['MOBSF_API_KEY']}
            )

        os.remove(temp_file_path)

        # Scan
        response = requests.post(f"{os.environ['MOBSF_ENDPOINT']}/api/v1/scan",
                                 data={
                                     "hash": file_hash
                                 },
                                 headers={
                                     "Authorization": os.environ['MOBSF_API_KEY']}
                                 )

        return {"static": response.json(), "file_md5": file_hash}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/gemini/action")
async def gemini_action(hash: str):
    try:
        response = requests.post(f"{os.environ['MOBSF_ENDPOINT']}/api/v1/report_json",
                                data={
                                    "hash": hash
                                },
                                headers={
                                    "Authorization": os.environ['MOBSF_API_KEY']}
                                )

        # !DEBUG LINE
        # print(response.text)

        # Remove garbage value
        response = response.json()
        response.pop('md5', None)
        response.pop('sha1', None)
        response.pop('sha256', None)
        response.pop('browsable_activities', None)
        response.pop('receivers', None)
        response.pop('icon_path', None)
        response.pop('certificate_analysis', None)
        response.pop('binary_analysis', None)
        response.pop('urls', None)
        response.pop('domains', None)
        response.pop('emails', None)
        response.pop('strings', None)
        response.pop('firebase_urls', None)
        response.pop('files', None)
        response.pop('exported_count', None)
        response.pop('secrets', None)

        action_prompt = BASE_PROMPT_ACTION + json.dumps(response)

        # !DEBUG LINE
        # print(action_prompt)

        genai.configure(api_key=GEMINI_API_KEY)

        model = genai.GenerativeModel('gemini-pro')

        response = model.generate_content(action_prompt)

        return response.text
    except:
        return "Not able to generate action due to Gemini's context limit (30K Tokens)"


@app.get("/gemini/summary")
async def gemini_summary(hash: str):
    try:
        response = requests.post(f"{os.environ['MOBSF_ENDPOINT']}/api/v1/report_json",
                                data={
                                    "hash": hash
                                },
                                headers={
                                    "Authorization": os.environ['MOBSF_API_KEY']}
                                )

        # Remove garbage value
        response = response.json()
        response.pop('md5', None)
        response.pop('sha1', None)
        response.pop('sha256', None)
        response.pop('browsable_activities', None)
        response.pop('receivers', None)
        response.pop('icon_path', None)
        response.pop('certificate_analysis', None)
        response.pop('binary_analysis', None)
        response.pop('urls', None)
        response.pop('domains', None)
        response.pop('emails', None)
        response.pop('strings', None)
        response.pop('firebase_urls', None)
        response.pop('files', None)
        response.pop('exported_count', None)
        response.pop('secrets', None)

        action_prompt = BASE_PROMPT_SUMMARY + json.dumps(response)
        genai.configure(api_key=GEMINI_API_KEY)

        model = genai.GenerativeModel('gemini-pro')

        response = model.generate_content(action_prompt)

        return response.text
    except:
        return "Not able to generate summary due to Gemini's context limit (30K Tokens)"


@app.get("/static/scorecard")
async def scorecard(hash: str):
    """Scorecard route (GET) for the APK file

    Args:
        hash (str): MD5 hash of the APK file

    Raises:
        HTTPException: _description_

    Returns:
        _type_: _description_

    Example:
        Command: `curl http://<api-server-endpoint>/static/scorecard?hash=5f06b231c5e9b1703b088ad87050c89f`

        Response: JSON object
    """
    try:
        mobsf_api_url = f"{os.environ['MOBSF_ENDPOINT']}/api/v1/scorecard"
        response = requests.post(
            mobsf_api_url,
            data={'hash': hash},
            headers={"Authorization": os.environ['MOBSF_API_KEY']}
        )
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/static/report_json")
async def report_json(hash: str):
    """Report JSON route (GET) for the APK file

    Args:
        hash (str): MD5 hash of the APK file

    Raises:
        HTTPException: _description_

    Returns:
        _type_: _description_

    Example:
        Command: `curl http://<api-server-endpoint>/static/report_json?hash=5f06b231c5e9b1703b088ad87050c89f`

        Response: JSON object
    """
    try:
        mobsf_api_url = f"{os.environ['MOBSF_ENDPOINT']}/api/v1/report_json"
        response = requests.post(
            mobsf_api_url,
            data={'hash': hash},
            headers={"Authorization": os.environ['MOBSF_API_KEY']}
        )
        if response.status_code == 200:
            return response.json()
        else:
            return JSONResponse(status_code=404, content=response.json())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/static/report_pdf")
async def report_pdf(hash: str):
    """Report PDF route (GET) for the APK file

    Args:
        hash (str): MD5 hash of the APK file

    Raises:
        HTTPException: _description_

    Returns:
        _type_: _description_

    Example:
        Command: `curl http://<api-server-endpoint>/pdf?hash=5f06b231c5e9b1703b088ad87050c89f`

        Response: PDF file
    """
    try:
        query = f"{os.environ['MOBSF_ENDPOINT']}/pdf/{hash}/"
        print(query)
        response = requests.get(query)
        return Response(content=response.content, media_type="application/pdf")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/fcm")
async def fcm_init(request: Request):
    data = await request.json()
    token = data.get("token")
    global fcmToken
    fcmToken = token
    print("fcmToken:", fcmToken)  # !DEBUG
    return {"success": True, "fcmToken": token}


async def send_notif(title: str, body: str):
    global fcmToken
    if fcmToken == "":
        print("FCM token not set")
        return {"message": "set FCM TOKEN first"}
    # response = requests.post(
    #     "https://securenet-notif.onrender.com/notif",
    #     json={'fcmToken': fcmToken, 'title': title, 'body': body},
    #     headers={"Content-Type": "application/json"}
    # )
    # return response.json()
    async with aiohttp.ClientSession() as session:
        print("Sending notif...")
        async with session.post(
            "https://securenet-notif.onrender.com/notif",
            json={'fcmToken': fcmToken, 'title': title, 'body': body},
            headers={"Content-Type": "application/json"}
        ) as response:
            return await response.json()


@app.get("/tests/notif")
async def test_notif():
    asyncio.create_task(send_notif(title="Malicious IP found!", body="com.android.chrome"))
    return {"success": True}

# import numpy as np
# import pickle


@app.get("/dynamic/ipdom")
async def ip_or_domain_report(package: str, port: int | None = None, ip: str | None = None, domain: str | None = None, protocol: int | None = None):
    # type = "ip"
    if ip:
        # source_ip = "192.168.100.103"

        # in_data = []

        # source_ip = source_ip.split('.')
        # source_ip = [in_data.append(float(i)) for i in source_ip]

        # in_data.append(float(port))

        # des_ip = ip.split('.')
        # des_ip = [in_data.append(float(i)) for i in des_ip]

        # in_data.append(float(port))

        # in_features = [0.000e+00, 0.000e+00, 3.000e+00, 1.800e+02, 0.000e+00, 0.000e+00, 1.000e+00, 1.000e+00]

        # [in_data.append(i) for i in in_features]

        # in_data = np.array(in_data).reshape(1, -1)

        # with open('model.pkl', 'rb') as f:
        #     model = pickle.load(f)

        # try:
        #     prediction = model.predict(in_data)
        #     print(prediction)

        # except Exception:
        #     print("Could not predict")

        # Check if the IP is already present in the Redis cache
        ip_report_redis = check_ip_report(ip)
        if ip_report_redis:
            print("IP Check: Cache Hit!")

            response = json.loads(ip_report_redis)

            # !Trigger Push Notification if malicious (IP)
            try:
                threat = response["threat"]
                # print("moye moye", threat)
                if threat['is_known_attacker'] and threat['is_known_abuser'] and threat['is_threat']:
                    asyncio.create_task(send_notif(title="Malicious IP found",
                                                body=f"{ip} is malicious for {package}"))
                    # TODO: ^^ Needs asyncio to be implemented
            except:
                pass

            return response
        else:
            print("IP Check: No Cache Found!")
            # Fetch the IP report from ipdata.co
            ip_report_data = ip_report(ip)
            ip_report_data['request'] = {
                "package": package,
                "port": port,
                "ip": ip,
                "protocol": protocol
            }

            # !Trigger Push Notification if malicious (IP)
            try:
                threat = ip_report_data["threat"]
                # print("moye moye", threat)
                if threat['is_known_attacker'] and threat['is_known_abuser'] and threat['is_threat']:
                    asyncio.create_task(send_notif(title="Malicious IP found",
                                                body=f"{ip} is malicious for {package}"))
                    # TODO: ^^ Needs asyncio to be implemented
            except:
                pass

            # Store the IP report in the Redis cache
            add_ip_report(ip, port, package, json.dumps(ip_report_data))
            return ip_report_data
    elif domain:
        # type = "domain"
        # Check if the domain is already present in the Redis cache
        domain_report_redis = check_domain_report(domain)
        if domain_report_redis:
            print("Domain Check: Cache Hit!")

            response = json.loads(domain_report_redis)

            # !Trigger Push Notification if malicious (Domain)
            try:
                if response['score'] < 0:
                    asyncio.create_task(send_notif(title="Malicious Domain found",
                                                body=f"{domain} is malicious for {package}"))
                    # TODO: ^^ Needs asyncio to be implemented
            except:
                pass

            return response
        else:
            print("Domain Check: No Cache Found!")
            # Fetch the domain report from ipdata.co
            domain_report_data = domain_report(domain)
            domain_report_data['request'] = {
                "package": package,
                "domain": domain,
                "protocol": protocol
            }

            # !Trigger Push Notification if malicious (Domain)
            try:
                if domain_report_data['score'] < 0:
                    asyncio.create_task(send_notif(title="Malicious Domain found",
                                                body=f"{domain} is malicious for {package}"))
                    # TODO: ^^ Needs asyncio to be implemented
            except:
                pass

            # Store the domain report in the Redis cache
            add_domain_report(domain, package, json.dumps(domain_report_data))
            return domain_report_data
    else:
        raise HTTPException(
            status_code=500, detail="Incorrect Parameters Provided")


@app.post("/dynamic/url_report")
async def url_report(package: str, url: str):
    try:
        response = requests.get(
            f"https://www.ipqualityscore.com/api/json/url/{os.environ['IPQUALITYSCORE_API_KEY']}/{urllib.parse.quote(url, safe='')}")
        response = response.json()
        response['package'] = package
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Blacklist POST & GET


class BlacklistPOST(BaseModel):
    ip: str | None = None,
    domain: str | None = None,


@app.post("/dynamic/blacklist")
async def add_to_blacklist(q: BlacklistPOST):
    try:
        q = q.model_dump()
        if q['ip'][0] == None:
            q['ip'] = None
        if q['domain'][0] == None:
            q['domain'] = None

        if q['ip'] != None:
            add_ip_to_blacklist(q['ip'])
        if q['domain'] != None:
            add_domain_to_blacklist(q['domain'])
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/dynamic/blacklist")
async def get_blacklist():
    try:
        return {"ips": get_blacklisted_ips(), "domains": get_blacklisted_domains()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

import json,boto3,sys ,datetime ,time
import requests
import hashlib,hmac,random
import pprint
import smtplib
import re
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    # AAD properties
    tenId='ad2d08bd-a00e-49be-b91a-79f4e00e5738'
    requestBody = {"grant_type" : "client_credentials" , "client_id":"495f19c3-9fa2-4a8d-b581-7c6563c7eb54", "client_secret": "+*ktY/9fzzsD_nqGVuNXzFavvt3NdY40","expires_in": "3600","scope":"https://graph.microsoft.com/.default" }
    aadUrl = 'https://login.microsoftonline.com/'+tenId+'/oauth2/v2.0/token'
    headers = {'content-type' : 'application/x-www-form-urlencoded'}
    aadResponse = requests.post(aadUrl, data=requestBody, headers=headers)
    accessToken=aadResponse.json()['access_token']
    #print(aadResponse.json()['access_token'])

    # AAD parameters
    givenName="trial"
    surname="user"
    uniqueUserName=givenName+"."+surname
    email="user"
    randomPasswd="Cufu1801"


    userDetails={
        "givenName": givenName ,
        "surname": surname ,
        "accountEnabled": "true",
        "displayName": "abc-value",
        "mailNickname": "mailNickname-abc",
        "userPrincipalName": "kakakaka@azure.cloudaz.net",
        "passwordProfile" : {
            "forceChangePasswordNextSignIn": "true",
            "password": "123Next!"
        }
    }
    # dictionary and serialize it to JSON 
    userDetails = json.dumps(userDetails)

    if accessToken:
        graphHeaders = {'Content-Type' : 'application/json' ,'Authorization' : 'Bearer '+ accessToken, 'Host':'graph.microsoft.com'}
        aadGraphApiResponse = requests.post("https://graph.microsoft.com/v1.0/users", data=userDetails, headers=graphHeaders)
        print(aadGraphApiResponse.json())

lambda_handler ("-","-")
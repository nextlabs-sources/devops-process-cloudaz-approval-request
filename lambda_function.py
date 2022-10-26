import json,boto3,sys,time
from datetime import datetime
import requests
import hashlib,hmac,random
import pprint
import smtplib
import re
import logging
import os
from base64 import b64decode

from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb_table= os.environ["dynamodb_table"]
kmsclient = boto3.client('kms', region_name = 'us-west-2')

tenId_encrypted= os.environ["tenId"]
tenId = boto3.client('kms').decrypt(
    CiphertextBlob=b64decode(tenId_encrypted),
    EncryptionContext={'LambdaFunctionName': os.environ['AWS_LAMBDA_FUNCTION_NAME']}
)['Plaintext'].decode('utf-8')
print(tenId)

client_id_encrypted= os.environ["client_id"]
client_id = boto3.client('kms').decrypt(
    CiphertextBlob=b64decode(client_id_encrypted),
    EncryptionContext={'LambdaFunctionName': os.environ['AWS_LAMBDA_FUNCTION_NAME']}
)['Plaintext'].decode('utf-8')
print(client_id)

client_secret_encrypted= os.environ["client_secret"]
client_secret = boto3.client('kms').decrypt(
    CiphertextBlob=b64decode(client_secret_encrypted),
    EncryptionContext={'LambdaFunctionName': os.environ['AWS_LAMBDA_FUNCTION_NAME']}
)['Plaintext'].decode('utf-8')
print(client_secret)

def lambda_handler(event, context):
    
    print(event)
    print(tenId)
    requestBody = {"grant_type" : "client_credentials", "client_id": client_id, "client_secret": client_secret, "expires_in": "3600", "scope": "https://graph.microsoft.com/.default" }
    aadUrl = 'https://login.microsoftonline.com/'+tenId+'/oauth2/v2.0/token'

    headers = {'content-type' : 'application/x-www-form-urlencoded'}
    aadResponse = requests.post(aadUrl, data=requestBody, headers=headers)
    #print(aadResponse.json())
    print(aadResponse)
    accessToken=aadResponse.json()['access_token']
    #print(aadResponse.json()['access_token'])
    print(accessToken)

    print("Im latest deployment")
    dynamodb = boto3.resource('dynamodb','us-west-2')
    table = dynamodb.Table(dynamodb_table)
    tableQ = dynamodb.Table('cloudaz-questionnaire')
    emailHash=event['queryStringParameters']['emailHash']
    #approval=event['queryStringParameters']['approval'] 
    #emailHash= "68fe0883d6465aa4d0d1f690d25af15619702f0d"
    allpass=False
    #print("approval:" + approval)
    print(emailHash) 
    if emailHash:
      #if approval=='y':    
        print(emailHash)
        responseGet = table.scan(FilterExpression=Attr('emailHash').eq(emailHash))
        responseGetQ = tableQ.scan(FilterExpression=Attr('emailHash').eq(emailHash))
        items = responseGet['Items']
        itemsQ = responseGetQ['Items']
        print(responseGet)
        print(responseGetQ)
        print(items)
        print(itemsQ)
        #print(type(items))
        
        if items != [] : 
            if itemsQ != [] : 
            
                for item in items:
                    company=item['company']
                    email=item['email']
                for itemQ in itemsQ:
                    whatApp=itemQ['whatApp']
                    whatLanguage=itemQ['whatLanguage'] 
                    anythingElse=itemQ['whatLanguage']   
                print(item['approval'])
                print(item['welcomeEmailSent'])
                print(item['emailHash'])
                if item['welcomeEmailSent']=='n':
                    try:
                        email=item['email']
                        responseDdb = table.update_item(
                                    Key={
                                        'email': email
                                    },
                                    UpdateExpression='SET welcomeEmailSent = :val1',
                                    ExpressionAttributeValues={
                                        ':val1': 'y'
                                    }
                                )
                        return {'statusCode': 200,'headers': {'Content-Type': 'application/json'},'body': json.dumps('Welcome email sent status updated')  }                         
                    except ClientError as e:
                        print(e)   
                if item['emailHash']==emailHash and item['approval']=='n' and item['loginDetailSent']=='n' and item['welcomeEmailSent']=='y':
                    email=item['email']
                    firstName=item['firstName']
                    lastName=item['lastName']
                    print(item['emailHash'])
                    
                    print("name : " + firstName + ' ' + lastName + " - Email :  " + email)
                    
    
                    loginPass = 'NXT'+ email.split("@")[0] + str(time.localtime().tm_sec)
                    hash_object = hashlib.sha1(loginPass.encode())
                    loginPass = "N"+str(hash_object.hexdigest())[2:14] 
                    displaynameFor = firstName + " " + lastName
                    #print(str(hash_object.hexdigest()))
    

                    # AAD parameters
                    uniqueUserName=firstName+" "+lastName
                    aadUserName=firstName[0]+lastName

                    userDetails={
                        "givenName": firstName ,
                        "surname": lastName ,
                        "accountEnabled": "true",
                        "displayName": uniqueUserName,
                        "mailNickname": "mailNickname-"+firstName.replace(" ",""),
                        "userPrincipalName": aadUserName.replace(" ","")+'@nextlabstest2.onmicrosoft.com',
                        "passwordProfile" : {
                            "forceChangePasswordNextSignIn": "true",
                            "password": str(loginPass)
                        }
                    }
                    print("mailNickname-"+firstName.replace(" ",""))
                    print(aadUserName.replace(" "," ")+'@nextlabstest2.onmicrosoft.com')
                    print(str(loginPass))
                    # dictionary and serialize it to JSON 
                    userDetails = json.dumps(userDetails)
                    # Create AAD User
                    if accessToken:
                        graphHeaders = {'Content-Type' : 'application/json' ,'Authorization' : 'Bearer '+ accessToken, 'Host':'graph.microsoft.com'}
                        aadGraphApiResponse = requests.post("https://graph.microsoft.com/v1.0/users", data=userDetails, headers=graphHeaders)
                        print(aadGraphApiResponse.json())
                        found = json.dumps(aadGraphApiResponse.json()).find("error")
                        if found != -1:
                         print(aadGraphApiResponse.json())
                         return {'statusCode': 500,'headers': {'Content-Type': 'application/json'},'body': json.dumps(aadGraphApiResponse.json()) }           
                        
                        resp_dict = json.loads(json.dumps(aadGraphApiResponse.json()))
                        UserId = resp_dict['id']
                        print(UserId)
                        OData = {"@odata.id": "https://graph.microsoft.com/v1.0/users/"+UserId}
                        print(type(OData))
                        # Convert class dictionary into JSON
                        OData = json.dumps(OData)
                        fromEmail =  "admin@cloudaz.com"
                        toEmail = email
                        
                        ccUserName=aadUserName + "@nextlabstest2.onmicrosoft.com"
                        ccPassword=str(loginPass)
                        print(ccPassword)
                        groupHeaders={'Content-Type' : 'application/json' ,'Authorization' : 'Bearer '+accessToken, 'Host':'graph.microsoft.com'}
                        print(type(groupHeaders))
                        group_id = os.environ["group_id"]
                        print(group_id)
                        aadnewUrl = 'https://graph.microsoft.com/v1.0/groups/'+group_id+'/members/$ref'
                        #addUserToGroup = requests.post("https://graph.microsoft.com/v1.0/groups/+group_id+/members/$ref", data=OData)
                        addUserToGroup = requests.post(aadnewUrl, data=OData, headers=groupHeaders)
                        #print(addUserToGroup.json())
                        print(addUserToGroup)
                        #print(type(addUserToGroup))
                        #ErrorFound = json.dumps(addUserToGroup.json()).find("error")
                        #ErrorFound = str(addUserToGroup).find("401")
                        #print(ErrorFound)
                        #if ErrorFound != -1:
                         #print(addUserToGroup)
                         #return {'statusCode': 500,'headers': {'Content-Type': 'application/json'},'body': 'Error while adding AAD user to group' }    
                        # datetime object containing current date and time
                        now = datetime.now()
                        dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
                        print("date and time =", dt_string)
                        try:
                            # Now update dynamodb table with customerNotified='y' for the customerEmaill
                            responseDdb = table.update_item(
                                    Key={
                                        'email': email
                                        
                                    },
                                    #UpdateExpression='SET ccUserName = :val1 , ccPassword = :val2, loginDetailSent = :val3, approval = :val4',
                                    UpdateExpression='SET ccUserName = :val1 , ccPassword = :val2, loginDetailSent = :val3, approval = :val4, dateApproved = :val5',
                                    ExpressionAttributeValues={
                                        ':val1': ccUserName,
                                        ':val2' : ccPassword,
                                        ':val3' : 'y',
                                        ':val4' : 'y',
                                        ':val5' : dt_string
                                    }
                                )
                            allpass=True
                            print(responseDdb)
                            print("update dynamodb database success")
                            # Send email
                            sendEmail(ccUserName,ccPassword,fromEmail,toEmail,email)
                            postMessageToTeams(ccUserName,email,company,whatApp,whatLanguage,anythingElse)
                            return {'statusCode': 200,'headers': {'Content-Type': 'application/json'},'body': json.dumps('Request has been approved and user has been notified via email')  } 

                        except ClientError as e:
                            print(e)
                            return {'statusCode': 500,'headers': {'Content-Type': 'application/json'},'body': json.dumps('Internal Server Error')  } 



                    else:
                        print("Invalid email hash or this request already approved 1")
                        return {'statusCode': 500,'headers': {'Content-Type': 'application/json'},'body': json.dumps('Invalid email hash or this request already approved')  } 
                else:
                    print("Invalid Access Code")
                    return {'statusCode': 500,'headers': {'Content-Type': 'application/json'},'body': json.dumps('Invalid email hash or this request already approved')  } 
            else:
                print("Invalid Access Code")
                return {'statusCode': 500,'headers': {'Content-Type': 'application/json'},'body': json.dumps('Invalid email hash or this request already approved')  } 
        else:
            print("Invalid email hash or emailHash does not exists")
            return {'statusCode': 500,'headers': {'Content-Type': 'application/json'},'body': json.dumps('Invalid email hash or emailHash does not exists')  } 
    else:
        print("Invalid email hash or this request already approved 2")
        return {'statusCode': 500,'headers': {'Content-Type': 'application/json'},'body': json.dumps('Invalid email hash or this request already approved')  } 

    return {'statusCode': 200,'headers': {'Content-Type': 'application/json'},'body': json.dumps('Request has been approved and user has been notified via email')  } 


#lambda_handler ("d148d636fd22e838689edd5af68faac80cd63f55","-")

def sendEmail(ccUserName,ccPassword,fromEmail,toEmail,email):
    
    msg = MIMEMultipart('alternative')
    msg['Subject'] = "CloudAz - Stage: NextLabs CloudAz service - Login instructions"
    msg['From'] = fromEmail
    msg['To'] = toEmail

    html = """ <html>
        <head>
            <style>
                table {
                    border-collapse: collapse;
                }
                
                table, td, th {
                    border: 1px solid black;
                    padding:10px;
                }
    
                body {
                font-family: "Lato", "Lucida Grande", "Lucida Sans Unicode", Tahoma, Sans-Serif;
                }


            </style>
        </head>
        <body>
            <p>Thank you for signing up with NextLabs</p>

        <p>Your free trial of the NextLabs Cloud Authorization Service is now ready. </p>
        
        <p>
            Go to https://staging.cloudaz.net , click on the <strong>Login </strong> button to login with provided credentials. 
            <br>
            
        </p>
        <table>
    """
    html=html+'<tr><td style="background-color:#FF6101;color:white">Login URL </td>  <td><a href="https://staging.cloudaz.net  ">https://staging.cloudaz.net</a></td></tr>'
    html=html+'<tr><td style="background-color:#FF6101;color:white">Username </td>  <td>'+ccUserName+'</td></tr>'
    html=html+'<tr><td style="background-color:#FF6101;color:white">Password </td>  <td>'+ccPassword+'</td></tr>'
    
    
    html=html+"""
    </table>
    <br><br>
    """
    #html=html+'Help Center <a href="https://cloudaz.com/help/about_the_console.html" target="_top">https://cloudaz.com/help/about_the_console.html</a>.'
    html=html+'Help Center <a href="https://www.cloudaz.com/console/help-resources/getting-started" target="_top">https://www.cloudaz.com/console/help-resources/getting-started</a>.'

    html=html+'<br>If you have any questions, please email us at <a href="mailto:CloudAz-Support@nextlabs.com?Subject=CloudAz%20support" target="_top">CloudAz-Support@nextlabs.com</a> or call <a href="tel:18008983065">1-800-898-3065</a>.'


    html=html+"""
    <p>Welcome to NextLabs Cloud Authorization Service! </p>

    Thank you,<br>
    NextLabs, Inc. 

    </body>
    </html>
    """

    part2 = MIMEText(html, 'html')
    try:
        msg.attach(part2)
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login("admin@cloudaz.com", "sgjunjhxnqisfmwr")
        server.sendmail(fromEmail, toEmail, msg.as_string())
        server.quit()
        print("Sending login details to : " + email)

    except smtplib.SMTPException as e:
        print(e)   


def setStatus(statusCode, message):
    return {'statusCode': statusCode,'body': json.dumps(message)  } 


def postMessageToTeams(ccUserName,email,company,whatApp,whatLanguage,anythingElse):
    message = {
      "@context": "https://schema.org/extensions",
      "@type": "MessageCard",
      "themeColor": "64a837",
      "title": "Cloudaz stage new user sign up",
      "text": "**Request has been approved and user has been notified via email** \n\r UserName =" +ccUserName+ "\n\r Email =" +email+ "\n\r Company =" +company+ "\n\r **Questions with Answers** \n\r What type of applications? = " +whatApp+ "\n\r What programming languages? = " +whatLanguage+ "\n\r Anything else we should know or can help you to make the trial successful? = "+anythingElse
    }

    req = Request('https://outlook.office.com/webhook/fad8578e-3db4-4fd6-be9f-c480009dc0bd@9677f667-24d2-4a58-a8e2-941644600b04/IncomingWebhook/e2380fa7f1c74778a0d237b91f1ab563/b36e6ea6-7fbf-48b6-a5fa-c60375fecaa6', json.dumps(message).encode('utf-8'))
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted")
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)
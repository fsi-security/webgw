import time
from mitmproxy.script import concurrent
from mitmproxy import http
from urllib.parse import unquote
import json

allowed_domain_list_file = "allowlist.txt"
allowed_account_list_file = "allowaccount.txt"      
authenticate_root_url = "signin.aws.amazon.com/signin"
authenticate_root_action = "authenticateRoot"
authenticate_iam_url = "signin.aws.amazon.com/authenticate"
authenticate_iam_action = "iam-user-authentication"    

@concurrent
def request(flow):

    LOG_TAG = "request"
    requestHost = flow.request.host
    requestUrl = flow.request.url
    clientIP = getClientIP(flow.client_conn.address)
    customResponse = False
    customHeader = ""
    customBody = ""   

    if checkAllowedDomain(requestHost) == True:
        #허용된 도메인
        applog(LOG_TAG, f"[{getCurrentTime()}][ALLOW]{clientIP} -> {requestHost}")

        accountId = getAccountIdInUserInfo(getCookeyByKey(getHeaderByKey(flow, "Cookie"), "aws-userInfo"))
        # 쿠키에 어카운트 ID가 있을 경우 검증
        if accountId is not None:
            customResponse, customBody, customHeader = checkAllowedAccountByAccountId(flow, accountId)

        # signin url만 검증, root로 로그인
        if authenticate_root_url in requestUrl:
            customResponse, customBody, customHeader = checkAllowedAccountByRoot(flow)

        # signin url만 검증, iam user로 로그인
        elif authenticate_iam_url in requestUrl:
            customResponse, customBody, customHeader = checkAllowedAccountByIAM(flow)

        # cli url검증
        elif ".amazonaws.com" in requestUrl:
            customResponse, customBody, customHeader = checkAllowedAccountByConsole(flow)

    else:
        #허용되지 않은 도메인
        applog(LOG_TAG, f"[{getCurrentTime()}][DENY]{clientIP} -> {requestHost}")
        customResponse, customBody, customHeader = getDeniedDomainMessage(requestHost)        

    #CustomReponse 오버라이딩
    if customResponse == True:
        flow.response = http.Response.make(
            200,  # (optional) status code
            customBody,  # (optional) content
            customHeader  # (optional) headers
        )

def response(flow):

    LOG_TAG = "response"    
    # applog(LOG_TAG, f"[Response]{flow.response.text}")
    # applog(LOG_TAG, f"[Response]{flow.response.headers}")

def checkAllowedDomain(host):

    allowed_domain_list = open(allowed_domain_list_file, 'r').read().split('\n')
    for allowed_domain in allowed_domain_list:
        if allowed_domain.strip() == "":
            # 리스트에 blank 들어갔을 경우 allowlist가 동작하지 않는 것을 방지
            pass
        elif allowed_domain.startswith(".") == True and host.endswith(allowed_domain[1:]):
            return True
        elif allowed_domain == host:
            return True

    return False

def checkAllowedAccountByAccountId(flow, account_id):

    LOG_TAG = "account"
    clientIP = getClientIP(flow.client_conn.address)
    allowed_account = readAllowedToken('account')    

    if account_id in allowed_account:
        applog(LOG_TAG, f"[{getCurrentTime()}]{clientIP}:WEB:{account_id}:{flow.request.url}:ALLOW")
        return (False, "", "")
    else:
        applog(LOG_TAG, f"[{getCurrentTime()}]{clientIP}:WEB:{account_id}:{flow.request.url}:DENY")
        customResponse = True
        customBody = b'<ForbiddenError><error>Not Allowed.</error></ForbiddenError>'
        customHeader = {               
            "Server": "Server",
            "Date": "Tue, 14 Sep 2021 04:52:55 GMT",
            "Content-Length": "60",
            "x-amzn-RequestId": "fa95bc17-8e08-4ae1-88fe-0915960a00b0",
            "Strict-Transport-Security": "max-age=47304000; includeSubDomains",
            "Connection": "close"
        }            
        return (customResponse, customBody, customHeader)

def checkAllowedAccountByRoot(flow):

    LOG_TAG = "account"
    action, email, password = ("", "", "")
    clientIP = getClientIP(flow.client_conn.address)
    allowed_email = readAllowedToken('email')        

    # form item에서 필요한 정보 저장
    for key, value in flow.request.urlencoded_form.items():
        if key.lower() == "action":
            action = value
        elif key.lower() == "email":
            email = value
        elif key.lower() == "password":
            password = value

    #password 체크하는 이유는 email 로그인은 1.email검증 2.capcha검증 3.pw검증 순에서 3단계에 처리에서 에러 메세지를 처리할 수 있기 때문. 1에서는 메세지 처리 불가
    if action.lower() == authenticate_root_action.lower() and len(password) > 0: 
        # allow/deny 로깅을 위핸 inner if로 처리
        if email not in allowed_email:
            #deny log
            applog(LOG_TAG, f"[{getCurrentTime()}]{clientIP}:ROOT:{email}::DENY")
            customResponse = True
            customBody = b'{"state":"FAIL","properties":{"Message":"You can use only allowed email.","Title":"AUTHENTICATION FAILURE"}}'
            customHeader = {
                "Content-Security-Policy": "default-src 'none' https://aws.amazon.com https://*.signin.aws.amazon.com https://signin.aws.amazon.com 'unsafe-inline'; img-src 'self' data: https://*.signin.aws.amazon.com https://signin.aws.amazon.com https://opfcaptcha-prod.s3.amazonaws.com https://images-na.ssl-images-amazon.com https://d1.awsstatic.com https://internal-cdn.amazon.com https://media.amazonwebservices.com https://d36cz9buwru1tt.cloudfront.net https://d0.awsstatic.com; media-src 'self' https://*.signin.aws.amazon.com https://signin.aws.amazon.com https://media.amazonwebservices.com https://d36cz9buwru1tt.cloudfront.net https://opfcaptcha-prod.s3.amazonaws.com; script-src 'self' https://aws.amazon.com https://*.signin.aws.amazon.com https://signin.aws.amazon.com https://d1dgtfo2wk29o4.cloudfront.net/fwcim.js https://m.media-amazon.com https://l0.awsstatic.com https://images-na.ssl-images-amazon.com 'unsafe-eval' 'unsafe-inline'; style-src 'self' https://aws.amazon.com https://*.signin.aws.amazon.com https://signin.aws.amazon.com https://aws-signin-website-assets.s3.amazonaws.com https://l0.awsstatic.com https://images-na.ssl-images-amazon.com 'unsafe-inline'; report-uri /metrics/cspreport;",
                "Content-Type": "application/json;charset=utf-8",
                "Content-Security-Policy-Report-Only": "frame-ancestors 'self'; report-uri /metrics/cspreportonly;",
                "Server": "Server",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Transfer-Encoding": "chunked",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-UA-Compatible": "IE=Edge",
                "X-XSS-Protection": "1; mode=block"
            }

            return (customResponse, customBody, customHeader)
        else:
            #allow log
            applog(LOG_TAG, f"[{getCurrentTime()}]{clientIP}:ROOT:{email}::ALLOW")

    return (False, "", "")

def checkAllowedAccountByIAM(flow):

    LOG_TAG = "account"
    action, account, username = ("", "", "")
    clientIP = getClientIP(flow.client_conn.address)
    allowed_account = readAllowedToken('account')        

    for key, value in flow.request.urlencoded_form.items():
        if key.lower() == "action":
            action = value
        elif key.lower() == "account":
            account = value
        elif key.lower() == "username":
            username = value

    if action.lower() == authenticate_iam_action.lower() and len(username) > 0: # username은 추후 세부 접근통제를 위해
        if account not in allowed_account:
            #deny log
            applog(LOG_TAG, f"[{getCurrentTime()}]{clientIP}:IAM:{account}:{username}:DENY")
            customResponse = True
            customBody = b'{"state":"FAIL","properties":{"result":"FAILURE","text":"You can use only allowed account."}}'
            customHeader = {                    
                "Accept": "application/json, text/plain, */*",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
                "Connection": "keep-alive",
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                "Host": "signin.aws.amazon.com",
                "Origin": "https://signin.aws.amazon.com",
                'sec-ch-ua': '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
                "sec-ch-ua-mobile": "?0",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36"
            }            
            return (customResponse, customBody, customHeader)
        else:
            #allow log
            applog(LOG_TAG, f"[{getCurrentTime()}]{clientIP}:IAM:{account}:{username}:ALLOW")

    return (False, "", "")

def checkAllowedAccountByConsole(flow):

    LOG_TAG = "account"
    accessKey = ""
    clientIP = getClientIP(flow.client_conn.address)
    allowed_accesskey = readAllowedToken('accesskey')    

    user_agent = getHeaderByKey(flow, "User-Agent").strip()    
    authorization = getHeaderByKey(flow, "Authorization")
    if (user_agent.upper().startswith("AWS-CLI") or user_agent.upper().startswith("BOTO3")) and authorization is not None:

        accessKey = getAccessKey(authorization)

        if accessKey not in allowed_accesskey:                
            #deny log
            applog(LOG_TAG, f"[{getCurrentTime()}]{clientIP}:CLI:{accessKey}:{flow.request.url}:DENY")
            customResponse = True
            customBody = b'<?xml version="1.0" encoding="UTF-8"?><Error><Code>NotAllowedAccessKeyId</Code><Message>The AWS Access Key Id you provided does not allowed in our systems.</Message><AWSAccessKeyId></AWSAccessKeyId><RequestId></RequestId><HostId></HostId></Error>'
            customHeader = {}
            return (customResponse, customBody, customHeader)
        else:
            #allow log
            applog(LOG_TAG, f"[{getCurrentTime()}]{clientIP}:CLI:{accessKey}:{flow.request.url}:ALLOW")

    return (False, "", "")

def getDeniedDomainMessage(request_host):

    customResponse = True                
    customBodyStr = f'<html><head></head><body><b><font color="#FF0000">{request_host}</font></b> is not allowed.</body></html>'
    customBody = customBodyStr.encode(encoding = "utf-8")        
    customHeader = {}

    return (customResponse, customBody, customHeader)

def readAllowedToken(token):

    tokenlist = []
    itemlist = open(allowed_account_list_file, 'r').read().split('\n')
    findToken = f"[{token}]"

    token_index = itemlist.index(findToken)
    for i in range(token_index, len(itemlist)):
        if itemlist[i].strip() == "":
            break
        elif itemlist[i].strip() == findToken or itemlist[i].startswith("#"):
            pass
        else:
            tokenlist.append(itemlist[i].strip())

    return tokenlist

def getHeaderByKey(flow, findkey):
    for key, value in flow.request.headers.items(): 
        if key.upper() == findkey.upper() and len(value) > 0:  
            return value

    return None

def getAccountIdInUserInfo(userInfo):
    if userInfo is not None:                    
        decoded_userInfo = unquote(userInfo)
        json_data = json.loads(decoded_userInfo)
        user_arn = json_data['arn']        
        if user_arn is not None:
            items = user_arn.split(':')
            # 데이터형식: arn:aws:iam::{ACCOUNT_ID}:root
            if len(items) > 4:
                return items[4]

    return None

def getCookeyByKey(cookie, findkey):
    if cookie is not None:
        items = cookie.split(';')
        for item in items:
            idx_delimiter = item.find("=")
            if idx_delimiter >= 0:         
                item_key = item[:idx_delimiter].strip()
                item_value = item[idx_delimiter + 1:].strip()

                if item_key == findkey:
                    return item_value

    return None

def getAccessKey(auth_str):

    findToken = "Credential="
    idx_s = auth_str.find(findToken)
    idx_e = auth_str.find("/", idx_s)
    if idx_s < 0 or idx_e < 0:
        return ""                

    return auth_str[idx_s + len(findToken):idx_e]

def applog(file, msg):
    ext = "log"
    f = open(f"{file}_{getLoggingFileTime()}.{ext}", 'a', encoding='utf-8')
    f.write(f"{msg}\n")
    f.close()

def getClientIP(client_address):

    client_ipv4 = ""
    if len(client_address) > 0:
        ip_info = client_address[0].split(':')
        if len(ip_info) > 0:
            if len(ip_info) > 3:                
                client_ipv4 = ip_info[3]
            else:
                client_ipv4 = ip_info[0]               

    return client_ipv4

def getLoggingFileTime():    
    now = time.localtime()
    return "%04d%02d%02d%02d" % (now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour)

def getCurrentTime():    
    now = time.localtime()
    return "%04d/%02d/%02d %02d:%02d:%02d" % (now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec)

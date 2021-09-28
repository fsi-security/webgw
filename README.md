# 오픈소스를 이용한 AWS Management Console 어카운트ID  접근제어

#### 주의사항: 프록시를 통한 AWS Management Console 어카운트 ID 접근제어는 AWS에서 공식적으로 가이드하는 방식은 아닙니다. 어카운트 ID가 포함된 헤더 정보는 언제든 변경될 수 있으며, 이로인한 어카운트 ID 접근제어 누락은 이 코드를 사용하는 당사자에게 책임이 있습니다. 제공된 샘플은 프록시를 통한 어카운트 ID 접근제어에 대한 이해를 돕기 위한 것으로 각자의 사용 환경에 맞도록 접근제어 규칙이 반영되어야 합니다

## 1.  mitmproxy 설치 및 실행

### 1-1) 윈도우
```
1. mitmproxy 설치
https://mitmproxy.org/
Download Windows Installer

2. mitmproxy 디폴트 인증서 설치 경로
%HomePath%\.mitmproxy

(참고) python3는 설치하지 않아도 mitmproxy 실행에 문제 
```

### 1-2) 맥
```
1. mitmproxy 설치
1-1) brew가 설치된 경우
brew install mitmproxy

1-2) python3가 설치된 경우
sudo pip3 install mitmproxy

## 2. mitmproxy 디폴트 인증서 설치 경로
~\.mitmproxy
```

## 2. 클라이언트 인증서 설치
### 2-1) 인증서 다운로드
프록시 설정 상태로 http://mitm.it/ 접속
![cert01](https://user-images.githubusercontent.com/90693041/133710390-1e838fb2-79a6-42b6-bcf1-823ff6f9f47b.png)
### 2-2) 윈도우에서 클라이언트 인증서 설치
![cert02](https://user-images.githubusercontent.com/90693041/133710395-ac1423e0-4cd1-4476-b0ef-6ede99096b44.png)

```
(설치 명령)
certutil.exe -addstore -user -f "Root" mitmproxy-ca-cert.pem
```
![cert_win_01](https://user-images.githubusercontent.com/90693041/133710398-b53b1ba9-d465-4009-8831-c5cd76cc38dc.png)
![cert_win_02](https://user-images.githubusercontent.com/90693041/133710407-c92f0376-d2bd-4ae7-8f95-c2951357edb7.png)

```
(인증서 설치 확인)
certmgr
```
![cert_win_03](https://user-images.githubusercontent.com/90693041/133710410-21077ea3-8e82-42d4-b728-5666ef0a4a3c.png)


### 2-3) 맥에서 클라이언트 인증서 설치
![cert_mac_01](https://user-images.githubusercontent.com/90693041/133710416-8ca31968-1d1b-45d2-91c5-23f5ff34b911.png)

mitmproxy-ca-cert.pem 더블클릭
```
파인더에서 숨김파일 표시 shift + command + .
```

![cert_mac_02](https://user-images.githubusercontent.com/90693041/133710418-3423c7bb-504e-4277-91ab-59acb9eb5f8b.png)

![cert_mac_03](https://user-images.githubusercontent.com/90693041/133710424-556f0e48-fdef-481a-a940-1a30c6574129.png)

![cert_mac_04](https://user-images.githubusercontent.com/90693041/133710433-39630300-c3c6-4e0e-af20-26e4fd986a6b.png)

![cert_mac_05](https://user-images.githubusercontent.com/90693041/133710441-7cde45a1-9a97-4855-9117-da1597d6159a.png)

![cert_mac_06](https://user-images.githubusercontent.com/90693041/133710446-febad9e3-6534-4dce-99c9-748b47e4b49a.png)

![cert_mac_07](https://user-images.githubusercontent.com/90693041/133710450-7d32067e-65eb-433e-8b60-9001e23a7c6e.png)

```
(설치 명령)
sudo security add-trusted-cert -d -p ssl -p basic -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem
```


## 3.  클라이언트에서 mitmproxy 연결

### 3-1) 브라우저(크롬)에서 프록시 연결
크롬 Extensions에서 Proxy SwitchySharp 설치
https://chrome.google.com/webstore/detail/proxy-switchysharp/dpplabbmogkhghncfbfdeeokoefdjegm

![proxy01](https://user-images.githubusercontent.com/90693041/133710456-09756393-940c-416a-b737-c26a9a18332a.png)

Proxy SwitchySharp에서 mitmproxy 연결 설정 정보 입력

![proxy02](https://user-images.githubusercontent.com/90693041/133710460-25beea6e-c192-4604-b489-4954268b93d7.png)

mitmproxy 프록시 연결 설정 

![proxy03](https://user-images.githubusercontent.com/90693041/133710469-00c4e677-848d-4f92-9703-3ed085db9612.png)

### 3-2) 커맨드창에서 프록시 연결
윈도우에서 설정
```
set HTTP_PROXY=http://127.0.0.1:8080
set HTTPS_PROXY=http://127.0.0.1:8080
set AWS_CA_BUNDLE=mitmproxy-ca-cert.pem
```

맥에서 설정
```
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export AWS_CA_BUNDLE=mitmproxy-ca-cert.pem
```

### 3-3)Custom 인증서 생성
```
$ openssl genrsa -out cert.key 2048 

# (Specify the mitm domain as Common Name, e.g. \*.google.com) 
$ openssl req -new -x509 -key cert.key -out cert.crt 
Country Name (2 letter code) [XX]:KR 
State or Province Name (full name) []:Seoul 
Locality Name (eg, city) [Default City]:GangNam 
Organization Name (eg, company) [Default Company Ltd]:MyCompany 
Organizational Unit Name (eg, section) []:IT 
Common Name (eg, your name or your server's hostname) []:mydomain.com
Email Address []:admin@mydomain.com

$ cat cert.key cert.crt > mitmproxy-ca.pem

$ cat cert.crt > mitmproxy-ca-cert.pem

mitmproxy-ca.pem파일은 private key와 인증서를 포함하며, 다음과 같은 형식으로 구성되어 있음
-----BEGIN CERTIFICATE-----
-----END RSA PRIVATE KEY----- 
-----BEGIN CERTIFICATE----- 
-----END CERTIFICATE----- 

mitmproxy-ca-cert.pem은 인증서 파일로 다음과 같은 형식으로 구성되어 있음
-----BEGIN CERTIFICATE----- 
-----END RSA PRIVATE KEY-----
```

## 4. mitmproxy 실행
```
4-1) CLI기반 interactive mode
$ mitmproxy

4-2) WEB기반 GUI
$ mitmweb

4-3) non-interactive terminal output
mitmdump

4-4) addon 실행
mitmdump -s hello.py
```

## 5. mitmproxy 동작 방식 이해
![mitmproxy01](https://user-images.githubusercontent.com/90693041/133710473-f1bcdc51-8ddf-42be-8c53-c0facc420c46.png)
https://docs.mitmproxy.org/stable/concepts-modes/

## 6. mitmproxy addon 개발
### 6-1) addon 샘플
```
# hello.py
from mitmproxy import http
from mitmproxy.script import concurrent

#concurrent는 non-blocking mode
@concurrent
def request(flow):                  
    host = flow.request.host
    applog ("DEBUG", f"[REQUEST]{host}")

    #Reponse 오버라이딩
    if host == "www.google.com":
        flow.response = http.Response.make(
            200,  # (optional) status code
            "<html><head></head><body>blocked</body></html>",  # (optional) content
            {}  # (optional) headers
        )

def response(flow):
    host = flow.request.host
    content = flow.response.content
    if host == "www.google.com":
        applog ("DEBUG", f"[RESPONSE]{content}")

def applog(file, msg):
    ext = "log"
    f = open(f"{file}.{ext}", 'a', encoding='utf-8')
    f.write(f"{msg}\n")
    f.close()
```
https://docs.mitmproxy.org/stable/addons-examples/

### 6-2) request 트래픽에서 확인할 수 있는 주요 정보

```
flow.request.host                    #호스트: String
flow.request.url                     #전체 URL: String
flow.request.path                    #URI PATH: String
flow.request.query                   #파라미터: Dictionary
flow.request.headers                 #헤더: Dictionary
flow.request.content                 #컨텐츠: String
flow.request.urlencoded_form         #컨텐츠: Dictionary
flow.client_conn.address             #클라이언트 IP:  List
```

## 7. AWS Management Console 트래픽 분석
```
<WEB>
Root
(전처리)
https://signin.aws.amazon.com/signin 
email: my@email.com
(본처리)
https://signin.aws.amazon.com/mfa 
action: authenticateRoot 
email: my@email.com

IAM 
https://signin.aws.amazon.com/authenticate 
action: iam-user-authentication 
account: 123412341234 
username: awsstudent

<AWS CLI>
(b'Host', b's3.ap-northeast-2.amazonaws.com'), 
(b'Accept-Encoding', b'identity'), 
(b'User-Agent', b'aws-cli/1.20.26 Python/3.6.0 Windows/10 botocore/1.21.26'), 
(b'X-Amz-Date', b'20210914T062657Z'), 
(b'X-Amz-Content-SHA256', b'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), 
(b'Authorization', b'AWS4-HMAC-SHA256 Credential=AKIA1234567890ABCDEFG/20210914/ap-northeast-2/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=892396b204609be3ece9269a3ce8ddfc995f9f8a61391ac758262ebef030e208')]]

<Boto3 - Python>
(b'Host', b's3.ap-northeast-2.amazonaws.com'), 
(b'Accept-Encoding', b'identity'), 
(b'User-Agent', b'Boto3/1.18.41 Python/3.9.7 Windows/10 Botocore/1.21.41'), 
(b'X-Amz-Date', b'20210914T062605Z'), 
(b'X-Amz-Content-SHA256', b'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), 
(b'Authorization', b'AWS4-HMAC-SHA256 Credential=AKIA1234567890ABCDEFG/20210914/ap-northeast-2/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=9de33ae635a0fc9eee86ab5fb4da3dd83d37656549144cd1be33131c32f42d24')
```


## 8. 샘플코드
허용되지 않은 도메인 또는 IP로 접근 했을 때 Remote 서버로 데이터가 전송되지 않는 것에 대한 검증 과정 필수
테스트 WEB서버의 Access 로그를 통해 확인할 수 있음

### 8-1) webgw.py
https://github.com/fsi-security/webgw/blob/main/webgw.py
```
AWS Management Console 어카운트ID 접근제어 샘플
```

### 8-2) allowaccount.txt
https://github.com/fsi-security/webgw/blob/main/allowaccount.txt
```
각 세그먼트는 한 라인을 하나의 아이템으로 인식하며, 빈 문자열로 구분

[email]
Root account 이메일

[account]
Root account id

[accesskey]
Access Key
```

### 8-3) allowlist.txt
https://github.com/fsi-security/webgw/blob/main/allowlist.txt
```
한 라인에 하나의 도메인 입력
- 시작 문자가 .일 경우 와일드카드 방식으로 처리되며, 해당 도메인이 포함된 host 허용
- 시작 문자가 .이 아닐 경우 도메인과 동일한 host 허용
```

## 9. Custom Response 처리
![console01](https://user-images.githubusercontent.com/90693041/133710479-5b20a38d-c47f-4fd8-a8ac-4c1817868d80.png)
![console02](https://user-images.githubusercontent.com/90693041/133710481-9755704a-506e-489c-bec1-56714adf9841.png)


## 10. 아마존리눅스에서 mitmrpoxy 설치 및 webgw.py 실행
```
1. python3 설치 확인
python3 -V

2. mitmproxy 설치
pip3 install mitmproxy

3. webgw 가져오기

4. webgw 실행
nohup mitmdump --set block_global=false -s webgw.py 1> /dev/null 2>&1 &

(인증서 폴더 지정)
nohup mitmdump --set block_global=false --set confdir=./cert_dir -s webgw.py &

--set confdir 를 지정하지 않으면, .mitmproxy 폴더에서 인증서 찾음
--set confdir에서 mitmproxy-ca-cert.pem 파일이 없으면 자동으로 생성함

5. Request 로그 확인
tail -f request.log 

6. Audit 로그 확인
tail -f account.log
```

## 11. 상용 솔루션 현황
https://www.mcafee.com/enterprise/ko-kr/products/web-gateway.html

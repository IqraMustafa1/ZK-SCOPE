#correct commands:
Place this canton.conf file in canton folder bin then run commands 
(canton {

  parameters {
    non-standard-config = yes
  }

  features {
    enable-testing-commands = yes
  }

  participants {
    local {
      storage.type = memory

      admin-api {
        address = "127.0.0.1"
        port    = 6865
      }

      ledger-api {
        address = "127.0.0.1"
        port    = 6866
      }
    }
  }

  domains {
    myLocalDomain {
      init {
        domain-parameters {
          protocol-version = 7
        }
      }

      storage.type = memory

      admin-api {
        address = "127.0.0.1"
        port    = 7500
      }

      public-api {
        address = "127.0.0.1"
        port    = 7575
      }
    }
  }

  # Optional bootstrap script:
  # bootstrap = "bootstrap.canton"
}
)
---------------------------
1. Run canton; 
2. Run daml start
3. Upload daml script (run commands)
4. Run flask
5. Run http_trigger.py (listening bridge)
6. Test 
#canton: 
store canton.conf in bin folder of canton
then run this command to start canton:

1. #C:\canton\canton\bin>canton.bat -c canton.conf
participants.local.head.domains.connect_local(domains.local.head)
participants.local.head.domains.is_connected(domains.local.head)


participants.local.head.dars.upload("""C:\Users\mustafai\Desktop\ZK-SCOPE\SCOPE-Framework-main\SCOPE-Framework-main\.daml\dist\test-0.0.1.dar""")
participants.local.head.dars.list()

2. #then On the server:
daml json-api --ledger-host localhost --ledger-port 6866 --http-port 7575
OR-----------daml server on seperate shell------------
2 $env:DAML_JSON_HTTP_AUTH_JWT_HS256_HS_SECRET = 'my-super-secret'>> daml json-api --ledger-host localhost --ledger-port 6866 --http-port 7575
#USE THIS COMMAND
 daml json-api `
   --ledger-host localhost `
  --ledger-port 6866 `
  --http-port 7575 `
  --allow-insecure-tokens
#---------------daml commands-----------on parallel seperate shell----------
3. #After running this: execute daml scripts:
cd "C:\Users\mustafai\Desktop\SCOPE-Framework-main\SCOPE-Framework-main"

daml ledger upload-dar --host localhost --port 6866 ".\.daml\dist\test-0.0.1.dar"

daml script --dar .daml\dist\test-0.0.1.dar --script-name Main:setup --ledger-host localhost --ledger-port 6866
daml script --dar .daml\dist\test-0.0.1.dar --script-name Main:testList  --ledger-host localhost --ledger-port 6866
daml script --dar .daml\dist\test-0.0.1.dar --script-name RunAll:runAll --ledger-host localhost --ledger-port 6866


#meplz
$env:DAML_JSON_HTTP_AUTH_JWT_HS256_HS_SECRET = 'my-super-secret'>> daml json-api --ledger-host localhost --ledger-port 6866 --http-port 7575
--------------Run client side seperate shell------------------
4. py -3 flask_app.py 
5. py -3 generate_jwt.py > token.txt
6. py -3 http_trigger.py


#To find Pckage id run these:-----------------PACKAGEID----------------
daml damlc inspect-dar ".daml\dist\test-0.0.1.dar"


#SEE DAML PACKAGE ID-------------SMALL
Invoke-RestMethod `
  -Method Get `
  -Uri http://localhost:7575/v1/packages `
  -Headers $headers
-------------------------------------TEST POWERSHELL-------------------------------
7. Flask ⇆ JSON‑API ⇆ ledger
-------------------To test flask talking to Json API------
RUN This Script 

powershell -ExecutionPolicy Bypass -File .\run_all.ps1

------------Or commands run yourself--------------
$jwt = Get-Content token.txt
Invoke-RestMethod -Uri "http://localhost:7575/v1/query" `
  -Method Post `
  -Headers @{ Authorization="Bearer $jwt"; "Content-Type"="application/json" } `
  -Body '{"templateIds":["914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:LogRequest"],"query":{}}'
#push to flask ps1
# (re‑use the same $jwt you loaded)
# Send one fake log
Invoke-RestMethod -Uri "http://localhost:5000/log_batch_activity" `
  -Method Post `
  -Headers @{"Content-Type"="application/json"} `
  -Body '{
    "logs":[
      {
        "operator_id":"test-op",
        "operation":"unit-test",
        "client_public_key":"dummy-pubkey",
        "message_length":123,
        "execution_time_ms":45
      }
    ]
  }' | ConvertTo-Json

  #requery-daml ps1
  Invoke-RestMethod -Uri "http://localhost:7575/v1/query" `
  -Method Post `
  -Headers @{ Authorization="Bearer $jwt"; "Content-Type"="application/json" } `
  -Body '{"templateIds":["914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:LogRequest"],"query":{}}' | ConvertTo-Json


powershell -ExecutionPolicy Bypass -File .\exercise.ps1
PS--------------------------------END--------------WORKED DAML AND FLASK API TALKING

#test flask enpoint:

1st Method:
 curl.exe -v -X POST "http://localhost:5000/log_batch_activity" -H "Content-Type: application/json" -d "{\"logs\":[{\"operator_id\":\"test-operator\",\"operation\":\"unit-test\",\"client_public_key\":\"dummy-key\",\"message_length\":42,\"execution_time_ms\":123}]}"
curl.exe -v -X POST "http://localhost:5000/log_batch_activity" -H "Content-Type: application/json" -d "{\"logs\":[{\"operator_id\":\"test-operator\",\"operation\":\"unit-test\",\"client_public_key\":\"dummy-key\",\"message_length\":42,\"execution_time_ms\":123}]}"
2nd Method----
py -3 send_requests.py

----------------To kill port service-if in use (powershell commands)------------
netstat -a -n -o | findstr :7575
netstat -ano | findstr :6865
taskkill /PID  13860 /F
--------------------------------------------CURL COMMAND OR USE ABOVE PS DEPEND ON U----------------
#Curl command run in curl folder from shell:
curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJsZWRnZXJJZCI6ImxvY2FsIiwiYXBwbGljYXRpb25JZCI6ImFwcCIsImFjdEFzIjpbIk9wZXJhdG9yIl19." ^
     -H "Accept: application/json" ^
     http://localhost:7575/v1/packages

     daml damlc inspect-dar .daml\dist\test-0.0.1.dar
     curl -X POST http://localhost:7575/v1/query ^
     -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJsZWRnZXJJZCI6ImxvY2FsIiwiYXBwbGljYXRpb25JZCI6ImFwcCIsImFjdEFzIjpbIk9wZXJhdG9yIl19." ^
     -H "Content-Type: application/json" ^
     -d "{\"templateIds\": [\"914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:BrokerContract\"]}"
   
     curl -X POST http://localhost:7575/v1/query ^
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJsZWRnZXJJZCI6ImxvY2FsIiwiYXBwbGljYXRpb25JZCI6ImFwcCIsImFjdEFzIjpbIk9wZXJhdG9yIl19." ^
  -H "Content-Type: application/json" ^
  -d "{\"templateIds\": [\"914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:BrokerContract\"], \"query\": {}}"

  curl -X POST http://localhost:7575/v1/query ^
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJsZWRnZXJJZCI6ImxvY2FsIiwiYXBwbGljYXRpb25JZCI6ImFwcCIsImFjdEFzIjpbIk9wZXJhdG9yIl19." ^
  -H "Content-Type: application/json" ^
  -d "{\"templateIds\": [\"914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:BrokerContract\"], \"query\": {}}"

  curl -X POST http://localhost:7575/v1/fetch ^
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJsZWRnZXJJZCI6ImxvY2FsIiwiYXBwbGljYXRpb25JZCI6ImFwcCIsImFjdEFzIjpbIk9wZXJhdG9yIl19." ^
  -H "Content-Type: application/json" ^
  -d "{\"templateId\": \"test-0.0.1:Main:BrokerContract\", \"key\": \"Operator::1220ddda03a96a124468d9eb604676c53f3500e52c13a0ec606a7c91e75e6e69e961\"}"

  curl -X POST http://localhost:7575/v1/fetch ^
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJsZWRnZXJJZCI6ImxvY2FsIiwiYXBwbGljYXRpb25JZCI6ImFwcCIsImFjdEFzIjpbIk9wZXJhdG9yIl19." ^
  -H "Content-Type: application/json" ^
  -d "{ \"templateId\": \"914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:BrokerContract\", \"key\": \"Operator::1220ddda03a96a124468d9eb604676c53f3500e52c13a0ec606a7c91e75e6e69e961\" }"


  C:\curl\curl>curl -X POST http://localhost:7575/v1/query ^
More?   -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJsZWRnZXJJZCI6ImxvY2FsIiwiYXBwbGljYXRpb25JZCI6ImFwcCIsImFjdEFzIjpbIk9wZXJhdG9yIl19." ^
More?   -H "Content-Type: application/json" ^
More?   -d "{ \"templateIds\": [\"914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:BrokerContract\"] }"
{"result":[],"status":200}

curl.exe -v -X POST "http://localhost:7575/v1/query" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3lvdXIuYXV0aC5wcm92aWRlci8iLCJzdWIiOiJ1c2VyLTEyMyIsImF1ZCI6Impzb24tYXBpIiwiZXhwIjoxNzQ1MzQ3ODI4LCJodHRwczovL2RhbWwuY29tL2xlZGdlci1hcGkiOnsiYWN0QXMiOlsiT3BlcmF0b3I6MTIyMGRkZGEwM2E5NmExMjQ0NjhkOWViNjA0Njc2YzUzZjM1MDBlNTJjMTNhMGVjNjA2YTdjOTFlNzVlNmU2OWU5NiJdLCJsZWRnZXJJZCI6ImxvY2FsIiwiYXBwbGljYXRpb25JZCI6ImFwcCJ9fQ.WEjK8PtMZlsT5Bfzez9jiumAtTbnNtaimIk-sdyopBc" -H "Content-Type: application/json" -d "{\"templateIds\":[\"914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:LogRequest\"],\"query\":{}}"

$headers = @{
  "Authorization" = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3lvdXIuYXV0aC5wcm92aWRlci8iLCJzdWIiOiJ1c2VyLTEyMyIsImF1ZCI6Impzb24tYXBpIiwiZXhwIjoxNzQ1MzUzMzkxLCJodHRwczovL2RhbWwuY29tL2xlZGdlci1hcGkiOnsiYWN0QXMiOlsiT3BlcmF0b3I6OjEyMjA3MWQ4Mjk0MmZhOTEwNDVhM2IyYWU3ZTFhNmU4MWRjMmUyNDQyY2YzZjUzNzdhZTdlNWFlNzZkMWU5NmQ0NjVjIl0sImxlZGdlcklkIjoibG9jYWwiLCJhcHBsaWNhdGlvbklkIjoiYXBwIn19.zvrh32taWNIeWMyRckiTjAaczEcu7ZCdhc2VoQ7SpkA."
  "Content-Type"  = "application/json"
}




#Query LOG Contracts:
curl.exe -v -X POST "http://localhost:7575/v1/query" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3lvdXIuYXV0aC5wcm92aWRlci8iLCJzdWIiOiJ1c2VyLTEyMyIsImF1ZCI6Impzb24tYXBpIiwiZXhwIjoxNzQ1MzQ3ODI4LCJodHRwczovL2RhbWwuY29tL2xlZGdlci1hcGkiOnsiYWN0QXMiOlsiT3BlcmF0b3I6MTIyMGRkZGEwM2E5NmExMjQ0NjhkOWViNjA0Njc2YzUzZjM1MDBlNTJjMTNhMGVjNjA2YTdjOTFlNzVlNmU2OWU5NiJdLCJsZWRnZXJJZCI6ImxvY2FsIiwiYXBwbGljYXRpb25JZCI6ImFwcCJ9fQ.WEjK8PtMZlsT5Bfzez9jiumAtTbnNtaimIk-sdyopBc" -H "Content-Type: application/json" -d "{\"templateIds\":[\"914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:LogRequest\"],\"query\":{}}"
curl.exe -v -X POST "http://localhost:7575/v1/query" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3lvdXIuYXV0aC5wcm92aWRlci8iLCJzdWIiOiJ1c2VyLTEyMyIsImF1ZCI6Impzb24tYXBpIiwiZXhwIjoxNzQ1MzQ3ODI4LCJodHRwczovL2RhbWwuY29tL2xlZGdlci1hcGkiOnsiYWN0QXMiOlsiT3BlcmF0b3I6MTIyMGRkZGEwM2E5NmExMjQ0NjhkOWViNjA0Njc2YzUzZjM1MDBlNTJjMTNhMGVjNjA2YTdjOTFlNzVlNmU2OWU5NiJdLCJsZWRnZXJJZCI6ImxvY2FsIiwiYXBwbGljYXRpb25JZCI6ImFwcCJ9fQ.WEjK8PtMZlsT5Bfzez9jiumAtTbnNtaimIk-sdyopBc" -H "Content-Type: application/json" -d "{\"templateIds\":[\"914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:LogRequest\"],\"query\":{}}"
curl.exe -v -X POST "http://localhost:7575/v1/create" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3lvdXIuYXV0aC5wcm92aWRlci8iLCJzdWIiOiJ1c2VyLTEyMyIsImF1ZCI6Impzb24tYXBpIiwiZXhwIjoxNzQ1MzQ3ODI4LCJodHRwczovL2RhbWwuY29tL2xlZGdlci1hcGkiOnsiYWN0QXMiOlsiT3BlcmF0b3I6MTIyMGRkZGEwM2E5NmExMjQ0NjhkOWViNjA0Njc2YzUzZjM1MDBlNTJjMTNhMGVjNjA2YTdjOTFlNzVlNmU2OWU5NiJdLCJsZWRnZXJJZCI6ImxvY2FsIiwiYXBwbGljYXRpb25JZCI6ImFwcCJ9fQ.WEjK8PtMZlsT5Bfzez9jiumAtTbnNtaimIk-sdyopBc" -H "Content-Type: application/json" -d "{\"templateId\":\"914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:LogRequest\",\"payload\":{\"logData\":\"{\\\"foo\\\":123}\",\"endpoint\":\"http://localhost:5000/log_batch_activity\"}}"
#new query working to test flask and daml
curl.exe -v -X POST "http://localhost:7575/v1/create" ^
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3lvdXIuYXV0aC5wcm92aWRlci8iLCJzdWIiOiJ1c2VyLTEyMyIsImF1ZCI6Impzb24tYXBpIiwiZXhwIjoxNzQ1MzQ3ODI4LCJodHRwczovL2RhbWwuY29tL2xlZGdlci1hcGkiOnsiYWN0QXMiOlsiT3BlcmF0b3I6MTIyMGRkZGEwM2E5NmExMjQ0NjhkOWViNjA0Njc2YzUzZjM1MDBlNTJjMTNhMGVjNjA2YTdjOTFlNzVlNmU2OWU5NiJdLCJsZWRnZXJJZCI6ImxvY2FsIiwiYXBwbGljYXRpb25JZCI6ImFwcCJ9fQ.WEjK8PtMZlsT5Bfzez9jiumAtTbnNtaimIk-sdyopBc" ^
  -H "Content-Type: application/json" ^
  -d "{\"templateId\":\"914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:LogRequest\",\"payload\":{\"operator\":\"Operator\",\"logData\":\"{\\\"foo\\\":123}\",\"endpoint\":\"http://localhost:5000/log_batch_activity\"}}"

curl.exe -v -X POST "http://localhost:7575/v1/query" ^
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3lvdXIuYXV0aC5wcm92aWRlci8iLCJzdWIiOiJ1c2VyLTEyMyIsImF1ZCI6Impzb24tYXBpIiwiZXhwIjoxNzQ1MzQ3ODI4LCJodHRwczovL2RhbWwuY29tL2xlZGdlci1hcGkiOnsiYWN0QXMiOlsiT3BlcmF0b3I6MTIyMGRkZGEwM2E5NmExMjQ0NjhkOWViNjA0Njc2YzUzZjM1MDBlNTJjMTNhMGVjNjA2YTdjOTFlNzVlNmU2OWU5NiJdLCJsZWRnZXJJZCI6ImxvY2FsIiwiYXBwbGljYXRpb25JZCI6ImFwcCJ9fQ.WEjK8PtMZlsT5Bfzez9jiumAtTbnNtaimIk-sdyopBc" ^
  -H "Content-Type: application/json" ^
  -d "{\"templateIds\":[\"914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:LogRequest\"],\"query\":{}}"


#powershell: 
powershell -ExecutionPolicy Bypass -File .\exercise.ps1

for public key:

C:\curl\curl>curl http://localhost:5000/get_operator_public_key
{
  "public_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VuAyEAx1bdlFrj4Bqdti3hnyyr6SAtJpcYQpGcfAffpYKo+gE=\n-----END PUBLIC KEY-----\n"
}

#generate ui
daml codegen js .daml\dist\test-0.0.1.dar -o ui
#to see codegen results
Get-ChildItem ..\ui\daml -Recurse -File |
  Select-Object FullName
#FINAL
curl.exe -v -X POST "http://localhost:7575/v1/create" `
  -H "Authorization: Bearer $(Get-Content token.txt)" `
  -H "Content-Type: application/json" `
  -d '{
    "templateId":"914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:BrokerContract",
    "payload":{
      "operator":"Operator",
      "edgeNodes":[["EdgeNode1","2025-04-22T17:56:43.239267Z"]],
      "iotDevices":[["IoTDevice1","PK1"]],
      "cachedValidNodes":[["EdgeNode1","2025-04-22T17:56:43.239267Z"]],
      "validUntil":"2025-04-22T18:56:43.239267Z"
    }
  }'

#SEE FLASK PUBLIC KEY

curl.exe -v ^
  -X GET http://localhost:5000/get_operator_public_key ^
  -H "Content-Type: application/json"

  #POST LOGs to Flask
  curl.exe -v ^
  -X POST http://localhost:5000/log_batch_activity ^
  -H "Content-Type: application/json" ^
  -d "{\"logs\":[{\"operator_id\":\"test-op\",\"operation\":\"ping\",\"client_public_key\":\"pubkey\",\"message_length\":3,\"execution_time_ms\":10}]}"

#fetch on the ledger 
curl.exe -v ^
  -X POST http://localhost:7575/v1/query ^
  -H "Authorization: Bearer <YOUR_JWT_HERE>" ^
  -H "Content-Type: application/json" ^
  -d "{\"templateIds\":[\"914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:LogRequest\"],\"query\":{}}"
#my token was:
curl.exe -v ^
  -X POST http://localhost:7575/v1/query ^
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3lvdXIuYXV0aC5wcm92aWRlci8iLCJzdWIiOiJ1c2VyLTEyMyIsImF1ZCI6Impzb24tYXBpIiwiZXhwIjoxNzQ1MzUyMDE5LCJodHRwczovL2RhbWwuY29tL2xlZGdlci1hcGkiOnsiYWN0QXMiOlsiT3BlcmF0b3IiOjoxMjIwNzFkODI5NDJmYTkxMDQ1YTNiMmFlN2UxYTZlODFkYzJlMjQ0MmNmM2Y1Mzc3YWU3ZTVhZTc2ZDFlOTZkNDY1YyJdLCJsZWRnZXJJZCI6ImxvY2FsIiwiYXBwbGljYXRpb25JZCI6ImFwcCJ9fQ.VoKHZ9MDwzQ28SIAgb5-E78cGqu7ThPw_BrVAkHfn68" ^
  -H "Content-Type: application/json" ^
  -d "{\"templateIds\":[\"914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:LogRequest\"],\"query\":{}}"

#get token from token.text
curl.exe -v ^
  -X POST http://localhost:7575/v1/query ^
  -H "Authorization: Bearer $(Get-Content token.txt)" ^
  -H "Content-Type: application/json" ^
  -d "{\"templateIds\":[\"914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:LogRequest\"],\"query\":{}}"

#query
curl.exe -v ^
  -X POST http://localhost:7575/v1/query ^
  -H "Authorization: Bearer $(Get-Content token.txt)" ^
  -H "Content-Type: application/json" ^
  -d "{\"templateIds\":[\"914d80669498582197424affdb30749007bb881460b73e58bdadc01a20abb9b8:Main:LogRequest\"],\"query\":{}}"
#use powershell -----------------------------PS START----------------------


or curl 
#
# peacock

~~~
$env:REQUESTS_CA_BUNDLE = 'C:\Users\steven\.mitmproxy\mitmproxy-ca.pem'
$env:https_proxy = '127.0.0.1:8080'
python peacock.py

go run fix.go

go run req.go
~~~

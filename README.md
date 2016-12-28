AutoCa
======

Service to autogenerate host/client certificates


Config
-------
```yaml
ca:
  cert: "signing-ca.crt"
  key: "signing-ca.key"
  key_pass: "secret"
  db: "serial.db"

cert:
  days: 1

web:
  port: 8081
  cert: "data/hostcert.pem"
  key: "data/hostkey.pem"
  generate_cert: true
  hosts: ["127.0.0.1", "192.169.17.0/24"]
```


Howto use
---------
There is a sample client in python to get certigicates:

```
$ ./pyclient/autoca-client -n https://localhost:8081/
```

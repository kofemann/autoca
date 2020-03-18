# AutoCa

Service to autogenerate host/client certificates

## Config

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

## HowTo use

### python client

There is a sample client in python to get certificates:

```sh
$ ./pyclient/autoca-client -n https://localhost:8081/
```

### without special client

Hard core users can use `curl` + `jq`

```sh
$ curl -s 'https://localhost:8081/v1/certificate' -o autoca.out
$ jq -r '.cert?' autoca.out > hostcert.pem
$ jq -r '.key?' autoca.out > hostkey.pem
$ rm autoca.out
```

## LICENSE

This work is published under [AGPLv3][1] license.

[1]: https://www.gnu.org/licenses/agpl-3.0.txt

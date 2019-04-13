# ezBastion internal PKI microservice.

**ezb_pki** is a *Public Key infrastructure* microservice. It will used by ezBastion nodes to interact together.


## SETUP

The PKI (Public Key Infrastructure) is the first node to be installed. It will be in charge to create and deploy the ECDSA pair key, used by all ezBastion's node to communicate.
The certificates are used to sign JWT too.


### 1. Download ezb_pki from [GitHub](<https://github.com/ezBastion/ezb_pki/releases/latest>)

### 2. Open an admin command prompte, like CMD or Powershell.

### 3. Run ezb_pki.exe with **init** option.

- name: This is the name used as Windows service and as certificates root name.
- fullname:The Windows service description.
- listen: The TCP/IP port used by ezb_pki to respond at nodes request. This port MUST BE reachable by all ezBastion's node.


### 4. Install Windows service and start it.

```powershell
    ezb_pki install
    ezb_pki start
```

![setup](https://github.com/ezBastion/doc/raw/master/image/pki-setup.gif)

## security consideration

- ezb_pki is an auto-enrolment system, if you do not add nodes, stop the service or don't install it and use debug mode instead.
- Protect cert folder.
- Backup the private/public key.


## Copyright

Copyright (C) 2018 Renaud DEVERS info@ezbastion.com
<p align="center">
<a href="COPYING"><img src="https://img.shields.io/badge/license-AGPL%20v3-blueviolet.svg?style=for-the-badge&logo=gnu" alt="License"></a></p>


Used librairy:

Name      | Copyright | version | url
----------|-----------|--------:|----------------------------
gin       | MIT       | 1.2     | github.com/gin-gonic/gin
cli       | MIT       | 1.20.0  | github.com/urfave/cli
gorm      | MIT       | 1.9.2   | github.com/jinzhu/gorm
logrus    | MIT       | 1.0.4   | github.com/sirupsen/logrus
go-fqdn   | Apache v2 | 0       | github.com/ShowMax/go-fqdn
jwt-go    | MIT       | 3.2.0   | github.com/dgrijalva/jwt-go
gopsutil  | BSD       | 2.15.01 | github.com/shirou/gopsutil


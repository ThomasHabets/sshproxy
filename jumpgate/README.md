# Jumpgate

## Purpose

[SSH Certificates](https://blog.habets.se/2011/07/OpenSSH-certificates.html) are
great, but are not supported by all SSH implementations, nor where they are
supported are they always configurable. E.g. many IoT devices don't support
them. Even public key logins are not always supported.

Jumpgate will allow you to set a unique password on all devices, and have a
jumpgate where you SSH with a certificate or pubkey, and the jumpgate logs in
for you, using the password it stores.

So you can have good and unique passwords, but with all the benefits of pubkeys
and CAs, even when the devices themselves don't support them.

Taking all connections through a set of proxies helps auditing and enables
cutting all new and existing connections instantly.

## Setup

### Create CA and a user key

```
$ ssh-keygen -t ed25519 -N "secret CA password" -f ca
$ ssh-keygen -t ed25519 -f user_key
$ ssh-keygen -s ca -I thomas-key1 -n thomas,username2 user_key.pub
$ ssh-keygen -l -f user_key.pub | awk '{print $2 ""}'
SHA256:abcabc___user_key_here___abcabc
```

### Create SSH proxy host key

```
$ ssh-keygen -t ed25519 -N '' -f jumpgate-key
```

### Set up login database

```
$ sqlite3 jumpgate.sqlite3 < jumpgate.schema
```

#### Add host keys

Host keys can be printed from a `known_hosts` with:

```
$ ssh-keygen -F router.example.com  -l  | grep -v ^# | awk '{print $3 "\n" $2}'
SHA256:abcabc___HOST_key_here___abcabc
ssh-rsa
```

Or on the server with something like:

```
$ ssh-keygen -l -f /etc/ssh/ssh_host_ecdsa_key.pub | awk '{print $2}'
SHA256:abcabc___HOST_key_here___abcabc
$ awk '{print $1}' /etc/ssh/ssh_host_ecdsa_key.pub
ecdsa-sha2-nistp256
```

```
$ sqlite3 jumpgate.sqlite3
> INSERT INTO host_keys(host, type, pubkey) VALUES('router.example.com:22', 'ssh-rsa', 'SHA256:abcabc___HOST_key_here___abcabc');
> INSERT INTO host_keys(host, type, pubkey) VALUES('router2.example.com:22', 'ssh-rsa', 'SHA256:abcabc___HOST_key2_here___abcabc');
```

#### Add user keys, client CAs, and account passwords

CA fingerprint can be extracted like the host key:

```
$ ssh-keygen -l -f ca.pub | awk '{print $2}'
SHA256:abcabc___CA_key_here___abcabc
$ awk '{print $1}' ca.pub
ssh-ed25519
```

```
$ sqlite3 jumpgate.sqlite3
> INSERT INTO acl(pubkey, target) VALUES('SHA256:abcabc___user_key_here___abcabc', 'admin@router.example.com:22');
> INSERT INTO cas(pubkey, target) VALUES('SHA256:abcabc___CA_key_here___abcabc', 'admin@router.example.com:22');
> INSERT INTO cas(pubkey, target) VALUES('SHA256:abcabc___CA_key_here___abcabc', 'admin@router2.example.com:22');
> INSERT INTO passwords VALUES('admin@router.example.com:22', 'password here');
> INSERT INTO passwords VALUES('admin@router2.example.com:22', 'password here');
^D
$ ./jumpgate -db jumpgate.sqlite3
```

### Start jumpgate

```
./jumpgate -db=jumpgate.sqlite3
```

### Log in to host

```
ssh -p 2022 admin%router.example.com:22@localhost
```

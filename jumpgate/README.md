### Create CA and a user key

```
$ ssh-keygen -t ed25519 -N "secret CA password" -f ca
$ ssh-keygen -t ed25519 -f user_key
$ ssh-keygen -s ca -I thomas-key1 -n thomas,username2 user_key.pub
$ ssh-keygen -l -f user_key.pub | awk '{print $2}'
SHA256:abcabc___user_key_here___abcabc
```

### Create SSH proxy host key

```
$ ssh-keygen -t ed25519 -N '' -f jumpgate-key
```

### Set up login database

Host keys can be printed from a `known_hosts` with:

```
$ ssh-keygen -F router.example.com  -l  | grep -v ^# | awk '{print $3}'
SHA256:abcabc___HOST_key_here___abcabc
```

Or on the server with something like:

```
ssh-keygen -l -f /etc/ssh/ssh_host_ecdsa_key.pub | awk '{print $2}'
SHA256:abcabc___HOST_key_here___abcabc
```

```
$ sqlite3 jumpgate.sqlite3 < jumpgate.schema
$ sqlite3 jumpgate.sqlite3
> INSERT INTO host_keys(host, type, pubkey) VALUES('router.example.com:22', 'ssh-rsa', 'SHA256:abcabc___HOST_key_here___abcabc');
> INSERT INTO acl(pubkey, target) VALUES('SHA256:abcabc___user_key_here___abcabc', 'admin@router.example.com:22');
> INSERT INTO passwords VALUES('admin@router.example.com:22', 'password here');
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

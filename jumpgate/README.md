
```
$ sqlite3 jumpgate.sqlite3 < schema.db
$ sqlite3 jumpgate.sqlite3
INSERT INTO host_keys(target, pubkey) VALUES('localhost:22', 'SHA256:dTr0kjTvypsE7Kaaaaaaaaaaa+ewKNz2nv5QE');
INSERT INTO acl(pubkey, target) VALUES('SHA256:mMmoetnuohunto', 'localhost:22');
INSERT INTO passwords VALUES('localhost:22', 'password here');
^D
$ ./jumpgate -db jumpgate.sqlite3
```

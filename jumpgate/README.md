
```
$ sqlite3 jumpgate.sqlite3
CREATE TABLE host_keys(
       target STRING NOT NULL,
       pubkey STRING NOT NULL,
       PRIMARY KEY(target)
);
INSERT INTO host_keys(target, pubkey) VALUES('localhost:22', 'SHA256:dTr0kjTvypsE7Kaaaaaaaaaaa+ewKNz2nv5QE');
CREATE TABLE passwords(
       target STRING NOT NULL,
       password STRING NOT NULL,
       PRIMARY KEY(target)
);
CREATE TABLE acl(
       pubkey TEXT NOT NULL,
       target TEXT NOT NULL
);
INSERT INTO acl(pubkey, target) VALUES('SHA256:mMmoetnuohunto', 'localhost:22');
INSERT INTO passwords VALUES('localhost:22', 'password here');
^D
$ ./jumpgate -db jumpgate.sqlite3
```

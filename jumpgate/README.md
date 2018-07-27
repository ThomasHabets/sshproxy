
```
$ sqlite3 jumpgate.sqlite3
CREATE TABLE passwords(
       target STRING NOT NULL,
       password STRING NOT NULL,
       PRIMARY KEY(target)
);
INSERT INTO passwords VALUES('localhost:22', 'password here');
^D
$ ./jumpgate -db jumpgate.sqlite3
```

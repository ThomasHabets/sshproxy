# sshproxy
SSH Proxy / Load balancer

Copyright (C) 2014 Thomas Habets <thomas@habets.se>

## Description

SSHProxy proxies an SSH connection over SSL, to allow:
* A client to use an SSH key they don't have access to. Therefore
  they can't go around the proxy, or lose the key.
* Logging of everything typed and received through the proxy (optional).

For setup instructions, see
[this blog post](https://blog.habets.se/2014/06/Another-way-to-protect-your-SSH-keys).

## -auth=key

With `-auth=key` the client will use `PubkeyAuthentication` to authenticate to `SSHProxy`,
and SSHProxy will use the key specified in `-client_keyfile` to log in to the server.

## -auth=kbi

With `-auth=kbi` SSHProxy will forward the password from the client on to the server.

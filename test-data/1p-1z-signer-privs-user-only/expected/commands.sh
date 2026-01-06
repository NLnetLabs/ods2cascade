cp out/policies/minimal.toml /etc/cascade/policies/
cascade --server 127.0.0.1:4539 policy reload
cascade --server 127.0.0.1:4539 zone add --policy minimal --source minimal.zone somezone

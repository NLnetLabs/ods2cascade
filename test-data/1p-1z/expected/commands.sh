sudo cp out/policies/minimal.toml /etc/cascade/policies/
cascade --server 127.0.0.1:4539 policy reload
cascade --server 127.0.0.1:4539 zone add --policy minimal --source minimal.zone --import-ksk-kmip somehsm DFE7265B783F418685380AA784C2F31D_pub DFE7265B783F418685380AA784C2F31D_priv 5 257 --import-zsk-kmip somehsm 8D76C0C49FEB4A97B8E920C7552401CE_pub 8D76C0C49FEB4A97B8E920C7552401CE_priv 5 256 somezone

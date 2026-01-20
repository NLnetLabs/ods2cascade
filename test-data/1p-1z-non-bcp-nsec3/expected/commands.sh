sudo cp out/policies/bcp-compliant-nsec3-settings.toml /etc/cascade/policies/
sudo cp out/policies/non-empty-nsec3-salt.toml /etc/cascade/policies/
sudo cp out/policies/too-many-nsec3-iterations.toml /etc/cascade/policies/
cascade --server 127.0.0.1:4539 policy reload
cascade --server 127.0.0.1:4539 zone add --policy bcp-compliant-nsec3-settings --source minimal.zone --import-ksk-kmip somehsm DFE7265B783F418685380AA784C2F31D_pub DFE7265B783F418685380AA784C2F31D_priv 5 257 --import-zsk-kmip somehsm 8D76C0C49FEB4A97B8E920C7552401CE_pub 8D76C0C49FEB4A97B8E920C7552401CE_priv 5 256 bcp-compliant-nsec3-zone
cascade --server 127.0.0.1:4539 zone add --policy too-many-nsec3-iterations --source minimal.zone --import-ksk-kmip somehsm DFE7265B783F418685380AA784C2F31D_pub DFE7265B783F418685380AA784C2F31D_priv 5 257 --import-zsk-kmip somehsm 8D76C0C49FEB4A97B8E920C7552401CE_pub 8D76C0C49FEB4A97B8E920C7552401CE_priv 5 256 too-many-nsec3-iterations
cascade --server 127.0.0.1:4539 zone add --policy non-empty-nsec3-salt --source minimal.zone --import-ksk-kmip somehsm DFE7265B783F418685380AA784C2F31D_pub DFE7265B783F418685380AA784C2F31D_priv 5 257 --import-zsk-kmip somehsm 8D76C0C49FEB4A97B8E920C7552401CE_pub 8D76C0C49FEB4A97B8E920C7552401CE_priv 5 256 non-empty-nsec3-salt

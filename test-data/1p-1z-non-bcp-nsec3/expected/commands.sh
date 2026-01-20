sudo cp out/policies/bcp-compliant-nsec3-settings.toml /etc/cascade/policies/
sudo cp out/policies/non-empty-nsec3-salt.toml /etc/cascade/policies/
sudo cp out/policies/too-many-nsec3-iterations.toml /etc/cascade/policies/
cascade --server 127.0.0.1:4539 policy reload
cascade --server 127.0.0.1:4539 zone add --policy bcp-compliant-nsec3-settings --source minimal.zone bcp-compliant-nsec3-zone
cascade --server 127.0.0.1:4539 zone add --policy too-many-nsec3-iterations --source minimal.zone too-many-nsec3-iterations
cascade --server 127.0.0.1:4539 zone add --policy non-empty-nsec3-salt --source minimal.zone non-empty-nsec3-salt

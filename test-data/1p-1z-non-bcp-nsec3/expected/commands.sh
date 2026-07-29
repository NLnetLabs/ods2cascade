# Copy the generated policies to the Cascade policy directory.
sudo cp out/policies/bcp-compliant-nsec3-settings.toml /etc/cascade/policies/
sudo cp out/policies/non-empty-nsec3-salt.toml /etc/cascade/policies/
sudo cp out/policies/too-many-nsec3-iterations.toml /etc/cascade/policies/

# Set the copied policy file ownership and permissions so that Cascade can read the files.
sudo chown test /etc/cascade/policies/bcp-compliant-nsec3-settings.toml
sudo chmod u+r /etc/cascade/policies/bcp-compliant-nsec3-settings.toml
sudo chown test /etc/cascade/policies/non-empty-nsec3-salt.toml
sudo chmod u+r /etc/cascade/policies/non-empty-nsec3-salt.toml
sudo chown test /etc/cascade/policies/too-many-nsec3-iterations.toml
sudo chmod u+r /etc/cascade/policies/too-many-nsec3-iterations.toml

# Tell Cascade to reload its policy files.
cascade --server 127.0.0.1:4539 policy reload

# Tell Cascade that a cascade-hsm-bridge instance named 'somehsm' is available at 127.0.0.1.
cascade --server 127.0.0.1:4539 hsm add --insecure --username OpenDNSSEC --password 1234 somehsm 127.0.0.1

# Tell Cascade to load and sign our zones using the appropriate policies.
cascade --server 127.0.0.1:4539 zone add --policy bcp-compliant-nsec3-settings --source minimal.zone --import-ksk-kmip somehsm DFE7265B783F418685380AA784C2F31D_pub DFE7265B783F418685380AA784C2F31D_priv 5 257 --import-zsk-kmip somehsm 8D76C0C49FEB4A97B8E920C7552401CE_pub 8D76C0C49FEB4A97B8E920C7552401CE_priv 5 256 bcp-compliant-nsec3-zone
cascade --server 127.0.0.1:4539 zone add --policy too-many-nsec3-iterations --source minimal.zone --import-ksk-kmip somehsm DFE7265B783F418685380AA784C2F31D_pub DFE7265B783F418685380AA784C2F31D_priv 5 257 --import-zsk-kmip somehsm 8D76C0C49FEB4A97B8E920C7552401CE_pub 8D76C0C49FEB4A97B8E920C7552401CE_priv 5 256 too-many-nsec3-iterations
cascade --server 127.0.0.1:4539 zone add --policy non-empty-nsec3-salt --source minimal.zone --import-ksk-kmip somehsm DFE7265B783F418685380AA784C2F31D_pub DFE7265B783F418685380AA784C2F31D_priv 5 257 --import-zsk-kmip somehsm 8D76C0C49FEB4A97B8E920C7552401CE_pub 8D76C0C49FEB4A97B8E920C7552401CE_priv 5 256 non-empty-nsec3-salt

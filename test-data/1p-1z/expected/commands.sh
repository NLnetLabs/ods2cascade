# Copy the generated policies to the Cascade policy directory.
sudo cp out/policies/minimal.toml /etc/cascade/policies/

# Set the copied policy file ownership and permissions so that Cascade can read the files.
sudo chown test /etc/cascade/policies/minimal.toml
sudo chmod u+rx /etc/cascade/policies/minimal.toml

# Tell Cascade to reload its policy files.
cascade --server 127.0.0.1:4539 policy reload

# Tell Cascade that a kmip2pkcs11 instance named 'somehsm' is available at 127.0.0.1.
cascade --server 127.0.0.1:4539 hsm add --insecure --username OpenDNSSEC --password 1234 somehsm 127.0.0.1

# Tell Cascade to load and sign our zones using the appropriate policies.
cascade --server 127.0.0.1:4539 zone add --policy minimal --source minimal.zone --import-ksk-kmip somehsm DFE7265B783F418685380AA784C2F31D_pub DFE7265B783F418685380AA784C2F31D_priv 5 257 --import-zsk-kmip somehsm 8D76C0C49FEB4A97B8E920C7552401CE_pub 8D76C0C49FEB4A97B8E920C7552401CE_priv 5 256 somezone

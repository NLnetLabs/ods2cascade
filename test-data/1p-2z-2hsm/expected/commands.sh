# Copy the generated policies to the Cascade policy directory.
sudo cp out/policies/hsm1.toml /etc/cascade/policies/
sudo cp out/policies/hsm2.toml /etc/cascade/policies/

# Set the copied policy file ownership and permissions so that Cascade can read the files.
sudo chown test /etc/cascade/policies/hsm1.toml
sudo chmod u+rx /etc/cascade/policies/hsm1.toml
sudo chown test /etc/cascade/policies/hsm2.toml
sudo chmod u+rx /etc/cascade/policies/hsm2.toml

# Tell Cascade to reload its policy files.
cascade --server 127.0.0.1:4539 policy reload

# Tell Cascade that a kmip2pkcs11 instance named 'somehsm' is available at 127.0.0.1.
cascade --server 127.0.0.1:4539 hsm add --insecure --username OpenDNSSEC --password 1234 somehsm 127.0.0.1

# Tell Cascade that a kmip2pkcs11 instance named 'someotherhsm' is available at 127.0.0.1.
cascade --server 127.0.0.1:4539 hsm add --insecure --username OpenDNSSEC --password 1234 someotherhsm 127.0.0.1

# Tell Cascade to load and sign our zones using the appropriate policies.
cascade --server 127.0.0.1:4539 zone add --policy hsm1 --source minimal.zone --import-ksk-kmip somehsm DFE7265B783F418685380AA784C2F31D_pub DFE7265B783F418685380AA784C2F31D_priv 5 257 --import-zsk-kmip somehsm 8D76C0C49FEB4A97B8E920C7552401CE_pub 8D76C0C49FEB4A97B8E920C7552401CE_priv 5 256 somezone
cascade --server 127.0.0.1:4539 zone add --policy hsm2 --source minimal.zone --import-ksk-kmip someotherhsm DFE7265B783F418685380AA784C2F31D_pub DFE7265B783F418685380AA784C2F31D_priv 5 257 --import-zsk-kmip someotherhsm 8D76C0C49FEB4A97B8E920C7552401CE_pub 8D76C0C49FEB4A97B8E920C7552401CE_priv 5 256 someotherzone

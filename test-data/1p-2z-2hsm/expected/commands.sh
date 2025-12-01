cp out/policies/hsm1.toml /etc/cascade/policies/
cp out/policies/hsm2.toml /etc/cascade/policies/
cascade --server 127.0.0.1:4539 policy reload
cascade --server 127.0.0.1:4539 hsm add --insecure --username OpenDNSSEC --password 1234 somehsm
cascade --server 127.0.0.1:4539 hsm add --insecure --username OpenDNSSEC --password 1234 someotherhsm
cascade --server 127.0.0.1:4539 zone add --policy hsm1 --source minimal.zone somezone
cascade --server 127.0.0.1:4539 zone add --policy hsm2 --source minimal.zone someotherzone

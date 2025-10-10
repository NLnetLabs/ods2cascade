# ods2cascade

A tool for assisting operators with migration from OpenDNSSEC to [Cascade](https://nlnetlabs.nl/cascade).

# Status

Not yet working, very early prototype.

Can:
  - Read **well-formed** OpenDNSSEC `conf.xml`, `kasp.xml`, `addns.xml` and `zonelist.xml` files.
  - Access the Cascade internal configuration and policy types, so in theory use them to serialize
    generated configurations to Cascade compatible files on disk.

Cannot:
  - Read the OpenDNSSEC database, so lacks full knowledge of the set of zones and keys and their state.
  - Read ``signconf.xml`` files.

# Usage

```
$ cargo run -- <path/to/opendnssec/conf.xml>
Loading /home/ximon/workspace/opendnssec/conf/conf.xml...
Loading /home/ximon/workspace/opendnssec/conf/kasp.xml...
Loading /home/ximon/workspace/opendnssec/conf/zonelist.xml...
Loading /home/ximon/workspace/opendnssec/conf/addns.xml...
[src/main.rs:39:5] &conf = Configuration {
    repository_list: RepositoryList {
        repositories: [
            Repository {
                name: "SoftHSM",
                module: "/usr/local/lib/softhsm/libsofthsm2.so",
                token_label: "OpenDNSSEC",
                pin: None,
                capacity: 18446744073709551615,
                require_backup: None,
                skip_public_key: Some(
                    (),
                ),
                allow_extraction: None,
            },
        ],
    },
    common: Common {
        logging: Some(
            Logging {
                verbosity: Some(
                    3,
                ),
                syslog: Some(
                    Syslog {
                        facility: local0,
                    },
                ),
            },
        ),
        policy_file: "/home/ximon/workspace/opendnssec/conf/kasp.xml",
        zone_list_file: "/home/ximon/workspace/opendnssec/conf/zonelist.xml",
    },
    enforcer: Enforcer {
        privs: None,
        datastore: Datastore {
            datastore: sqlite(
                Sqlite(
                    "/var/opendnssec/kasp.db",
                ),
            ),
        },
        manual_key_generation: None,
        automatic_key_generation_period: "P1Y",
        rollover_notification: None,
        delegation_signer_submit_command: None,
        pid_file: None,
        socket_file: None,
        working_directory: "/var/opendnssec/enforcer",
        worker_threads: 4,
    },
    signer: Some(
        Signer {
            privs: None,
            working_directory: "/var/opendnssec/signer",
            worker_threads: 4,
            signer_threads: 4,
            listener: Listener {
                interfaces: [
                    Interface {
                        address: "",
                        port: 15534,
                    },
                ],
            },
            notify_command: None,
        },
    ),
}
[src/main.rs:40:5] &kasp = KASP {
    policies: [
        Policy {
            name: "default",
            passthrough: None,
            description: "A default policy that will amaze you and your friends",
            signatures: Signatures {
                resign: "PT2H",
                refresh: "P3D",
                validity: Validity {
                    default: "P14D",
                    denial: "P14D",
                    keyset: None,
                },
                jitter: "PT12H",
                inception_offset: "PT3600S",
                max_zone_ttl: Some(
                    MaxZoneTTL {
                        duration: "P1D",
                    },
                ),
            },
            keys: Keys {
                ttl: "PT3600S",
                retire_safety: "PT3600S",
                publish_safety: "PT3600S",
                share_keys: None,
                purge: Some(
                    "P14D",
                ),
                ksks: [
                    Ksk {
                        algorithm: Algorithm {
                            length: "2048",
                            value: "8",
                        },
                        lifetime: "P1Y",
                        repository: "SoftHSM",
                        standby: None,
                        manual_rollover: None,
                        ksk_roll_type: None,
                        rfc5011: None,
                    },
                ],
                zsks: [
                    Zsk {
                        algorithm: Algorithm {
                            length: "1024",
                            value: "8",
                        },
                        lifetime: "P90D",
                        repository: "SoftHSM",
                        standby: None,
                        manual_rollover: None,
                        zsk_roll_type: None,
                    },
                ],
                csks: [],
            },
            zone: Zone {
                propagation_delay: "PT43200S",
                soa: ZoneSoa {
                    ttl: "PT3600S",
                    minimum: "PT3600S",
                    serial: Serial {
                        serial: unixtime,
                    },
                },
            },
            parent: Parent {
                propagation_delay: PropagationDelay {
                    duration: "PT9999S",
                },
                ds: Ds {
                    ttl: "PT3600S",
                },
                soa: Soa {
                    ttl: "PT172800S",
                    minimum: "PT10800S",
                },
                registration_delay: None,
            },
        },
        Policy {
            name: "lab",
            passthrough: None,
            description: "Quick turnaround policy for lab work",
            signatures: Signatures {
                resign: "PT10M",
                refresh: "PT30M",
                validity: Validity {
                    default: "PT1H",
                    denial: "PT1H",
                    keyset: None,
                },
                jitter: "PT1M",
                inception_offset: "PT3600S",
                max_zone_ttl: Some(
                    MaxZoneTTL {
                        duration: "PT300S",
                    },
                ),
            },
            keys: Keys {
                ttl: "PT300S",
                retire_safety: "PT360S",
                publish_safety: "PT360S",
                share_keys: None,
                purge: Some(
                    "P14D",
                ),
                ksks: [
                    Ksk {
                        algorithm: Algorithm {
                            length: "2048",
                            value: "8",
                        },
                        lifetime: "P1Y",
                        repository: "SoftHSM",
                        standby: None,
                        manual_rollover: None,
                        ksk_roll_type: None,
                        rfc5011: None,
                    },
                ],
                zsks: [
                    Zsk {
                        algorithm: Algorithm {
                            length: "1024",
                            value: "8",
                        },
                        lifetime: "PT4H",
                        repository: "SoftHSM",
                        standby: None,
                        manual_rollover: None,
                        zsk_roll_type: None,
                    },
                ],
                csks: [],
            },
            zone: Zone {
                propagation_delay: "PT300S",
                soa: ZoneSoa {
                    ttl: "PT300S",
                    minimum: "PT300S",
                    serial: Serial {
                        serial: unixtime,
                    },
                },
            },
            parent: Parent {
                propagation_delay: PropagationDelay {
                    duration: "PT9999S",
                },
                ds: Ds {
                    ttl: "PT3600S",
                },
                soa: Soa {
                    ttl: "PT172800S",
                    minimum: "PT10800S",
                },
                registration_delay: None,
            },
        },
    ],
}
[src/main.rs:41:5] &zone_list = ZoneList {
    zones: [
        Zone {
            name: "example.com",
            policy: "default",
            signer_configuration: "/var/opendnssec/signconf/example.com.xml",
            adapters: Adapters {
                input: Input {
                    adapter: Adapter {
                        _type: "File",
                        path: "/var/opendnssec/unsigned/example.com",
                    },
                },
                output: Output {
                    adapter: Adapter {
                        _type: "File",
                        path: "/var/opendnssec/signed/example.com",
                    },
                },
            },
        },
        Zone {
            name: "example.net",
            policy: "default",
            signer_configuration: "/var/opendnssec/signconf/example.net.xml",
            adapters: Adapters {
                input: Input {
                    adapter: Adapter {
                        _type: "DNS",
                        path: "/home/ximon/workspace/opendnssec/conf/addns.xml",
                    },
                },
                output: Output {
                    adapter: Adapter {
                        _type: "DNS",
                        path: "/home/ximon/workspace/opendnssec/conf/addns.xml",
                    },
                },
            },
        },
    ],
}
[src/main.rs:43:9] &adapter = (
    "/home/ximon/workspace/opendnssec/conf/addns.xml",
    Adapter {
        dns: Dns {
            tsig: [
                Tsig {
                    name: "secret.example.com",
                    algorithm: "hmac-sha256",
                    secret: "sw0nMPCswVbes1tmQTm1pcMmpNRK+oGMYN+qKNR/BwQ=",
                },
            ],
            inbound: Some(
                Inbound {
                    request_transfer: Some(
                        RequestTransfer {
                            remote: [
                                Remote {
                                    address: "1.2.3.4",
                                    port: None,
                                    key: None,
                                },
                                Remote {
                                    address: "dead:beef::1",
                                    port: Some(
                                        5353,
                                    ),
                                    key: Some(
                                        "secret.example.com",
                                    ),
                                },
                            ],
                        },
                    ),
                    allow_notify: Some(
                        AllowNotify {
                            remote: [
                                Peer {
                                    prefix: Some(
                                        "1.2.3.4",
                                    ),
                                    key: None,
                                },
                            ],
                        },
                    ),
                },
            ),
            outbound: Some(
                Outbound {
                    request_transfer: None,
                    allow_notify: None,
                },
            ),
        },
    },
)
```

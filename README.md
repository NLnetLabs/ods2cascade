# ods2cascade

A tool for assisting operators with migration from OpenDNSSEC to [Cascade](https://nlnetlabs.nl/cascade).

`ods2cascade`:
  - _Reads_ OpenDNSSEC files and the Enforcer Database.
  - Does **NOT** modify any existing Cascade or OpenDNSSEC instances.
  - Outputs generated files for use with Cascade to a user-specified directory.

# Status

Not yet working, very early prototype.

Progress:
  - [x] Read **well-formed** OpenDNSSEC `conf.xml`, `kasp.xml`, `addns.xml`, `zonelist.xml`, `zones.xml` and `signconf.xml` files.
  - [x] Read **well-formed** Cascade config TOML file.
  - [x] Read **well-formed** SQLite/MySQL Enforcer database fields.
  - [ ] Determine the set of PKCS#11 keys to import.
  - [ ] Read HSM configuration from OpenDNSSEC configuration.
  - [ ] Read database configuration from OpenDNSSEC configuration.
  - [ ] Determine the OpenDNSSEC source of truth to use for each Cascade setting to be configured.
  - [ ] Determine how to map any concepts in OpenDNSSEC that have exactly corresponding counterparts in Cascade.
    - [x] Handle the 2:1 mapping of separate but related OpenDNSSEC KASP policy and ADDNS XML files onto single Cascade policy files.
  - [x] Generate Cascade policy files by serializing Cascade data types.
  - [ ] Generate `kmip2pkcs11` configuration for each OpenDNSSEC "Repository".
  - [ ] Generate Cascade configuration.
  - [ ] Generate a shell script containing the sequence of commands needed to:
    - [x] Install generated Cascade policy files.
    - [x] Instruct Cascade to reload policy.
    - [ ] Instruct Cascade to add HSMs.
    - [ ] Instruct Cascade to add zones
      - [x] Using the correct policy.
      - [ ] Using the correct HSM.
      - [ ] Using the correct keys.

# Usage

`ods2cascade` requires that both Cascade and `kmip2pkcs11` (if needed, see #22) already be installed.

`ods2cascade` requires three filesystem paths as input:

1. The path to the config file of your new Cascade instance. This is used to determine the Cascade policy directory.
2. The path to the config file of the OpenDNSSEC instance to migrate.
3. The path to a directory to create that will contain generated policy files and a migration shell script.

When invoked `ods2cascade` will:
  - Read the specified Cascade configuration file.
  - Read the specified OpenDNSSEC configuration and any files that references.
  - Query the specified OpenDNSSEC Enforcer database using the connection details specified in the OpenDNSSEC configuration.
  - Generate Cascade policy, configuration and migration shell script files in the specified output directory.

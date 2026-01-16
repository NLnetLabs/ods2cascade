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
  - [x] Determine the set of PKCS#11 keys to import.
  - [x] Read HSM configuration from OpenDNSSEC configuration.
  - [x] Read database configuration from OpenDNSSEC configuration.
  - [ ] Determine the OpenDNSSEC source of truth to use for each Cascade setting to be configured.
  - [ ] Determine how to map any concepts in OpenDNSSEC that have exactly corresponding counterparts in Cascade.
    - [x] Handle the 2:1 mapping of separate but related OpenDNSSEC KASP policy and ADDNS XML files onto single Cascade policy files.
  - [x] Generate Cascade policy files by serializing Cascade data types.
  - [x] Generate `kmip2pkcs11` configuration for each OpenDNSSEC "Repository".
  - [ ] -Generate Cascade configuration.- BLOCKED, see [#36](https://github.com/NLnetLabs/ods2cascade/pull/36), 
  - [x] Generate a shell script containing the sequence of commands needed to: - NOTE: Now generates a `README.md`.
    - [x] Install generated Cascade policy files.
    - [x] Instruct Cascade to reload policy.
    - [x] Instruct Cascade to add HSMs.
    - [x] Instruct Cascade to add zones
      - [x] Using the correct policy.
      - [x] Using the correct HSM.
      - [x] Using the correct keys.

# Usage

`ods2cascade` requires that both Cascade and `kmip2pkcs11` (if needed, see #22) already be installed.

`ods2cascade` requires three filesystem paths as input:

1. The path to the config file of your new Cascade instance.
3. The path to the config file of the OpenDNSSEC instance to migrate.
4. The path to a directory to create that will contain generated policy files and a migration shell script.

When invoked `ods2cascade` will:
  - Read the specified Cascade configuration file.
  - Read the specified OpenDNSSEC configuration and any files that references.
  - Query the specified OpenDNSSEC Enforcer database using the connection details specified in the OpenDNSSEC configuration.
  - Generate Cascade configuration and policy files.
  - Generate `kmip2pkcs11` configuration files.
  - Generate a `README.md` containing instructions and shell commands required to complete the migration.

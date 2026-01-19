Using :program:`ods2cascade`
============================

tl;dr
-----

- Run :program:`ods2cascade`.
- Follow the steps described in the `README.md` that it generates.

This will result in both :doc:`cascade` and :doc:`kmip2pkcs11` being
configured to behave like the OpenDNSSEC Enforcer and Signer, using the same
input zones and HSM keys as OpenDNSSEC to publish signed zones for consumption
by secondary nameservers via XFR.

.. Note::

   At the time of writing :doc:`cascade` does **NOT** support writing signed
   zones to files on disk.

Prerequisites
-------------

These instructions assume that you have:

  - An existing up-to-date (2.1.14) OpenDNSSEC installation.
	:program:`ods2cascade` has not been tested with earlier versions of
	OpenDNSSEC, you are advised to upgrade before migrating.

  - An existing vanilla installation of Cascade **and** :doc:`kmip2pkcs11`.
    Follow the instructions at :doc:`cascade` to install both.

  - Installed :program:`ods2cascade`. See :doc:`installation` or
    :doc:`building`.

Getting started
---------------

Running :program:`ods2cascade` is quite simple.

Assuming that OpenDNSSEC and Cascade are both installed on the same machine
as :program:`ods2cascade` and their configuration files are in the default
locations, we can invoke :program:`ods2cascade` like so:

  ```bash
  $ ods2cascade /etc/opendnssec/conf.xml /etc/cascade/config.toml /tmp/ods2cascade-out
  ```

This will:

  - Read the OpenDNSSEC configuration file and any other configuration files
    that it references.
  - Connect to the OpenDNSSEC database using the credentials found in the
    OpenDNSSEC configuration to determine the location of the "signconf" XML
    files and to verify some settings.
  - Generate Cascade policy and :doc:`kmip2pkcs11` configuration files.
  - Generate a ``README.md`` file that will describe the steps that need to be
    taken to migrate from OpenDNSSEC to Cascade.
  - Generate a script containing Cascade CLI commands to run to finalize the
    configuration of :doc:`cascade`.

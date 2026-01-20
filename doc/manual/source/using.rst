Using :program:`ods2cascade`
============================

tl;dr
-----

- Run :program:`ods2cascade`.
- Follow the steps described in the ``README.md`` that it generates.

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

  .. code-block:: bash

     $ ods2cascade /etc/opendnssec/conf.xml /etc/cascade/config.toml /tmp/out

This will:

  - Read the OpenDNSSEC configuration file and any other configuration files
    that it references.
  - Connect to the OpenDNSSEC database using the credentials found in the
    OpenDNSSEC configuration to determine the location of the "signconf" XML
    files and to verify some settings.
  - Generate Cascade policy and :doc:`kmip2pkcs11` configuration files in the
    ``/tmp/out/`` directory.
  - Generate a ``/tmp/out/README.md`` file that will describe the steps that need to be
    taken to migrate from OpenDNSSEC to Cascade.
  - Generate a ``/tmp/out/commands.sh`` script containing Cascade CLI commands
    to run to finalize the configuration of :doc:`cascade`, to be used as described in
    the generated ``README.md``.

If the process ran successfully, output should look something like this:

  .. code-block:: bash

     Welcome to ods2cascade.

     This tool will generate files and instructions that you can use to configure Cascade to match the setup of an existing OpenDNSSEC deployment.

     NOTE: This tool will NOT modify your existing OpenDNSSEC or Cascade installation.

     Provided inputs:
       - OpenDNSSEC config file: /etc/opendnssec/conf.xml
       - Cascade config file   : /etc/cascade/config.toml
       - Output directory      : /tmp/out

     Gathering inputs and generating outputs:

     Loading /etc/cascade/config.toml...
     Loading /etc/opendnssec/conf.xml...
     Loading /etc/opendnssec/kasp.xml...
     Loading /var/opendnssec/enforcer/zones.xml...
     Connecting to SQLite Enforcer database at sqlite:///var/opendnssec/kasp.db...
     Found Enforcer database version: 1
     Generating '/tmp/out/kmip2pkcs11/SoftHSM.toml'...
     Creating Cascade policy 'lab' from ODS KASP 'lab'....
     Generating '/tmp/out/commands.sh'...

     Gathering of inputs and generation of outputs is complete.
     Please consult /tmp/out/README.md which advises how to proceed in order to perform the migration.

Once completed successfully the next step is, as directed, to read ``out/README.md`` and follow
the steps it describes.

Note that the generated steps are suggestions only, you will need to read
and carefully consider the guidance in the generated ``README.md`` and adjust
it for aspects of your environment that :program:`ods2cascade` is unaware
of, such as which user commands should be executed as, whether or not to use
``sudo``, whether or not your daemons are managed by systemd or some other
mechanism, and so on.

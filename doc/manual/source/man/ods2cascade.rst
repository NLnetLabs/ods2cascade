Ods2Cascade CLI
===============

Synopsis
--------

:program:`ods2cascade` ``<path/to/casade.toml>`` ``<path/to/opendnssec/conf.xml>`` ``<path/to/write/files/to>``

Description
-----------

**ods2cascade** is a command line tool to assist with migration from OpenDNSSEC to :doc:`cascade`.

Arguments
---------

.. option:: ``<path/to/cascade.toml>``

   The path to the configuration file of the Cascade instance that you wish
   to migrate to.

.. option:: ``<path/to/opendnssec/conf.xml>``

   The path to the configuration file of the OpenDNSSEC instance that you wish
   to migrate from.

.. option:: ``<path/to/write/files/to>``

   The path to a directory to be created which will contain generated
   documentation, scripts and  configuration files for use when migrating and
   will be tailored to your specific OpenDNSSEC instance.

See Also
--------

https://cascade.docs.nlnetlabs.nl
    Cascade online documentation.

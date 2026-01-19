Ods2Cascade
===========

.. only:: html

   |lastupdated| |mastodon|

   .. |lastupdated| image:: https://img.shields.io/github/last-commit/NLnetLabs/ods2cascade?path=%2Fdoc%2Fmanual&label=last%20updated
      :alt: Last docs update
      :target: https://github.com/NLnetLabs/o2dscascade/commits/main/doc/manual/source

   .. |mastodon| image:: https://img.shields.io/mastodon/follow/114692612288811644?domain=social.nlnetlabs.nl&style=social
      :alt: Mastodon
      :target: https://social.nlnetlabs.nl/@nlnetlabs

:program:`ods2cascade` is a command line tool to assist with
migration from `OpenDNSSEC <https://www.opendnssec.org/>`_ to `Cascade
<https://www.nlnetlabs.nl/projects/cascade>`_.

OpenDNSSEC EoL
--------------

OpenDNSSEC, launched in 2010, pioneered automated DNSSEC key management
and zone signing. In October 2027 OpenDNSSEC will `officially
<https://www.nlnetlabs.nl/news/2025/Oct/03/opendnssec-eol-announcement/>`_ be
End-Of-Life, and users are encouraged to transition to its successor, Cascade.

Understanding your OpenDNSSEC setup
-----------------------------------

To achieve a successful transition to Cascade users would need to:
  - Understand their OpenDNSSEC setup in some detail.
  - Extract configuration settings from various XML files, CLI commands and
    perhaps even examine the contents of the OpenDNSSEC database.
  - Understand Cascade and its configuration files sufficiently to map the
    existing OpenDNSSEC setup to an equivalent Cascade setup.
  - Understand how OpenDNSSEC was granted access to the HSM and which signing
    keys are currently in use in order to tell Cascade to use the same HSM and
    the same signing keys.

This is likely a scary and overwhelming task to perform, even assuming that
the knowledge of OpenDNSSEC has been retained in-house.

Using :program:`ods2cascade` to simplify the transition
-------------------------------------------------------

To ease this process users can use :program:`ods2cascade` to automate the
extraction and mapping of OpenDNSSEC configuration to an equivalent Cascade
setup. The tool also generates tailored guidance on the step by step actions
to take to move from OpenDNSSEC signing and publishing zones to Cascade
signing and publishing those zones.

.. Tip::

   :program:`ods2cascade` will **NOT** modify your existing OpenDNSSEC
   setup. It is designed output guidance and configuration instructions
   to a directory of your choosing. Actually configuring Cascade, starting
   it running and stopping OpenDNSSEC are deliberately **NOT** done by
   :program:`ods2cascade`, instead these are steps that you must do yourself.

.. Note::

   Not all features of OpenDNSSEC are supported by Cascade. Running
   :program:`ods2cascade` can be done safely without changing your current
   setup and will abort or warn if the migration is too complex for the tool
   or will have noteworthy consequences.

Next steps
----------

 - :doc:`installation` or :doc:`building`.
 - :doc:`using`

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Getting Started
   :name: toc-getting-started

   installation
   building
   using

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Manual Pages
   :name: toc-manual-pages

   man/ods2cascade

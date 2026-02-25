Installation
============

Binary Packages
---------------

.. Note:: Binary packages are coming soon.

Getting started with Ods2Cascade is really easy by installing a binary
package for either Debian and Ubuntu or for Red Hat Enterprise Linux (RHEL)
and compatible systems such as Rocky Linux. Alternatively, you can run with
Docker.

You can also build Ods2Cascade from the source code using Cargo, Rust's build
system and package manager. Cargo lets you run Ods2Cascade on almost any
operating system and CPU architecture. Refer to the :doc:`building` section to
get started.

.. tabs::

   .. group-tab:: Debian

       To install an Ods2Cascade package, you need the 64-bit version of one
       of these Debian versions:

         -  Debian Trixie 13
         -  Debian Bookworm 12
         -  Debian Bullseye 11

       Packages are available for the ``amd64``/``x86_64`` architecture only.
       
       First update the :program:`apt` package index: 

       .. code-block:: bash

          sudo apt update

       Then install packages to allow :program:`apt` to use a repository over HTTPS:

       .. code-block:: bash

          sudo apt install \
            ca-certificates \
            curl \
            gnupg \
            lsb-release

       Add the GPG key from NLnet Labs:

       .. code-block:: bash

          curl -fsSL https://packages.nlnetlabs.nl/aptkey.asc | sudo gpg --dearmor -o /etc/apt/keyrings/nlnetlabs-archive-keyring.gpg

       Now, use the following command to set up the *proposed* repository:

       .. code-block:: bash

          echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/nlnetlabs-archive-keyring.gpg] https://packages.nlnetlabs.nl/linux/debian \
          $(lsb_release -cs)-proposed main" | sudo tee /etc/apt/sources.list.d/nlnetlabs-proposed.list > /dev/null

       Update the :program:`apt` package index once more: 

       .. code-block:: bash

          sudo apt update

       You can now install Ods2Cascade with:

       .. code-block:: bash

          sudo apt install ods2cascade

       After installing, refer to the :doc:`quick-start` to get started.

   .. group-tab:: Ubuntu

       To install an Ods2Cascade package, you need the 64-bit version of one
       of these Ubuntu versions:

         - Ubuntu Noble 24.04 (LTS)
         - Ubuntu Jammy 22.04 (LTS)
         - Ubuntu Focal 20.04 (LTS)

       Packages are available for the ``amd64``/``x86_64`` architecture only.
       
       First update the :program:`apt` package index: 

       .. code-block:: bash

          sudo apt update

       Then install packages to allow :program:`apt` to use a repository over HTTPS:

       .. code-block:: bash

          sudo apt install \
            ca-certificates \
            curl \
            gnupg \
            lsb-release

       Add the GPG key from NLnet Labs:

       .. code-block:: bash

          curl -fsSL https://packages.nlnetlabs.nl/aptkey.asc | sudo gpg --dearmor -o /etc/apt/keyrings/nlnetlabs-archive-keyring.gpg

       Now, use the following command to set up the *proposed* repository:

       .. code-block:: bash

          echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/nlnetlabs-archive-keyring.gpg] https://packages.nlnetlabs.nl/linux/ubuntu \
          $(lsb_release -cs)-proposed main" | sudo tee /etc/apt/sources.list.d/nlnetlabs-proposed.list > /dev/null

       Update the :program:`apt` package index once more: 

       .. code-block:: bash

          sudo apt update

       You can now install Ods2Cascade with:

       .. code-block:: bash

          sudo apt install ods2cascade

       After installing, refer to the :doc:`quick-start` to get started.

   .. group-tab:: RHEL

       To install an Ods2Cascade package, you need Red Hat Enterprise Linux
       (RHEL) 8, 9 or 10 or compatible operating system such as Rocky Linux.
       Packages are available for the ``amd64``/``x86_64`` architecture only.
       
       First create a file named :file:`/etc/yum.repos.d/nlnetlabs-testing.repo`,
       enter this configuration and save it:

       .. tip::

          On Fedora systems replace $releasever with 10 (or 8 or 9 if 10 is too
          new for your Fedora) as there is no repository with Fedora numbers, e.g.
          42, in our package repository.
       
       .. code-block:: text
       
          [nlnetlabs-testing]
          name=NLnet Labs Testing
          baseurl=https://packages.nlnetlabs.nl/linux/centos/$releasever/proposed/$basearch
          enabled=1
        
       Add the GPG key from NLnet Labs:
       
       .. code-block:: bash
       
          sudo rpm --import https://packages.nlnetlabs.nl/aptkey.asc
       
       You can now install Ods2Cascade with:

       .. code-block:: bash

          sudo yum install -y ods2cascade

       After installing, refer to the :doc:`quick-start` to get started.
       
   .. group-tab:: Docker

       .. Note:: Docker images are coming soon.

.. _updating:

Updating
--------

.. tabs::

   .. group-tab:: Debian

       To update an existing Ods2Cascade installation, first update the
       repository using:

       .. code-block:: text

          sudo apt update

       You can use this command to get an overview of the available versions:

       .. code-block:: text

          sudo apt policy ods2cascade

       You can upgrade an existing Ods2Cascade installation to the latest
       version using:

       .. code-block:: text

          sudo apt --only-upgrade install ods2cascade

   .. group-tab:: Ubuntu

       To update an existing Ods2Cascade installation, first update the 
       repository using:

       .. code-block:: text

          sudo apt update

       You can use this command to get an overview of the available versions:

       .. code-block:: text

          sudo apt policy ods2cascade

       You can upgrade an existing Ods2Cascade installation to the latest
       version using:

       .. code-block:: text

          sudo apt --only-upgrade install ods2cascade

   .. group-tab:: RHEL

       To update an existing Ods2Cascade installation, you can use this
       command to get an overview of the available versions:
        
       .. code-block:: bash
        
          sudo yum list --showduplicates ods2cascade
          
       You can update to the latest version using:
         
       .. code-block:: bash
         
          sudo yum update -y ods2cascade
             
   .. group-tab:: Docker

       .. Note:: Docker images are coming soon.
               

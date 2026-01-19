Building From Source
====================

Building Ods2Cascade requires Rust and an operating system and CPU
architecture supported by Rust.

Rust
""""

The Rust compiler runs on, and compiles to, a great number of platforms,
though not all of them are equally supported. The official `Rust Platform
Support <https://doc.rust-lang.org/nightly/rustc/platform-support.html>`_
page provides an overview of the various support levels.

While some system distributions include Rust as system packages, Ods2Cascade
relies on a relatively new version of Rust, currently |rustversion| or newer.
We therefore suggest using the canonical Rust installation via a tool called
:program:`rustup`.

Assuming you already have :program:`curl` installed, you can install
:program:`rustup` and Rust by simply entering:

.. code-block:: bash

  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

Alternatively, visit the `Rust website
<https://www.rust-lang.org/tools/install>`_ for other installation methods.

.. tip:: During installation :program:`rustup` will attempt to configure the
  ``PATH``. Modifications to ``PATH`` may not take effect until the console 
  is restarted, or the user is logged out, or it may not succeed at all. If,
  after installation, running :command:`rustc --version` in the console 
  fails, this is the most likely reason.

Building
--------

In Rust, a library or executable program such as Ods2Cascade is called a *crate*.
Crates are published on `crates.io <https://crates.io/>`_, the Rust package
registry. Cargo is the Rust package manager. It is a tool that allows Rust
packages to declare their various dependencies and ensure that you’ll always
get a repeatable build. 

Cargo fetches and builds Ods2Cascade’s dependencies into an executable binary
for your platform. By default, you install from crates.io, but you can for
example also install from a specific Git URL, as explained below.

Installing the latest Ods2Cascade is as simple as running:

.. Installing the latest Ods2Cascade release from
.. crates.io is as simple as running:

.. Commented out until released
.. .. code-block:: text

  cargo install --locked ods2cascade

.. code-block:: bash

  cargo install --locked --git https://github.com/nlnetlabs/ods2cascade

The command will build Ods2Cascade and install it in the same directory that
Cargo itself lives in, likely ``$HOME/.cargo/bin``. Ensure this directory is
in your PATH so you can run Ods2Cascade immediately.

Updating
""""""""

.. tip::

   Read the :ref:`general updating instructions <updating>` first.

If you want to update to the latest version of Ods2Cascade, it’s recommended
to update Rust itself as well, using:

.. code-block:: bash

    rustup update

Use the ``--force`` option to overwrite an existing version with the latest
Ods2Cascade release:

.. code-block:: text

    cargo install --locked --force --git https://github.com/nlnetlabs/ods2cascade
..  cargo install --locked --force ods2cascade

Installing Specific Versions
""""""""""""""""""""""""""""

If you want to install a specific version of Ods2Cascade using Cargo, explicitly
use the ``--version`` option. If needed, use the ``--force`` option to
overwrite an existing version:
        
.. code-block:: bash

    cargo install --locked --force --git https://github.com/nlnetlabs/ods2cascade --tag 0.1.0-alpha
..  cargo install --locked --force ods2cascade --version 0.1.0-alpha

All new features of Ods2Cascade are built on a branch and merged via a `pull
request <https://github.com/NLnetLabs/ods2cascade/pulls>`_, allowing you to
easily try them out using Cargo. If you want to try a specific branch from
the repository you can use the ``--git`` and ``--branch`` options:

.. code-block:: bash

    cargo install --git https://github.com/NLnetLabs/ods2cascade.git --branch main
    
.. Seealso:: For more installation options refer to the `Cargo book
             <https://doc.rust-lang.org/cargo/commands/cargo-install.html#install-options>`_.


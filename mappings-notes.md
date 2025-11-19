# Mapping notes.

## Keys

conf.xml:

		<Repository name="SoftHSM">
			<Module>/usr/lib64/softhsm/libsofthsm.so</Module>
			<TokenLabel>OpenDNSSEC</TokenLabel>
			<PIN>1234</PIN>
<!--
			# Disabled so it stores the public key in the HSM too,
			# so bind's dnssec-signzone can be used as well
			<SkipPublicKey/>
-->
		</Repository>

<SkipPublicKey/> -- NOT SUPPORTED
<name> -- ignore
<Module> -> kmip2pkcs11.conf
<TokenLabel> -> Cascade HSM user
<PIN> -> Cascade HSM pass

signconf.xml:

  <Zone name="nl.">
    ..
    <Keys>
      <TTL>PT1H</TTL>
      <Key>
        <Flags>257</Flags>
        <Algorithm>8</Algorithm>
        <Locator>daa52b9117243bfb691d6b7e86aa1f1b</Locator>
        <KSK/>
        <Publish/>
      </Key>
      <Key>
        <Flags>256</Flags>
        <Algorithm>8</Algorithm>
        <Locator>a247b887c3595e5cc2cc478a269b7f18</Locator>
        <ZSK/>
        <Publish/>
      </Key>
    </Keys>
	..
  </Zone>

dnst keyset:
  dnst keyset import kmip <SERVER> <PUBLIC_ID> <PRIVATE_ID> <ALGORITHM> <FLAGS>

Only import keys with <Publish/>.

hsm id -> <SERVER>
<Locator> -> PKCS#11 CKA_ID can be used to determine <XXX_ID>
<Algorithm> -> <ALGORITHM>
<Flags> -> <FLAGS>
<KSK/> & <ZSK/> -> ...

## Zones

## Enforcer zones.xml

On startup the signer reads conf.xml looking for Configuration/Enforcer/WorkingDirectory.
Defaults to /var/opendnssec/enforcer/.
From that directory the signer reads zones.xml, which is written by the Enforcer.
This is separate to but in the same format as conf.xml/Configuration/Common/ZoneListFile.
This is the canonical list of zones used by both the Enforcer and the Signer.
From here we can get the zone name, policy, signconf path, and adapters.

### DB

Zone.name
Zone.policy_id ->
Zone.inputAdapterType
Zone.inputAdapterUri
Zone.outputAdapterType
Zone.outputAdapterUri

## Backup files

From /var/opendnssec/tmp/nl.backup2.

It describes which settings the Signer used to last sign the zone.

;OpenDNSSEC-backup-v3
;;Time: 1759147706
;;Zone: name nl class 1 inbound 2025020329 internal 2025020330 outbound 2025020330
;;Signconf: lastmod 1759139153 maxzonettl 0 resign PT2H refresh P3D valid P14D denial P14D keyset PT0S jitter PT12H offset PT1H nsec 50 dnskeyttl PT1H soattl PT1H soamin PT1H serial unixtime 
;;Nsec3parameters: salt dce5f47e90bbee95 algorithm 1 optout 0 iterations 5
;;Key: locator daa52b9117243bfb691d6b7e86aa1f1b algorithm 8 flags 257 publish 1 ksk 1 zsk 0 keytag 54706
;;Key: locator a247b887c3595e5cc2cc478a269b7f18 algorithm 8 flags 256 publish 1 ksk 0 zsk 1 keytag 36738
;;

- Zone name and class.
- Serial numbers: inbound, internal and outbound
- Signconf summary:
  - Max zone TTL
  - Resign duration
  - Refresh duration
  - Validity durations (default, denial, keyset)
  - Jitter duration
  - Inception offset
  - NSEC(3) settings? (what is "50" ?)
  - SOA parameters
    - TTL
    - Minimum
    - Serial (counter/datecounter/unixtime/keep)
  - NSEC3 settings: salt, algorithm, optout boolean, iterations
  - Keys
    - TTL for all DNSKEYs
    - Per key:
      - Flags
      - Algorithm number
      - Locator
      - KSK boolean
      - ZSK boolean
      - Publish boolean
      - Keytag (NOT in signconf)

Lacks:
- Key deactivate boolean

## Signconf

Signconf is written by the Enforcer and read by the Signer.

It tells the Signer which settings to use when next signing the zone.

It contains:

- Zone name
- Current policy for the zone
  - Passthrough boolean (optional)
  - Signatures
    - Resign duration
    - Refresh duration
    - Validity durations (default, denial and keyset)
    - Jitter duration
    - Inception offset
    - Max zone TTL (optional)
  - NSEC(3) settings
  - Keys
    - TTL for all DNSKEYs
    - Per key
      - Flags
      - Algorithm number
      - Locator (PKCS#11 CKA_ID in hex form) (optional)
      - Resource record (base64 binary) (optional)
      - KSK boolean (optional) - sign DNSKEY RRsets with this key?
      - ZSK boolean (optional) - sign non-DNSKEY RRsets with this key?
      - Publish boolean (optional) - include this key in the zonefile?
      - Deactivate boolean (optional) - deactivate this key (do not recycle signatures)
    - Zero or more signature resource records (base64 binary)
    - SOA parameters
      - TTL
      - Minimum
      - Serial (counter/datecounter/unixtime/keep)

## keyset import command

Base the server URI on kasp/Policy/Keys/{KSK,ZSK,CSK}/Repository

## keyset set command

NOTE: None of these are currently exposed via cascade zone add or cascade keyset!

- set use-csk - base this on kasp/Policy/Keys/CSK
- set autoremove - base this on kasp/Policy/Keys/Purge (but ignore the actual delay)
- set algorithm - base this on kasp/Policy/Keys/{KSK,ZSK,CSK}/Algorithm
- set auto-ksk/zsk/csk/algorithm - base this on kasp/Policy/Keys/{KSK,ZSK,CSK}/ManualRollover
- set dnskey-lifetime - base this on kasp/Policy/Signatures/Validity/Keyset?
- set dnskey-remain-time - base this on kasp/Policy/Signatures/Refresh?
- set dnskey-inception-offset - base this on kasp/Policy/Signatures/InceptionOffset
- set ksk/zsk/csk-validity - base this on kasp/Policy/Keys/{KSK,ZSK,CSK}/Lifetime

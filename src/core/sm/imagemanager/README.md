# Image Manager

## Encrypted layer blobs

A layer can be published as an encrypted blob (`mediaType:
application/vnd.aos.image.layer.enc.v1.aes256gcm+tar+gz`) so that its content is unreadable to anything
that only sees the manifest and the blob itself. Decryption happens locally on the node, using a
symmetric key that is never transmitted over the network.

### Design

- Each node holds a single AES-256 key, stored as a PKCS11 secret key object (`CKO_SECRET_KEY`/`CKK_AES`)
  on a token IAM's cert module system also manages. Unlike other keys IAM loads, this cert module (see
  `certType` below) is **dedicated** to the layer key: its registered key URL's id/label directly identify
  the `CKO_SECRET_KEY` object (see `aos::sm::imagemanager::KeyProvider`), which is why there is no separate
  layer-key-specific label constant anywhere in this code — provisioning just needs to import the key under
  whatever id/label that cert module is configured with in IAM.
- The key is provisioned **non-extractable** (`CKA_EXTRACTABLE=CK_FALSE`, `CKA_SENSITIVE=CK_TRUE`) and is
  never read off the token: all AES-GCM decryption happens through a PKCS11 `C_Decrypt` call on the token
  itself (`aos::pkcs11::AESPrivateKey`, which implements `aos::crypto::PrivateKeyItf` the same way
  `PKCS11RSAPrivateKey`/`PKCS11ECDSAPrivateKey` do — `GetPublic`/`Sign` simply aren't supported for it,
  only `Decrypt` with `crypto::GCMDecryptionOptions`). The raw key bytes exist only at provisioning time,
  on the machine that generates them — the running node process never holds them, and loading this key
  goes through the very same `CertLoaderItf::LoadPrivKeyByURL` any other private key does.
- The key is looked up lazily, the first time an encrypted layer is actually installed — a node with no
  key provisioned starts up normally and only fails when asked to install an encrypted layer.
- The algorithm is AES-256-GCM: authenticated encryption, so a wrong key or a modified blob is detected
  and rejected instead of decrypting to garbage. GCM is a stream mode, so no padding is involved (PKCS7
  only applies to CBC).
- The IV (nonce) is not derived or coordinated separately: it travels with the data as the first 12 bytes
  of the encrypted blob (see `aos::sm::imagemanager::BlobDecryptor`). Producing an encrypted blob therefore
  needs no synchronization with the device beyond knowing the AES key. Use a fresh random IV for every
  blob: with GCM, reusing an IV with the same key is a serious weakness, not just bad practice.

### File format

```text
[ 12 bytes IV ][ AES-256-GCM ciphertext of the gzip'd layer tar ][ 16 bytes authentication tag ]
```

The ciphertext is exactly as long as the plaintext (no padding). This is an IV followed by the output of a
typical AEAD API such as Python's `AESGCM(key).encrypt(iv, data, None)`, which returns the ciphertext with the
tag already appended. No additional authenticated data is used.

### One-time device provisioning

`--token-label` below must be the token that the dedicated "layer key" IAM cert module is actually
configured with (`certModules[].params.tokenLabel`); if that param is left empty, IAM's PKCS11 module
falls back to its own default label (`aos`), not `aoscore` — check the node's config rather than assuming
either. `--id`/`--label` must match that same cert module's configured key id/label exactly: unlike a real
cert module's own keypair, this cert module exists purely so its registered key URL's id/label point at
this `CKO_SECRET_KEY` object — get both values from that config, not from this document.
`--private` marks the object `CKA_PRIVATE`, so it is only readable after PIN login, the same as the
cert module's own private key.

```bash
# on the build machine
openssl rand -out layerkey.bin 32

# copy layerkey.bin to the device, then on the device (replace <token-label>/<id>/<label> as above):
# clear any stale copy first - the delete is expected to fail if there isn't one
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --token-label <token-label> \
  -p "$(cat /var/aos/iam/.usrpin)" --delete-object --type secrkey --id <id> --label <label>
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --token-label <token-label> \
  -p "$(cat /var/aos/iam/.usrpin)" --write-object layerkey.bin --type secrkey --key-type AES:32 \
  --id <id> --label <label> --private --sensitive
```

**`--id` is not optional, and pkcs11-tool won't warn you if you forget it**: omitted, the object gets no
`CKA_ID` at all (SoftHSM does not generate one), and `FindPrivateKey`'s lookup filters on `CKA_ID` as well
as `CKA_LABEL` — the key will silently fail to be found later (`eNotFound`) unless the id also matches. If
you don't already know the id the cert module is configured with, list what's already on that token first;
its `ID:` line is the value to reuse:

```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --token-label <token-label> \
  -p "$(cat /var/aos/iam/.usrpin)" --list-objects
```

After writing the object, list it back and confirm an `ID:` line is present and matches — no `ID:` line
means the write above left it out:

```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --token-label <token-label> \
  -p "$(cat /var/aos/iam/.usrpin)" --list-objects --type secrkey --label <label>
```

Do **not** add `--extractable`: leaving it off is what makes the object non-extractable
(`CKA_EXTRACTABLE=CK_FALSE`), so the token refuses to ever hand the raw key bytes back out again, to this
code or to anyone else with PIN access — decryption only works through PKCS11 operations on the token
itself (see "On-device decryption" below), never by reading the key.

Keep `layerkey.bin` in your own secrets store, keyed by device/node ID — the same key is reused for every
layer shipped to that device. Once written to the token, delete `layerkey.bin` from the device; it is not
needed there again (re-provisioning uses your secrets-store copy, not anything read back off the token).

### Encrypting a layer (build side)

`openssl enc` doesn't support AEAD ciphers such as GCM, so use a crypto library. With Python's
`cryptography` package:

```bash
gzip -c layer.tar > layer.tar.gz
```

```python
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = open("layerkey.bin", "rb").read()
assert len(key) == 32, "AES-256 key must be 32 bytes"

iv = os.urandom(12)  # fresh random IV for every blob
sealed = AESGCM(key).encrypt(iv, open("layer.tar.gz", "rb").read(), None)  # ciphertext + 16 byte tag

open("layer.tar.gz.enc", "wb").write(iv + sealed)
```

Publish `layer.tar.gz.enc` as the layer blob with
`mediaType: application/vnd.aos.image.layer.enc.v1.aes256gcm+tar+gz`; its digest (SHA-256 of the `.enc`
file) is the manifest `ContentDescriptor` digest.

### On-device decryption

1. `ImageManager` downloads the encrypted blob like any other layer.
2. `aos::sm::imagemanager::KeyProvider::Fetch()` calls `GetCert(<certType>, …)` against IAM to resolve the
   dedicated cert module's `pkcs11:` key URL, then calls `CertLoaderItf::LoadPrivKeyByURL` on it — the same
   entry point used to load any other private key. `pkcs11::Utils::FindPrivateKey` tries that URL's id/label
   as a `CKO_SECRET_KEY` object first (a symmetric key has no public part to pair it with, so it can't go
   through the usual `CKO_PRIVATE_KEY`/`CKO_PUBLIC_KEY` matching) and, if found, wraps it as an
   `aos::pkcs11::AESPrivateKey`. The resulting `aos::crypto::PrivateKeyItf` handle is cached after the first
   lookup.
3. `aos::sm::imagemanager::BlobDecryptor::Decrypt`:
   - splits the encrypted file into its IV (first 12 bytes) and the rest (ciphertext followed by the
     16-byte authentication tag), buffering the latter whole — `crypto::PrivateKeyItf::Decrypt` is a
     single in-memory call, there is no streaming variant here;
   - calls `key->Decrypt(cipherAndTag, crypto::GCMDecryptionOptions{iv}, plaintext)`, which
     `AESPrivateKey` implements as one PKCS11 `CKM_AES_GCM` / `C_Decrypt` call on the token; the key's own
     value is never read by this code;
   - output is staged to a temporary file and only put in place once decoding, including the
     authentication tag check, fully succeeds. If the tag doesn't match — wrong key, modified or
     truncated blob — decryption fails and the staged output is deleted, so unauthenticated plaintext is
     never left on disk.
4. The result is the plaintext gzip'd tar, unpacked normally like any other layer.

This is separate from `CryptoHelperItf::Decrypt`, which still handles the cloud-delivered blobs handled by
CM (`AES<128|192|256>/CBC/PKCS7PADDING`, 16 byte IV, and `AES<128|192|256>/GCM`, 12 byte IV) by decrypting
in the CM process with an in-memory key, since those blobs are decrypted with a key CM already holds
in-process rather than one kept non-extractable on a token.

### Manually verifying an encrypted blob

Useful when a layer fails to install and you want to check, independently of the running node, whether
the `.enc` file and the key provisioned to the device actually match. GCM makes this unambiguous: with the
wrong key or a damaged file decryption fails with an authentication error instead of producing garbage.

The key is provisioned non-extractable, so it can no longer be read back off the token (`--read-object`
fails by design, the same as it would for the cert module's own private key) — use your own secrets-store
copy of `layerkey.bin` from provisioning instead:

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = open("layerkey.bin", "rb").read()  # your secrets-store copy, not anything read off the token
blob = open("/path/to/layer.tar.gz.enc", "rb").read()

iv, sealed = blob[:12], blob[12:]  # sealed = ciphertext + 16 byte tag

# raises cryptography.exceptions.InvalidTag if the key or the blob is wrong
open("/tmp/layer.tar.gz.dec", "wb").write(AESGCM(key).decrypt(iv, sealed, None))
```

```bash
od -An -tx1 -N4 /tmp/layer.tar.gz.dec   # expect: 1f 8b 08 00 (gzip magic)
```

If instead you specifically want to confirm the token has the *right* key object provisioned (rather than
verify a blob), check its attributes without reading its value:

```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --token-label <token-label> \
  -p "$(cat /var/aos/iam/.usrpin)" --list-objects --type secrkey --id <id> --label <label>
```

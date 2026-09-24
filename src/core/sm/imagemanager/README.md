# Image Manager

## Encrypted layer blobs

A layer can be published as an encrypted blob (`mediaType:
application/vnd.aos.image.layer.enc.v1.aes256gcm+tar+gz`) so that its content is unreadable to anything
that only sees the manifest and the blob itself. Decryption happens locally on the node, using a
symmetric key that is never transmitted over the network.

### Design

- Each node holds a single AES-256 key, stored as an opaque PKCS11 data object (`CKO_DATA`, label
  `aos-layer-key`) on the same token as an existing IAM cert module. That cert module's own keypair is
  **not** used cryptographically here — it is only a convenient, already-provisioned pointer to which
  PKCS11 token/library/PIN to use (see `aos::sm::imagemanager::KeyProvider`).
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

`--token-label` below must be the token that the target IAM cert module is actually configured with
(`certModules[].params.tokenLabel`); if that param is left empty, IAM's PKCS11 module falls back to its
own default label (`aos`), not `aoscore` — check the node's config rather than assuming either.
`--private` marks the object `CKA_PRIVATE`, so it is only readable after PIN login, the same as the
cert module's own private key.

```bash
# on the build machine
openssl rand -out layerkey.bin 32

# copy layerkey.bin to the device, then on the device (replace <token-label> as above):
# clear any stale copy first - the delete is expected to fail if there isn't one
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --token-label <token-label> \
  -p "$(cat /var/aos/iam/.usrpin)" --delete-object --type data --label aos-layer-key
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --token-label <token-label> \
  -p "$(cat /var/aos/iam/.usrpin)" --write-object layerkey.bin --type data --label aos-layer-key --private
```

Keep `layerkey.bin` in your own secrets store, keyed by device/node ID — the same key is reused for every
layer shipped to that device.

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
2. `aos::sm::imagemanager::KeyProvider::Fetch()` calls `GetCert(<certType>, …)` against IAM purely to
   resolve a `pkcs11:` URL (token/library/PIN), then reads the `aos-layer-key` data object off that token
   via `CertLoaderItf::LoadDataByURL` — the raw key, cached after the first read.
3. `aos::sm::imagemanager::BlobDecryptor::Decrypt`:
   - splits the encrypted file into its IV (first 12 bytes) and the rest (ciphertext and tag);
   - builds a `DecryptInfo{alg: "AES256/GCM", iv, key}` and calls `CryptoHelperItf::Decrypt`, which streams
     the file through AES-256-GCM (OpenSSL/mbedTLS) in the SM process, holding back the trailing 16 bytes
     as the tag. If the tag doesn't match — wrong key, modified or truncated blob — decryption fails and
     the partial output is deleted, so unauthenticated plaintext is never left on disk.
4. The result is the plaintext gzip'd tar, unpacked normally like any other layer.

`CryptoHelperItf::Decrypt` still supports `AES<128|192|256>/CBC/PKCS7PADDING` (16 byte IV), as used for the
cloud-delivered blobs handled by CM, and also accepts `AES<128|192|256>/GCM` (12 byte IV, file =
ciphertext + tag). The padding part of an algorithm name is ignored for GCM.

### Manually verifying an encrypted blob

Useful when a layer fails to install and you want to check, independently of the running node, whether
the `.enc` file and the key on the token actually match. GCM makes this unambiguous: with the wrong key or a
damaged file decryption fails with an authentication error instead of producing garbage.

```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --token-label <token-label> \
  -p "$(cat /var/aos/iam/.usrpin)" --read-object --type data --label aos-layer-key -o /tmp/layerkey.bin
```

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = open("/tmp/layerkey.bin", "rb").read()
blob = open("/path/to/layer.tar.gz.enc", "rb").read()

iv, sealed = blob[:12], blob[12:]  # sealed = ciphertext + 16 byte tag

# raises cryptography.exceptions.InvalidTag if the key or the blob is wrong
open("/tmp/layer.tar.gz.dec", "wb").write(AESGCM(key).decrypt(iv, sealed, None))
```

```bash
od -An -tx1 -N4 /tmp/layer.tar.gz.dec   # expect: 1f 8b 08 00 (gzip magic)
```

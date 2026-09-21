# Key the layer cache by diff ID

## Motivation

The per-layer cache under `~/.cache/airlock/oci/layers/` was keyed by
whatever digest the source handed us. Registry pulls used the manifest's
compressed blob digest. `docker image save` and `podman image save` name
blobs by the digest of the uncompressed tar, the diff ID. The same layer
therefore lived in the cache twice as soon as one project pulled a base
image from a registry and another exported an image built on top of it.
Worse than the disk: the export path skips blobs it already has, so a
docker-built image whose base layers were already pulled still re-streamed
gigabytes of them.

## Changes

* `LAYER_FORMAT` is 3 and the image JSON schema is `v3`. Every layer key
  is now `3.<diff-id hex>`. Old entries are ignored and swept by the
  existing GC.
* Registry path (`oci::ensure_registry_image`): the manifest layer list
  and the config's `rootfs.diff_ids` are the same length and order, so
  layer `i` is cached under `diff_ids[i]`. The download itself is still
  verified against the compressed digest in `registry::pull_layer`. A
  count mismatch between the two lists fails resolution.
* Extractor (`layer::extract_tarball_to_cache`): the decompressed stream
  is hashed while extracting, including the end-of-archive padding the
  tar reader stops short of, and must equal the key before the layer dir
  is committed. On mismatch the staging dir and the staged tarball are
  removed. This is what makes diff-ID keys safe: a registry that lies in
  its config about a diff ID cannot plant content under a key a later
  docker export would trust.
* Docker path: its blobs were already named by diff ID, so they now share
  keys with registry pulls. The hash check it did on each blob before
  staging (`docker::copy_hashing`) is gone, since the extractor check
  covers every source. Its two tests went with it.

# Update Interface to the Bootloader

Within this document, the term 'update-client' refers to any program or
library wishing to interact with the bootloader in order to update one or more
components of the boot sequence.

## Metadata Header

Each stage of the boot sequence leading up to and including the application
(except the root bootloader) is paired with a metadata header (containing
version, size, hash etc.). Information contained in the metadata header allows
validation and ordering of available firmwares.

The firmware metadata header structure can be found [here](https://github.com/ARMmbed/update-client-common/blob/master/update-client-common/arm_uc_metadata_header_v2.h). There are two header formats, internal and external. The external header format is meant to be used when storing firmware on external storage which is assumed to be insecure. Hence the external header format contains extra security information prevent external tampering of the header data.

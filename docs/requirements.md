# Definition

A bootloader is an intermediate stage during system startup responsible for
selecting and forwarding control to the 'next stage' in the boot sequence
based on validation. Optionally, a bootloader can also install an alternate
version of the 'next stage' upon request or upon detection of pathological or
persistent failure.

Boot sequences can be composed of N stages of bootloaders leading to an
'application'. Boot sequences longer than 1 stage allow for upgrade--any stage
can be replaced by another active stage in situ, leading to altered behaviour
when the system restarts. Typically, the first stage isn't replaced because it
is the first thing to get control upon startup, and if an upgraded first-stage
proves to be faulty then recovery may become impossible.

Boot sequences (including the application) may need to evolve over time,
either due to the need for additional features or due to bug-fixes. While
replacing a component in the boot sequence, it may be desirable to retain
older versions (up to a certain maximum number of versions) in order to
protect against faults in the newly installed component. Following an upgrade
to a component, if stage 'n' of the boot sequence starts being unstable,
behaving incorrectly, or needs additional functionality, then the bootloader
at stage 'n-1' can forward control to an alternate (older) version of stage
'n' during the next startup sequence. This results in a boot-sequence tree
which is traversed in a depth-first order as the system recovers from
successive faults.

Fault tolerance ultimately rests on the sanity of the first-stage bootloader--
also referred to in this document as the 'root bootloader' or the 'boot
selector'. This bootloader is usually kept minimal to ensure dependable
operation.

Most boot sequences are usually composed of only three stages:

1. boot selector (fixed, does not change)
1. bootloader (multiple versions stored at once)
1. application (multiple versions stored at once)

## Requirements for the Bootloader

The following subsections detail the requirements for our bootloaders. Another way
to understand the functionality of a bootloader would be to refer to the
[pseudo code](pseudo-code.md) for a generic bootloader.

### Reliable operation

A bootloader should have a minimal feature-set to increase the
likelihood of correct operation. Failures in the boot sequence are expensive
to recover from; failures in some components such as the root bootloader may
not be recoverable.

### Ability to chain bootloaders, and run-time context

Each stage of the boot sequence (except the root bootloader) exposes metadata
about itself (e.g. version, size, hash) using a standard metadata-header.
Information in the header allows a bootloader stage to verify the integrity of
the next stage before forwarding control to it. The Firmware-version in the
metadata defines an ordering for firmwares. This notion of ordering allows a
boot stage to select the best amongst the set of available next-stage
programs.

The following is the proposed structure for the header.

```C
typedef struct FirmwareHeader {
    uint32_t magic;                         /** Metadata-header specific magic code */
    uint32_t version;                       /** Revision number for this generic metadata header. */
    uint32_t checksum;                      /** A checksum of this header. This field should be considered to be zeroed out for
                                             *  the sake of computing the checksum. */
    uint32_t totalSize;                     /** Total space (in bytes) occupied by the firmware BLOB, including headers and any padding. */
    uint64_t firmwareVersion;               /** Version number for the accompanying firmware. Larger numbers imply more preferred (recent)
                                             *  versions. This defines the selection order when multiple versions are available. */
    uint8_t  firmwareSHA256[SIZEOF_SHA256]; /** A SHA-2 using a block-size of 256-bits of the firmware, including any firmware-padding. */
} FirmwareHeader_t;
```

Boot sequences can be composed in stages using increasingly complex
bootloaders leading up to an application. The operation of a bootloader may
depend upon its stage-index in the boot sequence--a bootloader may choose to
behave differently depending on whether it is operating as the root bootloader
or an intermediate bootloader.

A bootloader should at runtime have an awareness of its 'index' in the boot
sequence. The root-bootloader (let's say) has index 0, and each successive
stage leading up to the application has increasing indices. This means that
there could be useful systems where the same bootloader program can be chained
to serve at different stages of a boot sequence.

One way to pass the stage-index as a dynamic parameter into the bootloader is
to use some reserved space in SRAM to pass parameters when transferring
control between stages.

### Shared state between stages

The stages of the boot sequence (together with the 'update-client') share
state with one another through a well-known dictionary of key-value pairs.

The location of this dictionary is a well-known constant defined by the
platform porter, possibly encoded into the linker script. Access to it is
shared between the stages of the boot sequence and any update-client.

The dictionary is meant to hold a small, bounded number of state variables
of the following sort:

  * The following keys are instantiated for every intermediate boot
    stage. Note that in this list the variables with indices
    'nextStageIndex' don't apply to the root-bootloader. And the list of
    variables with indices 'stageIndex' don't apply to the application.
      * "jumpAddressForStage{nextStageIndex}" - this is the target jump location
        of the next boot stage.
      * "locationOfJournalForStage{nextStageIndex}" - this is the location of a
        container for available next-stages.
      * "newFirmwareForStage{nextStageIndex}" - to indicate the availability of
        a next-stage firmware.
      * "commandForStage{stageIndex}" - to set the operation mode for the
        bootloader at stageIndex; for example: "forwardControl",
        "forwardControlToVersion", or "default".
      * "stage{nextStageIndex}IsStable" - to allow stage 'n+1' of the boot
        sequence to be able to confirm to stage 'n' that it has launched and is
        stable.
      * "crashCounterForIndex{nextStageIndex}" - to keep a counter of the number
        of times control has been forwarded to next-stage without it having
        confirmed its stability.
  * Singletons:
      * "rebootReason" - This would be an explicit reason for reboot, such as
        "Failure", or "Update" (to signal the need for an update). The hardware
        may have keep its own view about reboot reason.
      * "lastActiveStage" - last bootloader stage to have received control.
      * "CRASH_COUNTER_THRESHOLD" - the maximum number of times a bootloader at
        stage 'n' may allow booting into stage 'n+1' without receiving
        confirmation that stage 'n+1' is stable.

The dictionary provides the standard 'insert()' and 'lookup()' operations, as
one would expect. Its API looks like the following:

```C
/**
 * Insert or update a key-value pair into the dictionary.
 *
 * @param[in] key
 *              An arbitrary set of bytes used as a key for an entry. Often a string.
 * @param[in] keyLength
 *              Length (in bytes) of the key.
 * @param[in] value
 *              An arbitrary set of bytes used as a value to be associated with
 *              a key. There may be implementation defined upper bounds to the
 *              length of a value.
 * @param[in] valueLength
 *               Length (in bytes) of the value.
 * @return
 *     DICTIONARY_OK(i.e. 0) if the insert or update was successful, else an error code less than 0.
 */
error_t insert(const uint8_t *key, size_t keyLength, const uint8_t *value, size_t valueLength);

/**
 * Lookup a dictionary entry based on a key.
 *
 * @param[in]     key
 *                  An arbitrary set of bytes used as a key for an entry. Often a string.
 * @param[in]     keyLength
 *                  Length (in bytes) of the key.
 * @param[out]    value
 *                  A caller-supplied buffer to fill in with the value if a
 *                  matching entry is found. The length of the buffer is passed
 *                  in using 'valueLength'.
 * @param[in/out] valueLength
 *                  Length of the caller-supplied buffer. It is updated with the size of the fetched value.
 * @return
 *     DICTIONARY_OK(i.e. 0) if the lookup was successful, else an error code less than 0.
 */
error_t lookup(const uint8_t *key, size_t keyLength, uint8_t *value, size_t *valueLength);
```

The dictionary should be checksummed to guard against integrity failures.

Updates to the dictionary should be atomic. In most cases, the writers and
readers of the dictionary are separate--i.e. values in the dictionary are
written by the update-client or from a boot stage other than the one which
reads them back. This removes the need to guard against concurrent accesses.
Nevertheless, if multiple values need to be updated in the dictionary, care
must be take to order the updates to have a single commit-point so that the
system may always recover from an incomplete set of updates.

The implementation of the dictionary is platform-specific. It may be backed
by persistent storage--i.e. non-volatile memory--in systems where the boot
stages need to operate across cold reboots. In simple systems, it may even
be implemented using some reserved, scratch volatile memory area within
SRAM; this would mean that the dictionary could remain valid across warm
resets.

All key-value pairs are bounded in size. Given the number of stages in the
boot sequence, the total payload size of the dictionary should be computable
statically.

### Transfer of control

Firmware can be compiled to have Position-Independent-Code (PIC), in which
case it doesn't matter where it is placed. Position-independent-code, however,
comes with run-time penalties of relative addressing, and is often not the
default choice for application developers. In most cases, firmware is compiled
to run out of a particular start address. This choice is made by the platform
designer and is encoded in the linker script.

We'll assume that bootloaders need to be able to handle non-PIC code.

Each bootloader stage, therefore, needs to know the target jump location of
the next boot stage. This is available through the dictionary state variable
"jumpAddressForStage{nextStageIndex}".

The actual mechanism by which control is transferred to the next stage is
platform-specific. It may involve:

* Being able to set MSP (main-stack-pointer).
* Being able to update VTOR (vector-table-offset-register).
* Being able to set program-counter.

In fault-tolerant, multi-stage boot sequences, each bootloader stage can boot
into one of a set of available next-stages. In the default case, a bootloader
often selects the next-stage firmware with the highest firmware version within
the available set. Once the 'best' firmware is selected, it may still need to
be moved to its intended start location (in the case of non-PIC firmwares)
before transfer of control.

Bootloaders may maintain private containers for available next-stage
firmwares, or perhaps they may share such a container with other boot-stages
and obtain its location from the state variable
"locationOfJournalForStage{nextStageIndex}".

Optionally, it is also desirable for bootloaders to be able to override this
default behaviour of selecting the most recent next stage for forwarding
control--i.e. being able to handle commands such as "forward control to
version XYZ".

### Update

In an upgradeable, multi-stage boot sequence, each boot component should be
able to accept a new firmware for its 'next-stage'. A boot component may
discover availability of next-stage firmwares using the state variable
"newFirmwareForStage{nextStageIndex}". An 'update-client' may simply set such
a variable pointing to the location of a new firmware (accompanied by a
metadata header). The bootloader at stage 'nextStageIndex - 1' would respond
to such information by incorporating the new firmware into its container for
available next-stages.

Incorporating a new next-stage (stage 'n+1') firmware by the stage 'n'
bootloader should have the following properties:

* If the new stage 'n+1' firmware is chosen for installation at the target
  jump location of the next boot stage, the writing of this firmware BLOB
  should be atomic--i.e. a system failure during any part of the writing
  process should result in the partially installed next stage firmware
  appearing invalid.
* If the new stage 'n+1' firmware is chosen to be incorporated in the
  container for available next-stages, that insertion should also be atomic.
  The container should remain coherent in the presence of system failures
  during the insertion.
* To enable rollback, it should be possible to keep a certain maximum number
  of previously committed stage 'n+1's within the container. This maximum
  number should be configurable by the stage 'n' bootloader.
* To enable rollback, it should be possible for the container to yield
  previously committed versions of stage 'n+1'.

### Fault detection and handling

In fault-tolerant systems, there needs to be a way for the boot sequence to
determine that some component of the system has failed. The definition of
failure is platform and application specific. Failures often result in a
system restart; this can be forced to happen automatically (if necessary)
through the use of watchdogs. Restarts offer an opportunity for fault-tolerant
systems to recover from failures.

On many platforms, the system may offer its own notion of failure detection in
the form of a 'reboot reason'. Bootloaders may build upon such system-specific
information to provide a high-level view on causes for system failures, and
may even attempt to isolate failures to particular boot stages.

In general, for multi-stage boot sequences, stage 'n' of the boot sequence
should be able to determine if stage 'n+1' is operating without failure. The
only reliable way to achieve this is to have stage 'n+1' of the boot sequence
confirm to stage 'n' that it has launched previously and is stable. One
mechanism to do that would be to use a state variable such as
"stage{nextStageIndex}IsStable". In the absence of such communication,
bootloaders participating in simple boot sequences may rely upon
"rebootReason" and "lastActiveStage" to infer system stability and determine
the source of any instability.

A bootloader may assume that unless it has been informed explicitly about the
stability of stage 'n+1' (using something like
"stage{nextStageIndex}IsStable"), each system reboot due to failure where
control was transferred to stage 'n+1' may be evidence that stage 'n+1' is
faulty. Bootloaders may also maintain additional state in the dictionary (such
as "lastActiveStage" and "rebootReason") to be more certain of the failing
boot stage.

A bootloader may maintain a key in the dictionary (such as
"crashCounterForIndex{nextStageIndex}") to track faulty operation of stage
'n+1'. It may define an upper bound for "crashCounterForIndex{nextStageIndex}"
in the form of "CRASH_COUNTER_THRESHOLD". Once the crash-counter rises above
the threshold, it may be reasonable to look for a replacement for stage 'n+1'.

Given that a bootloader is able to discover system instability and the stage
in the boot sequence from which the instability arises, when stage 'n+1'
starts to fail, the bootloader at stage 'n' may choose to switch (downgrade)
to an alternate version of stage 'n+1'. A downgrade is possible only if the
bootloader maintains a set of alternate firmwares.

A downgrade begins with invalidating the existing installed version of the
next stage (together with its copy in the container for next stages). Unless
stage 'n+1' is compiled with Position-Independent-Code, a downgrade will
require copying the alternate version of stage 'n+1' to its expected target
jump location.

Downgrades should be atomic. A bootloader may ensure this by writing some
additional metadata at the tail of a firmware BLOB to match with its header;
unless a matching tail is written, a firmware would fail validation. A failed
of incomplete downgrade may just appear to be equivalent to an absent next-
stage firmware; the bootloader involved in the downgrade should be able to re-
attempt the installation of the alternate firmware.

The boot process ultimately relies upon well known images. Typically, the root
bootloader doesn't change. There may also be default, well-known versions of
intermediate bootloaders, and a default, stable version of the application. In
the face of persistent system failures, all bootloaders should ultimately fall
back upon default images to allow system recovery and usability.

### Generic

As far as possible, the bootloader should be built upon abstractions to allow
for generic code. The bootloader relies upon a small subset of CMSIS (most
importantly the Storage driver).

Platform-specific parts of the bootloader may rely upon the following:

* Being able to drive a serial peripheral (such as a UART) for tracing.
* being able to drive an LED (for fault indication).
* Fetching a "Reboot Reason" during system restart.
* Some sort of non-volatile memory to allow communication of commands and
  state between stages of the boot sequence.
* A jump mechanism to transfer control to the next stage. This includes:
  * Being able to set MSP (main-stack-pointer).
  * Being able to update VTOR (vector-table-offset-register).
  * Being able to set program-counter.
* Being able to reset the system upon failure.
* Watchdogs to trigger automatic reset upon faults.

### Tracing

Optionally, each stage of the boot sequence could generate tracing output to
record progress. Each trace message should mention the boot stage and system
time (if available). Each boot stage should also emit trace messages revealing
its build version at startup.

## Boot Selector

The boot selector (also known as the root bootloader or stage-0 bootloader)
can be considered as a specialization of a general bootloader.

The boot selector is small and allows only reduced functionality for the sake
of higher reliability. For many systems, it may only decide which of the
multiple available versions of the stage-1 bootloader to use. The boot
selector may also allow safe updates of the 'stage 1' bootloader.

It is intentionally kept simple to reduce chances of failure. It may even be
that all stage-1 bootloaders are built with Position-Independent-Code so that
the Boot Selector never has to copy a new version of the stage-1 bootloader to
the target jump address; this avoids a source of errors.

## Potential failure points in the operation of a bootloader

The boot sequence can fail at any stage due to a faulty component or due to
the inability of a boot stage in handling of the available versions of the
next-stage. Recovery from such errors can be made by falling back upon
default/well-known versions.

* A big source of failure for a bootloader might be in the use of the Storage
driver (from CMSIS). The Storage driver is involved in maintaining multiple
versions of the next-stage, and in copying an updated version of the next-stage
to its target jump location. These generic storage algorithms may fail
during their use of erase() and/or write() due to eccentricities of the
storage hardware.

* Another source of failures is in the handover of control between stage 'n' and
stage 'n+1' of the boot sequence.

* Yet another source of failures is when an incoming update for stage 'n' is
larger than the space that has been budgeted for it; and the system fails to
accept an update.

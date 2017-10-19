# Pseudo-Code

Given the [requirements for a bootloader](requirements.md), we will present
here the pseudo-code for a generic bootloader.

It supports the following modes of operation:

* 'forwardControl': which forwards control to a previously installed next-stage
  (ignoring any alternate versions).
* 'forwardControlToVersion(.*)': which forwards control to a particular version
  of the next-stage.
* 'default': which checks for alternate versions before forwarding control to
  the best available next-stage firmware.

It makes the following assumptions:

* The bootloader is able to select a 'bestAlternative' from the 'journal' of next-stage firmwares.
* The journal is able to 'invalidate' a particular next-stage firmware.
* The journal allows lookups based on firmware metadata--particularly firmware version.
* The 'jumpTo()' is able to communicate a stageIndex value to the next-stage
  firmware, possibly using some scratch memory area in the SRAM.
* The 'valid()' method for a firmware object does validation based on checksums in the header.
* The 'copyTo()' method of a firmware object resets the key "crashCounterForIndex{nextStageIndex}".


```python
## Bootloader's main entry point.
#
# @param stageIndex
#          The run-time index of this bootloader in the boot sequence. Boot
#          selector has index 0 known to it at compile time. Each successive
#          bootloader can be passed in a 'stageIndex' at runtime through 'jumpTo()'.
def bootloader(stageIndex):
    global locationOfSharedDictionary # This is a well-known constant defined by the platform
                                      # porter, possibly encoded into the linker script.
    dictionary = SharedDictionary(locationOfSharedDictionary)

    # discover nextStageJumpAddress
    nextStageJumpAddress = dictionary.get("jumpAddressForStage{}".format(stageIndex + 1))
    if nextStageJumpAddress is None:
        resortToFactoryDefault(stageIndex + 1) or raise BootFailed("failed to find nextStageJumpAddress") # failure
    # discover locationOfJournal
    locationOfJournal = dictionary.get("locationOfJournalForStage{}".format(stageIndex + 1))
    if locationOfJournal is None:
        resortToFactoryDefault(stageIndex + 1) or raise BootFailed("failed to find locationOfJournal") # failure

    nextStageFirmware = NextStageFirmware(nextStageJumpAddress)                     # synonym for 'next stage'
    journal           = ContainerForAlternateVersionsOfNextStage(locationOfJournal) # container for alternate next-stage firmwares

    # handle 'rebootReason'
    rebootReason = System.fetchRebootReason() or dictionary.get("rebootReason", "unknown")
    if rebootReason is not None:
        lastActiveStage = dictionary.get("lastActiveStage", "-1")
        if lastActiveStage == (stageIndex + 1):
            if rebootReason == "Failure":
                journal.invalidate(nextStageFirmware.metadata())
                nextStageFirmware.markAsInvalid()

            # reset reboot reason (if necessary)
            System.resetRebootReason()
            dictionary.set("rebootReason", None)
        elif lastActiveStage is None:
            # reset reboot reason (if necessary)
            System.resetRebootReason()
            dictionary.set("rebootReason", None)

    # Update 'lastActiveStage' with our own stageIndex.
    dictionary.set("lastActiveStage", stageIndex);

    # Incorporate new firmware (if available) into journal.
    locationOfNewFirmware = dictionary.get("newFirmwareForStage{}".format(stageIndex + 1), None)
    if locationOfNewFirmware is not None:
        newFirmware = NextStageFirmware(locationOfNewFirmware)
        if newFirmware.valid() and not journal.has(newFirmware):
            journal.incorporate(newFirmware)

    # Fetch the 'operationMode' command, if available.
    operationalMode = dictionary.get("commandForStage{}".format(stageIndex), "default")

    # Handle request for forwarding control to a previously installed next-stage
    # (without checking for alternate versions).
    if operationalMode == "forwardControl":
        if nextStageFirmware.valid():
            try:
                transferControlTo(stageIndex, nextStageJumpAddress, nextStageFirmware, dictionary, journal)
            except NextStageUnstableException as e:
                # A crash-counter failure would have implicitly invalidated the
                # firmware. Fall back to picking the best from among alternate versions.
                operationalMode = "default"
        else:
            # Fall back to picking the best from among alternate versions.
            operationalMode = "default"

    # Handle request for forwarding control to a particular version
    m = re.match("forwardControlToVersion(.*)", operationalMode)
    if m:
        requestedVersion = m.group(0)

        if nextStageFirmware.valid() and (nextStageFirmware.version() == requestedVersion):
            try:
                transferControlTo(stageIndex, nextStageJumpAddress, nextStageFirmware, dictionary, journal)
            except NextStageUnstableException as e:
                # A crash-counter failure would have implicitly invalidated the
                # firmware. Reset the operationMode configured in the 'dictionary'.
                dictionary.set("commandForStage{}".format(stageIndex), "default")

        alternativeFirmware = journal.fetchVersion(requestedVersion)
        if alternativeFirmware.valid():
            alternativeFirmware.copyTo(nextStageJumpAddress)
            transferControlTo(stageIndex, nextStageJumpAddress, alternativeFirmware, dictionary, journal)

        # fall back to alternate versions
        operationalMode = "default"

    # Default operation is to check for alternate versions before forwarding
    # control to the best available firmware.
    assert(operationalMode == "default")
    while True :
        bestAlternative = journal.bestAlternative()
        if not bestAlternative.valid() and not nextStageFirmware.valid():
            resortToFactoryDefault(stageIndex + 1) or raise BootFailed("failed to find valid alternative for next-stage") # failure

        if bestAlternative.valid():
            if (not nextStageFirmware.valid()) or (bestAlternative.version() > nextStageFirmware.version())
                bestAlternative.copyTo(nextStageJumpAddress)

        try:
            transferControlTo(stageIndex, nextStageJumpAddress, nextStageFirmware, dictionary, journal)
        except NextStageUnstableException as e:
            # A crash-counter failure would have implicitly invalidated the
            # firmware. Continuing with this loop would pick the next
            # alternative.
            pass

## Pass control to the next stage.
#
# There is no return from this method unless we discover that the next-stage has
# been un-reliable and we choose not to forward control to it.
def transferControlTo(thisStageIndex, nextStageJumpAddress, nextStageFirmware, dictionary, journal):
    nextStageIndex = thisStageIndex + 1

    try:
        validateNextStageForStability(dictionary, nextStageIndex)
    except NextStageUnstableException as e:
        # Mark nextStageFirmware as invalid.
        journal.invalidate(nextStageFirmware.metadata())
        nextStageFirmware.markAsInvalid()

        # Some alternate version of the next firmware will be installed as a
        # result of this exception. Reset the crashCounter in preparation for
        # the new firmware.
        dictionary.set("crashCounterForIndex{}".format(nextStageIndex), 0)

        # Continue to propagate the exception.
        raise NextStageUnstableException()

    # A bootloader can mark itself 'stable' once it can pass control.
    dictionary.set("stage{}IsStable".format(thisStageIndex), True)

    jumpTo(nextStageJumpAddress, nextStageIndex) # Control passes on to the next
                                                 # stage bootloader or application
                                                 # passing the value of 'nextStageIndex'
                                                 # as a parameter; if this is successful
                                                 # there is no return to the caller.

# There isn't a definite way to establish the stability of the next stage. We
# attempt to do this in combination with information from the next-stage. Once
# the next stage firmware knows itself to be stable (whatever that criteria
# might be), it can set the variable "stage{nextStageIndex}IsStable" as
# True in the shared dictionary. Until that happens, the current bootloader
# will attempt to forward control to a potentially faulty next-stage
# CRASH_COUNTER_THRESHOLD number of times (using the variable
# "crashCounterForIndex{nextStageIndex}").
#
# Note: this part of the bootloader is very specific to the platform and the
# application.
def validateNextStageForStability(dictionary, nextStageIndex):
    nextStageStable = dictionary.get("stage{}IsStable".format(nextStageIndex), False)
    if not nextStageStable:
        crashCounter            = dictionary.get("crashCounterForIndex{}".format(nextStageIndex), "0")
        CRASH_COUNTER_THRESHOLD = dictionary.get("CRASH_COUNTER_THRESHOLD", 4)
        if crashCounter < CRASH_COUNTER_THRESHOLD:
            # increment and update crash counter
            crashCounter = crashCounter + 1
            dictionary.set("crashCounterForIndex{}".format(nextStageIndex), crashCounter)
        else:
            raise NextStageUnstableException()
```

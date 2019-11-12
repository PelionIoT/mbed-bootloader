# Releasing Bootloader

This page describes release process of Mbed Bootloader.

First, I'm going to describe steps, and then follow with detailed information what each step does.

## Steps

1. Check CI results and manual test results to verify release is in OK condition.
1. Create PR into a release branch in Github. For example from `master` to `mbed-os-5.14` branch.
1. If OK merge. (Not rebase, or squash. Need merge commit)
1. Pull in the release branch into your local machine.
1. Tag, for example `git tag -a v4.1.0` and write release notes into the annotated tag message.
1. push tag into Github
1. Restart build job for release branch to update binary names with correct tag.
1. (if not done) Clone `mbed-bootloader` repository
1. Run `./.sync_to_staging.sh ../mbed-bootloader`
1. Create same version tag with same message into mbed-bootloader repo. Push out.
1. Send email to client team about release. Copy&paste release notes.

## (Optional) Manually generating binary releas

1. If you are working off of a local copy, clean up any local changes, and pull to update to latest master or release branch.
1. Remove **BUILD** directory.
1. Create `release` directory.
1. Run script in the root directly of the bootloader repo: `python scripts/make_release.py -o release`.
   Or to release a single target `python scripts/make_release.py -o ../mbed-cloud-client-example-internal -m K64F -c internal_flash_sotp`

   This script does the following things:
    1. Fill [mbed_bootloader_info.h](https://github.com/ARMmbed/mbed-bootloader-internal/blob/master/mbed_bootloader_info.h) with the latest commit SHA-1 in the current repo.
    1. Compile application with a release compile profile
    1. Copy binary to the `release/` folder
    1. Generate results.txt with details about binary names, and SHA1 location within the bootloader. This information is parsed from the symbol bootloader in the .map file.
1. Release content is now located in `release/`

## CI generated binary release

1. `Jenkinsfile` contains list of targets to build. These must match what Client team extect to be in binary release.
1. When Jenkinsjob deploys the repository, it runs `./scripts/make_release.py --patch -o release` to update SHA hash in the header file.
1. All targets in the `build_test_config[]` are built.
1. Greentea and smoke tests are ran.
1. One passed, binary release content is generated with `/scripts/make_release.py -o release --prebuilt`
1. Release content is stored in build job's archive.

## Adding a new platform

1. Define a working configuration for target in one of the `app.json` files.
1. Modify `make_release.py`. Add your target and configuration you want to build in the `targets` variable.
1. Modify `Jenkinsfile` to build this target.
1. Make PR to bootloader repo to add your new configurations.
1. Verify from build artifact that binary release is working.


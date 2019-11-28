//----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorised under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C) COPYRIGHT 2019 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

repoName = "mbed-bootloader"

// This build archives artifacts at build stage and later on copies artifacts
// on the later state. Permission is needed for copying, even for the job itself.
// Instructions from here: https://stackoverflow.com/questions/47771722/grant-copy-artifact-permission-in-multi-branch-pipeline?rq=1
// Also, we trigger master branch rebuild every night
if (env.BRANCH_NAME == "master") {
  properties([[$class: 'CopyArtifactPermissionProperty', projectNames: '*'], pipelineTriggers([cron('H H(0-4) * * *')])])
} else {
  properties([[$class: 'CopyArtifactPermissionProperty', projectNames: '*'], pipelineTriggers([])])
}
toolchains = [
  ARM: "armcc",
  GCC_ARM: "arm-none-eabi-gcc",
  IAR: "iar_arm"
]

// RaaS allocation timeout
raas_timeout = 1200

// Initial maps for parallel build steps
def buildStepsForParallel = [:]
def runStepsForParallel = [:]
def smokeTests = [:]

def deployBootloaderRepoStep() {
  return {
    stage ("deploy_bootloader_repo") {
      node ("all-in-one-build-slave") {
        dir(repoName) {
          deleteDir()
          checkout scm
          sh ('''
            mbed deploy --protocol ssh
            mbed ls
            mkdir release
            python ./scripts/make_release.py --patch -o release
            cd mbed-os
            git archive -o ../mbed.tar HEAD
            cd ..
            tar cjf mbed-bootloader.tar.bz2 --exclude mbed-os --exclude mbed-bootloader.tar.bz2 * .[a-z]*
          ''')
          stash name: "deployed_bootloader_repo", includes: "mbed-bootloader.tar.bz2", useDefaultExcludes: false
        }
      }
    }
  }
}

def bootloaderBuildStep(stepName,
                        target,
                        toolchain,
                        repoName,
                        mbed_app_json) {
  return {
    stage (stepName) {
      node ("all-in-one-build-slave") {
        dir(repoName) {
          // get the deployed source code from previous step
          deleteDir()
          unstash "deployed_bootloader_repo"
          sh ('''
            tar xjf mbed-bootloader.tar.bz2
            mkdir mbed-os
            tar xf mbed.tar -C mbed-os
            mbed config root .
          ''')
          def build_dir = mbed_app_json[0..-6]
          if (build_dir.indexOf('/') != -1) {
            build_dir = build_dir.tokenize('/')[1]
          }
          build_dir = "BUILD/" + build_dir + "/${target}/${toolchain}"

          // build with default setup
          sh ("""
            mbed --version
            mbed compile -m ${target} -t ${toolchain} --app-config ${mbed_app_json} --build ${build_dir} --profile release
          """)

          // Archive the binary
          def file_extension = ("${target}" == "NRF52_DK" || "${target}" == "NRF52840_DK" || "${target}" == "LPC55S69_NS") ? "hex" : "bin"
          def binary_path = build_dir + "/${repoName}.${file_extension}"
          archiveArtifacts artifacts: binary_path
          archiveArtifacts artifacts: build_dir + "/${repoName}_application.map"
        }
      }
    }
  }
}

def build_test_config = [
  // Bootloaders for Smoke test using internal flash
  ["DISCO_L475VG_IOT01A", "mbed_app.json", "GCC_ARM"],
  ["K64F",                "mbed_app.json", "GCC_ARM"],
  ["NRF52840_DK",         "mbed_app.json", "GCC_ARM"],
  ["NUCLEO_F303RE",       "mbed_app.json", "GCC_ARM"],
  ["NUCLEO_F411RE",       "mbed_app.json", "GCC_ARM"],
  ["NUCLEO_F429ZI",       "mbed_app.json", "GCC_ARM"],

  // Bootloaders for just testing the build
  ["NRF52840_DK",   "configs/kvstore_and_fw_candidate_on_sd.json", "GCC_ARM"],
  ["NUCLEO_L073RZ", "configs/kvstore_and_fw_candidate_on_sd.json", "GCC_ARM"],
  ["DISCO_L475VG_IOT01A", "configs/external_kvstore_with_qspif.json", "GCC_ARM"],
  ["NUCLEO_H743ZI2", "configs/internal_flash_no_rot.json", "GCC_ARM"],

  // Bootloaders for release.
  // NOTE: Must match make_release.py
  ["K64F", "configs/kvstore_and_fw_candidate_on_sd.json", "GCC_ARM"],
  ["K64F", "configs/internal_flash_no_rot.json",          "GCC_ARM"],
  ["K64F", "configs/internal_kvstore_with_sd.json",       "GCC_ARM"],
  ["K66F", "configs/internal_flash_no_rot.json",          "GCC_ARM"],
  ["NRF52840_DK",         "configs/internal_kvstore_with_qspif.json",    "GCC_ARM"],
  ["NUCLEO_L4R5ZI",       "configs/internal_flash_no_rot.json",          "GCC_ARM"],
  ["NUCLEO_F429ZI",       "configs/internal_flash_no_rot.json",          "GCC_ARM"],
  ["UBLOX_EVK_ODIN_W2",   "configs/internal_kvstore_with_sd.json",       "GCC_ARM"],
  ["NUCLEO_F411RE",       "configs/kvstore_and_fw_candidate_on_sd.json", "GCC_ARM"],
  ["DISCO_L475VG_IOT01A", "configs/internal_kvstore_with_qspif.json",    "GCC_ARM"],
  ["LPC55S69_NS",         "configs/psa.json",                            "GCC_ARM"],
  ["NUCLEO_F303RE",       "configs/internal_kvstore_with_spif.json",     "GCC_ARM"],
]


for (int i = 0; i < build_test_config.size(); i++) {
  def target        = build_test_config[i][0]
  def mbed_app_json = build_test_config[i][1]
  def toolchain     = build_test_config[i][2]
  def stepName      = "build_test_${target}_${toolchain}_${mbed_app_json}"
  buildStepsForParallel[stepName] = bootloaderBuildStep(stepName,
                                                        target,
                                                        toolchain,
                                                        repoName,
                                                        mbed_app_json)
}

def greenteaTestStep(step_name,
                     target,
                     toolchain,
                     raas,
                     repo_name) {
  return {
    stage(step_name) {
      node("all-in-one-build-slave") {
        dir(repo_name) {
          deleteDir()
          unstash "deployed_bootloader_repo"
          sh ("""
            tar xjf mbed-bootloader.tar.bz2
            mkdir mbed-os
            tar xf mbed.tar -C mbed-os
            mbed config root .
            ls -al

            # remove bootloader application main file
            rm source/main.cpp

            # build greentea tests
            mbed test --compile -m ${target} -t ${toolchain} -n '*bootloader-hmac*' --app-config configs/test_configs/greentea.json
          """)
          env.RAAS_USERNAME = "ci"
          env.RAAS_PASSWORD = "ci"
          env.RAAS_PYCLIENT_FORCE_REMOTE_ALLOCATION = 1
          env.RAAS_PYCLIENT_ALLOCATION_QUEUE_TIMEOUT = raas_timeout

          // Only run if the test_spec.json is not empty
          def test_spec_json_empty = sh (
            script: """grep -c "\\"tests\\": {}" BUILD/tests/${target}/${toolchain}/test_spec.json || exit 0""",
            returnStdout: true
          )
          echo "Printing test_spec_json_empty: [${test_spec_json_empty}]"
          if (test_spec_json_empty.trim() == "1") {
            echo "test_spec.json is empty, no tests to run"
          } else {
            sh ("mbedgt -g ${target}:raas_client:${raas}:443 -vV")
          }
        }
      }
    }
  }
}

// Only HMAC tests remains in Greentea. This test is equivalent of unittest for
// ARM_UC_cryptoHMACSHA256(), and relies entirely on Mbed TLS and its SHA256 functions.
// Those are already tested in Mbed OS, and therefore we use minimal number of targets here
// for testing the ARM_UC_cryptoHMACSHA256().
def greentea_test_config = [
  "K64F":           ["toolchains": ["GCC_ARM"], "raas": "https://eeva.mbedcloudtesting.com"],
  "NUCLEO_F429ZI":  ["toolchains": ["GCC_ARM"], "raas": "https://ruka.mbedcloudtesting.com"],
]

for (target in greentea_test_config.keySet()) {
  for (toolchain in greentea_test_config[target]["toolchains"]) {

    def raas = greentea_test_config[target]["raas"]
    def step_name = "greentea_test_${target}_${toolchain}"

    runStepsForParallel[step_name] = greenteaTestStep(step_name,
                                                      target,
                                                      toolchain,
                                                      raas,
                                                      repoName)
  }
}

def SmokeTestStep(step_name,
                     target,
                     toolchain,
                     raas,
                     repo_name) {
  return {
    stage(step_name) {
      node("all-in-one-build-slave") {
        dir(repo_name) {
          env.RAAS_USERNAME = "ci"
          env.RAAS_PASSWORD = "ci"
          env.RAAS_PYCLIENT_FORCE_REMOTE_ALLOCATION = 1
          env.RAAS_PYCLIENT_ALLOCATION_QUEUE_TIMEOUT = raas_timeout

          deleteDir()
          unstash "deployed_bootloader_repo"
          sh ('''
            tar xjf mbed-bootloader.tar.bz2
            mkdir mbed-os
            tar xf mbed.tar -C mbed-os
          ''')
          copyArtifacts filter: '**/mbed-bootloader.*', projectName: '${JOB_NAME}', selector: specific('${BUILD_NUMBER}')
          dir('TESTS/smoke') {
            sh "./build.sh ${target}"
            archiveArtifacts artifacts: "**/${target}_smoke.*"
            sh "./test.sh ${target} ${raas}"
          }
        }
      }
    }
  }
}

def smoke_test_config = [
  "DISCO_L475VG_IOT01A": ["toolchains": [ "GCC_ARM"], "raas": "https://auli.mbedcloudtesting.com:443"],
  "K64F":           ["toolchains": [ "GCC_ARM"], "raas": "https://ruka.mbedcloudtesting.com:443"],
  "NRF52840_DK":    ["toolchains": [ "GCC_ARM"], "raas": "https://auli.mbedcloudtesting.com:443"],
  "NUCLEO_F303RE":  ["toolchains": [ "GCC_ARM"], "raas": "https://auli.mbedcloudtesting.com:443"],
  "NUCLEO_F411RE":  ["toolchains": [ "GCC_ARM"], "raas": "https://ruka.mbedcloudtesting.com:443"],
  "NUCLEO_F429ZI":  ["toolchains": [ "GCC_ARM"], "raas": "https://ruka.mbedcloudtesting.com:443"],
]

for (target in smoke_test_config.keySet()) {
  for (toolchain in smoke_test_config[target]["toolchains"]) {

    def raas = smoke_test_config[target]["raas"]
    def step_name = "smoke_${target}_${toolchain}"

    smokeTests[step_name] = SmokeTestStep(step_name,
                                          target,
                                          toolchain,
                                          raas,
                                          repoName)
  }
}

def ReleaseStep() {
  return {
    stage ("release_bootloader") {
      node ("all-in-one-build-slave") {
        dir(repoName) {
          deleteDir()
          unstash "deployed_bootloader_repo"
          copyArtifacts filter: '**/mbed-bootloader*', projectName: '${JOB_NAME}', selector: specific('${BUILD_NUMBER}')
          sh ('''
            tar xjf mbed-bootloader.tar.bz2
            mkdir mbed-os
            tar xf mbed.tar -C mbed-os
            mkdir -p release
            python ./scripts/make_release.py -o release --prebuilt
          ''')
          archiveArtifacts artifacts: 'release/*'
        }
      }
    }
  }
}
/* Jenkins does not allow stages inside parallel execution,
 * https://issues.jenkins-ci.org/browse/JENKINS-26107 will solve this by adding labeled blocks
 */
// Actually run the steps in parallel - parallel takes a map as an argument, hence the above.
timestamps {
  parallel "deploy_bootloader": deployBootloaderRepoStep()
  parallel buildStepsForParallel
  parallel smokeTests + runStepsForParallel
  parallel "release_bootloader": ReleaseStep()
}

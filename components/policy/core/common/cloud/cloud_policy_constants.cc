// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/policy/core/common/cloud/cloud_policy_constants.h"

#include <stdint.h>

#include "base/command_line.h"
#include "build/build_config.h"
#include "components/policy/core/common/policy_switches.h"

namespace policy {

// Constants related to the device management protocol.
namespace dm_protocol {

// Name constants for URL query parameters.
const char kParamAgent[] = "agent";
const char kParamAppType[] = "apptype";
const char kParamCritical[] = "critical";
const char kParamDeviceID[] = "deviceid";
const char kParamDeviceType[] = "devicetype";
const char kParamLastError[] = "lasterror";
const char kParamOAuthToken[] = "oauth_token";
const char kParamPlatform[] = "platform";
const char kParamRequest[] = "request";
const char kParamRetry[] = "retry";
const char kParamProfileID[] = "profileid";

// Policy constants used in authorization header.
const char kAuthHeader[] = "Authorization";
const char kServiceTokenAuthHeaderPrefix[] = "GoogleLogin auth=";
const char kDMTokenAuthHeaderPrefix[] = "GoogleDMToken token=";
const char kEnrollmentTokenAuthHeaderPrefix[] = "GoogleEnrollmentToken token=";
const char kOAuthTokenHeaderPrefix[] = "OAuth";
const char kOidcAuthHeaderPrefix[] = "GoogleDM3PAuth";
const char kOidcAuthTokenHeaderPrefix[] = " oauth_token=";
const char kOidcIdTokenHeaderPrefix[] = " id_token=";
const char kOidcEncryptedUserInfoPrefix[] = " encrypted_user_information=";

// String constants for the device and app type we report to the server.
const char kValueAppType[] = "Chrome";
const char kValueBrowserUploadPublicKey[] = "browser_public_key_upload";
const char kValueDeviceType[] = "2";
const char kValueRequestAutoEnrollment[] = "enterprise_check";
const char kValueRequestPsmHasDeviceState[] = "enterprise_psm_check";
const char kValueCheckUserAccount[] = "check_user_account";
const char kValueRequestPolicy[] = "policy";
const char kValueRequestRegister[] = "register";
const char kValueRequestRegisterProfile[] = "register_profile";
const char kValueRequestApiAuthorization[] = "api_authorization";
const char kValueRequestUnregister[] = "unregister";
const char kValueRequestUploadCertificate[] = "cert_upload";
const char kValueRequestUploadEuiccInfo[] = "upload_euicc_info";
const char kValueRequestDeviceStateRetrieval[] = "device_state_retrieval";
const char kValueRequestUploadStatus[] = "status_upload";
const char kValueRequestRemoteCommands[] = "remote_commands";
const char kValueRequestDeviceAttributeUpdatePermission[] =
    "device_attribute_update_permission";
const char kValueRequestDeviceAttributeUpdate[] = "device_attribute_update";
const char kValueRequestGcmIdUpdate[] = "gcm_id_update";
const char kValueRequestCheckAndroidManagement[] = "check_android_management";
const char kValueRequestCertBasedRegister[] = "certificate_based_register";
const char kValueRequestTokenBasedRegister[] = "token_based_register";
const char kValueRequestActiveDirectoryEnrollPlayUser[] =
    "active_directory_enroll_play_user";
const char kValueRequestActiveDirectoryPlayActivity[] =
    "active_directory_play_activity";
const char kValueRequestAppInstallReport[] = "app_install_report";
const char kValueRequestRegisterBrowser[] = "register_browser";
const char kValueRequestRegisterPolicyAgent[] = "register_policy_agent";
const char kValueRequestChromeDesktopReport[] = "chrome_desktop_report";
const char kValueRequestChromeOsUserReport[] = "chrome_os_user_report";
const char kValueRequestInitialEnrollmentStateRetrieval[] =
    "device_initial_enrollment_state";
const char kValueRequestUploadPolicyValidationReport[] =
    "policy_validation_report";
const char kValueRequestPublicSamlUser[] = "public_saml_user_request";
const char kValueRequestCertProvisioningRequest[] = "client_cert_provisioning";
const char kValueRequestChromeProfileReport[] = "chrome_profile_report";
const char kValueRequestFmRegistrationTokenUpload[] =
    "fm_registration_token_upload";
const char kValueRequestDeterminePromotionEligibility[] =
    "promotion_eligibility";

const char kChromeDevicePolicyType[] = "google/chromeos/device";
#if BUILDFLAG(IS_CHROMEOS)
const char kChromeUserPolicyType[] = "google/chromeos/user";
#elif BUILDFLAG(IS_ANDROID)
const char kChromeUserPolicyType[] = "google/android/user";
#elif BUILDFLAG(IS_IOS)
const char kChromeUserPolicyType[] = "google/ios/user";
#else
const char kChromeUserPolicyType[] = "google/chrome/user";
#endif
const char kChromePublicAccountPolicyType[] = "google/chromeos/publicaccount";
const char kChromeExtensionPolicyType[] = "google/chrome/extension";
const char kChromeSigninExtensionPolicyType[] =
    "google/chromeos/signinextension";

const char kChromeMachineLevelUserCloudPolicyType[] =
#if BUILDFLAG(IS_ANDROID)
    "google/chrome/machine-level-user-android";
#elif BUILDFLAG(IS_IOS)
    "google/chrome/machine-level-user-ios";
#else
    "google/chrome/machine-level-user";
#endif
const char kChromeMachineLevelExtensionCloudPolicyType[] =
    "google/chrome/machine-level-extension";
const char kChromeRemoteCommandPolicyType[] = "google/chromeos/remotecommand";

// A policy type which is expanded to google/machine-level-omaha,
// google/chrome/machine-level-user, and google/chrome/machine-level-extension
// on the server side. This type is used by policy agents (i.e. GoogleUpdater
// and Chrome Enterprise Companion App) on Linux, Mac, and Windows.
// TODO(b/361632880): Consider removing this if google/machine-level-omaha can
// be requested directly.
const char kGoogleUpdateMachineLevelAppsPolicyType[] =
    "google/machine-level-apps";

const char kGoogleUpdateMachineLevelOmahaPolicyType[] =
    "google/machine-level-omaha";

const char kChromeAshUserRemoteCommandType[] = "google/ash/user/remotecommand";
const char kChromeDeviceRemoteCommandType[] = "google/ash/device/remotecommand";
const char kChromeBrowserRemoteCommandType[] =
    "google/chrome/browser/remotecommand";
const char kChromeUserRemoteCommandType[] = "google/chrome/user/remotecommand";

const char kChromeMachineLevelUserCloudPolicyTypeBase64[] =
    "Z29vZ2xlL2Nocm9tZS9tYWNoaW5lLWxldmVsLXVzZXI=";

}  // namespace dm_protocol

const uint8_t kPolicyVerificationKey[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xd3, 0x06, 0x3f,
    0xce, 0x35, 0xa3, 0x52, 0x2e, 0xd1, 0xd9, 0x9d, 0xb1, 0x44, 0x9f, 0x5a,
    0x25, 0xb6, 0x70, 0x9e, 0xa0, 0x34, 0x11, 0xbb, 0x16, 0xe8, 0x7d, 0x57,
    0xcd, 0x16, 0xa7, 0x3f, 0x1f, 0xd8, 0xd3, 0x95, 0x97, 0x80, 0x2f, 0x51,
    0x40, 0x21, 0x86, 0x9b, 0x33, 0x48, 0x6a, 0xda, 0x44, 0x8d, 0x50, 0xb3,
    0x33, 0x26, 0xdd, 0xec, 0x2e, 0xbd, 0xc1, 0xaf, 0x3e, 0xa7, 0xd7, 0x39,
    0x11, 0xfb, 0x4b, 0x79, 0xb0, 0xbb, 0xac, 0x9f, 0xbd, 0xfe, 0x69, 0x55,
    0x28, 0xef, 0x93, 0xda, 0x15, 0xe2, 0x92, 0xa8, 0x46, 0x12, 0x0b, 0x8f,
    0xab, 0x66, 0x8c, 0xbe, 0xc1, 0xdd, 0x67, 0x61, 0x9a, 0x0a, 0xa2, 0x5a,
    0xef, 0xe8, 0x52, 0xfb, 0xbe, 0xe2, 0x96, 0x4f, 0x69, 0x81, 0x8c, 0x13,
    0x28, 0xea, 0x43, 0x5b, 0x2d, 0x79, 0xc2, 0x6d, 0xc8, 0x0e, 0xa6, 0xeb,
    0xe4, 0x66, 0x7b, 0xfe, 0x88, 0x4e, 0x80, 0x04, 0x4a, 0x35, 0x1a, 0x6b,
    0xe3, 0xe1, 0x9a, 0xf2, 0x66, 0xad, 0x67, 0xe0, 0x6d, 0x23, 0x4e, 0x20,
    0xe4, 0x8c, 0xa9, 0x17, 0x71, 0x39, 0xd8, 0xea, 0x3a, 0x90, 0x39, 0xb0,
    0x72, 0xbf, 0xbf, 0x21, 0x74, 0x95, 0xd8, 0xb9, 0xa1, 0x79, 0xd8, 0x2e,
    0x1a, 0x55, 0xca, 0xd6, 0x3f, 0xae, 0xa5, 0x48, 0xb3, 0x67, 0x71, 0xd0,
    0x79, 0x8e, 0x12, 0xf4, 0xb9, 0x12, 0x2f, 0x58, 0x3f, 0x79, 0x44, 0x93,
    0xc6, 0x51, 0x5f, 0x2d, 0xb9, 0x7d, 0xd9, 0x65, 0x67, 0xff, 0x51, 0x1a,
    0xd8, 0x80, 0x16, 0x52, 0x2a, 0x14, 0x44, 0xd7, 0x71, 0xdc, 0x9c, 0xbf,
    0x09, 0x05, 0x9f, 0xe5, 0xba, 0x33, 0x8e, 0x0a, 0xe4, 0xf4, 0xcf, 0xc3,
    0xcb, 0x30, 0x61, 0xfe, 0x3c, 0x99, 0x33, 0x65, 0xd5, 0x12, 0x5c, 0x4d,
    0x01, 0xc6, 0xf2, 0xf6, 0x4f, 0xc8, 0x40, 0x45, 0x76, 0x17, 0x2b, 0xe8,
    0xb5, 0x02, 0x03, 0x01, 0x00, 0x01};

const char kPolicyVerificationKeyHash[] = "1:356l7w";

const char kDemoModeDomain[] = "cros-demo-mode.com";

std::string GetPolicyVerificationKey() {
  return std::string(reinterpret_cast<const char*>(kPolicyVerificationKey),
                     sizeof(kPolicyVerificationKey));
}
// Notes from the past: When the key is rotated in the future, the old one may
// still worth being kept to verified any existing policy cache so that browser
// can load it one last time. However, it really depends on the reason of the
// rotation. From a different angle, if a key is no longer trusted, so should
// anything bound to it.

}  // namespace policy

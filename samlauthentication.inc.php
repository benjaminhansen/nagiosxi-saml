<?php

// include the xi component helper
require_once(dirname(__FILE__) . '/../componenthelper.inc.php');

// include the xi common include
require_once(dirname(__FILE__) . '../../../common.inc.php');

// let's do this...
samlauthentication_component_init();

function samlauthentication_component_init() {
    // information to pass to xi about our component
    $args = [
        COMPONENT_NAME              => "samlauthentication",
        COMPONENT_VERSION           => "1.1",
        COMPONENT_AUTHOR            => "BJ Hansen <bjhansen@benjaminhansen.net>",
        COMPONENT_DESCRIPTION       => "SAML Authentication Component for Nagios XI",
        COMPONENT_CONFIGFUNCTION    => "saml_config_func",
        COMPONENT_TITLE             => "SAML Authentication"
    ];

    // register with xi
    register_component("samlauthentication", $args);

    // register the default authentication override
    register_callback(CALLBACK_HEADER_START, 'override_default_authentication');
}

function override_default_authentication() {
    $app_url = get_option('url');
    $saml_url = "{$app_url}includes/components/samlauthentication/";

    if (empty($_SESSION["session_id"]) || is_null($_SESSION["session_id"])) {
        // user is not auth'd
        $saml_enabled = get_option('saml2_enabled', false);
        $saml_force_sso = get_option('saml2_force_sso', false);

        if($saml_enabled) {
            // saml is enabled in the component settings
            if(!$saml_force_sso || isset($_GET['sso_bypass'])) {
                // if the force saml option is not enabled, or the user has passed the ?sso_bypass querystring in the URL

                $content = '

                    <script>
                        $(document).ready(function(){
                            var loginbox = $(".login-box .well");
                            if(loginbox.is(":visible")) {
                                // we are on the login page
                                var custom_html = "<style>'.str_replace(["\n", "<br />", "\r"], " ", htmlentities(get_option('saml2_login_button_styles'))).'</style><br /><hr /><br />'.get_option('saml2_login_text', 'Sign-in with SSO').'<br /><a id=\'saml2-login-button\' href=\''.$saml_url.'?sso\' title=\''.get_option('saml2_login_text', 'Sign-in with SSO').'\'>";
                ';

                if(!empty(get_option('saml2_login_button_logo'))) {
                    $content .= '

                        custom_html += "<img src=\''.get_option('saml2_login_button_logo').'\' alt=\'SAML Login Button Image\' />";

                    ';
                }

                $content .= '
                                custom_html += "'.get_option('saml2_login_button_text', 'Sign In Now').'</a>";
                                loginbox.append(custom_html);
                            }
                        });
                    </script>

                ';

                echo $content;

                return;
            }

            // need to find a better way to do this...
            die("<script>window.location.href = '$saml_url?sso';</script>");
        }

        return;
    }

    return;
}

function saml_config_func($mode = "", $inargs, &$outargs, &$result) {
    switch ($mode) {
        case COMPONENT_CONFIGMODE_GETSETTINGSHTML:
            $saml_enabled = get_option('saml2_enabled', false);
            $saml_strict = get_option('saml2_strict', false);
            $saml_debug = get_option('saml2_debug', false);
            $saml_idp_sso_url = get_option('saml2_idp_sso_url');
            $saml_idp_sls_url = get_option('saml2_idp_sls_url');
            $saml_idp_x509_cert = get_option('saml2_idp_x509_cert');
            $saml_idp_metadata_url = get_option('saml2_idp_metadata_url');
            $saml_idp_username_attr = get_option('saml2_idp_username_attr');
            $saml_idp_entityid = get_option('saml2_idp_entityid');
            $saml_allow_bypass = get_option('saml2_allow_bypass', false);
            $saml_force_sso = get_option('saml2_force_sso', false);
            $saml_login_button_text = get_option('saml2_login_button_text');
            $saml_login_button_styles = get_option('saml2_login_button_styles');
            $saml_login_text = get_option('saml2_login_text');
            $saml_login_button_logo = get_option('saml2_login_button_logo');
            $saml_organization_url = get_option('saml2_organization_url');
            $saml_organization_name = get_option('saml2_organization_name');
            $saml_organization_display_name = get_option('saml2_organization_display_name');
            $saml_organization_locale = get_option('saml2_organization_locale');
            $saml_contact_support_name = get_option('saml2_contact_support_name');
            $saml_contact_support_email = get_option('saml2_contact_support_email');
            $saml_contact_technical_name = get_option('saml2_contact_technical_name');
            $saml_contact_technical_email = get_option('saml2_contact_technical_email');
            $saml_sp_private_key = get_option('saml2_sp_private_key');
            $saml_sp_public_key = get_option('saml2_sp_public_key');
            $saml_nameid_encrypted = get_option('saml2_nameid_encrypted', false);
            $saml_authn_requests_signed = get_option('saml2_authn_requests_signed', false);
            $saml_logout_requests_signed = get_option('saml2_logout_requests_signed', false);
            $saml_logout_responses_signed = get_option('saml2_logout_responses_signed', false);
            $saml_want_messages_signed = get_option('saml2_want_messages_signed', false);
            $saml_want_assertions_encrypted = get_option('saml2_want_assertions_encrypted', false);
            $saml_want_assertions_signed = get_option('saml2_want_assertions_signed', false);
            $saml_want_nameid_encrypted = get_option('saml2_want_nameid_encrypted', false);
            $saml_requested_authn_context = get_option('saml2_requested_authn_context', false);
            $saml_want_xml_validation = get_option('saml2_want_xml_validation', false);
            $saml_relax_destination_validation = get_option('saml2_relax_destination_validation', false);
            $saml_allow_repeat_attribute_name = get_option('saml2_allow_repeat_attribute_name', false);
            $saml_destination_strictly_matches = get_option('saml2_destination_strictly_matches', false);
            $saml_reject_unsolicited_responses_with_in_response_to = get_option('saml2_reject_unsolicited_responses_with_in_response_to', false);
            $saml_want_nameid = get_option('saml2_want_nameid', false);

            $output = '

            <h5 class="ul">' . _('Global Settings') . '</h5>

            <table class="table table-condensed table-no-border table-auto-width">
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_enabled" ' . is_checked($saml_enabled, true) . '>
                            '._('Enable SAML Authentication').'
                        </label>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_debug" ' . is_checked($saml_debug, true) . '>
                            '._('Enable SAML Debugging').'
                        </label>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_strict" ' . is_checked($saml_strict, true) . '>
                            '._('Enable SAML Strict Mode').'
                        </label>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_force_sso" ' . is_checked($saml_force_sso, true) . '>
                            '._('Force SAML SSO By Default (users will not be presented with the default Nagios XI login page)').'
                            <br />
                            <small>Bypass URL For Admins: <a href="'.get_option('url').'login.php?sso_bypass">'.get_option('url').'login.php?sso_bypass</a></small>
                        </label>
                    </td>
                </tr>
            </table>

            <h5 class="ul">' . _('Identity Provider (IDP) Settings') . '</h5>

            <table class="table table-condensed table-no-border table-auto-width">
                <tr>
                    <td class="vt">
                        <label>' . _('Metadata URL') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" id="saml_idp_metadata_url" name="saml_idp_metadata_url" value="' . htmlentities($saml_idp_metadata_url) . '" class="form-control">
                        <button type="button" onclick="parseIdPMetadata()">Get Metadata</button>
                    </td>
                </tr>

                <tr>
                    <td class="vt">
                        <label>' . _('Entity ID') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" id="saml_idp_entityid" name="saml_idp_entityid" value="' . htmlentities($saml_idp_entityid) . '" class="form-control">
                    </td>
                </tr>

                <tr>
                    <td class="vt">
                        <label>' . _('Single Sign-On (SSO) URL') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" id="saml_idp_sso_url" name="saml_idp_sso_url" value="' . htmlentities($saml_idp_sso_url) . '" class="form-control">
                    </td>
                </tr>

                <tr>
                    <td class="vt">
                        <label>' . _('Single Logout (SLS) URL') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" id="saml_idp_sls_url" name="saml_idp_sls_url" value="' . htmlentities($saml_idp_sls_url) . '" class="form-control">
                    </td>
                </tr>

                <tr>
                    <td class="vt">
                        <label>' . _('x509 Certificate') . ':</label>
                    </td>
                    <td>
                        <textarea style="width:100%; height:auto;" id="saml_idp_x509_cert" class="form-control" rows="6" name="saml_idp_x509_cert">'.htmlentities($saml_idp_x509_cert).'</textarea>
                    </td>
                </tr>

                <tr>
                    <td class="vt">
                        <label>' . _('Username Attribute') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" name="saml_idp_username_attr" value="' . htmlentities($saml_idp_username_attr) . '" class="form-control">
                    </td>
                </tr>
            </table>

            <h5 class="ul">' . _('Serivce Provider (SP) Settings') . '</h5>

            <table class="table table-condensed table-no-border table-auto-width">
                <tr>
                    <td>
                        <button type="button" onclick="generateSpKeys()">Generate Public and Private Keys</button>
                    </td>
                    <td></td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('Private Key') . ':</label>
                    </td>
                    <td>
                        <textarea style="width:100%; height:auto;" id="saml_sp_private_key" class="form-control" rows="6" name="saml_sp_private_key">'.htmlentities($saml_sp_private_key).'</textarea>
                    </td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('Public Key') . ':</label>
                    </td>
                    <td>
                        <textarea style="width:100%; height:auto;" id="saml_sp_public_key" class="form-control" rows="6" name="saml_sp_public_key">'.htmlentities($saml_sp_public_key).'</textarea>
                    </td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('Entity ID') . ':</label>
                    </td>
                    <td><a href="'.get_option('url').'includes/components/samlauthentication/?metadata">'.get_option('url').'includes/components/samlauthentication/?metadata</a></td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('Sign-In URL') . ':</label>
                    </td>
                    <td><a href="'.get_option('url').'includes/components/samlauthentication/?sso">'.get_option('url').'includes/components/samlauthentication/?sso</a></td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('Assertion Consumer Service (ACS)') . ':</label>
                    </td>
                    <td><a href="'.get_option('url').'includes/components/samlauthentication/?acs">'.get_option('url').'includes/components/samlauthentication/?acs</a></td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('Single Logout (SLS)') . ':</label>
                    </td>
                    <td><a href="'.get_option('url').'includes/components/samlauthentication/?sls">'.get_option('url').'includes/components/samlauthentication/?sls</a></td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('NameID Format') . ':</label>
                    </td>
                    <td>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</td>
                </tr>
            </table>

            <h5 class="ul">' . _('Security Settings') . '</h5>

            <table class="table table-condensed table-no-border table-auto-width">
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_nameid_encrypted" ' . is_checked($saml_nameid_encrypted, true) . '>
                            '._('NameID Encrypted').'
                        </label>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_authn_requests_signed" ' . is_checked($saml_authn_requests_signed, true) . '>
                            '._('AuthN Requests Signed').'
                        </label>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_logout_requests_signed" ' . is_checked($saml_logout_requests_signed, true) . '>
                            '._('Logout Requests Signed').'
                        </label>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_logout_responses_signed" ' . is_checked($saml_logout_responses_signed, true) . '>
                            '._('Logout Responses Signed').'
                        </label>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_want_messages_signed" ' . is_checked($saml_want_messages_signed, true) . '>
                            '._('Want Messages Signed').'
                        </label>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_want_assertions_encrypted" ' . is_checked($saml_want_assertions_encrypted, true) . '>
                            '._('Want Assertions Encrypted').'
                        </label>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_want_assertions_signed" ' . is_checked($saml_want_assertions_signed, true) . '>
                            '._('Want Assertions Signed').'
                        </label>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_want_nameid" ' . is_checked($saml_want_nameid, true) . '>
                            '._('Want NameID').'
                        </label>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_want_nameid_encrypted" ' . is_checked($saml_want_nameid_encrypted, true) . '>
                            '._('Want NameID Encrypted').'
                        </label>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_requested_authn_context" ' . is_checked($saml_requested_authn_context, true) . '>
                            '._('Requested AuthN Context').'
                        </label>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_want_xml_validation" ' . is_checked($saml_want_xml_validation, true) . '>
                            '._('Want XML Validation').'
                        </label>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_relax_destination_validation" ' . is_checked($saml_relax_destination_validation, true) . '>
                            '._('Relax Destination Validation').'
                        </label>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_allow_repeat_attribute_name" ' . is_checked($saml_allow_repeat_attribute_name, true) . '>
                            '._('Allow Repeat Attribute Name').'
                        </label>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_destination_strictly_matches" ' . is_checked($saml_destination_strictly_matches, true) . '>
                            '._('Destination Strictly Matches').'
                        </label>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td class="checkbox">
                        <label>
                            <input type="checkbox" class="checkbox" name="saml_reject_unsolicited_responses_with_in_response_to" ' . is_checked($saml_reject_unsolicited_responses_with_in_response_to, true) . '>
                            '._('Reject Unsolicited Responses With In Response To').'
                        </label>
                    </td>
                </tr>
            </table>

            <h5 class="ul">' . _('Organization Settings') . '</h5>

            <table class="table table-condensed table-no-border table-auto-width">
                <tr>
                    <td class="vt">
                        <label>' . _('Organization Locale (en-US, etc)') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" name="saml_organization_locale" value="' . htmlentities($saml_organization_locale) . '" class="form-control">
                    </td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('Organization Name') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" name="saml_organization_name" value="' . htmlentities($saml_organization_name) . '" class="form-control">
                    </td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('Organization Display Name') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" name="saml_organization_display_name" value="' . htmlentities($saml_organization_display_name) . '" class="form-control">
                    </td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('Organization Website/URL') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" name="saml_organization_url" value="' . htmlentities($saml_organization_url) . '" class="form-control">
                    </td>
                </tr>
            </table>

            <h5 class="ul">' . _('Technical Contact Settings') . '</h5>

            <table class="table table-condensed table-no-border table-auto-width">
                <tr>
                    <td class="vt">
                        <label>' . _('Name') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" name="saml_contact_technical_name" value="' . htmlentities($saml_contact_technical_name) . '" class="form-control">
                    </td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('Email') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" name="saml_contact_technical_email" value="' . htmlentities($saml_contact_technical_email) . '" class="form-control">
                    </td>
                </tr>
            </table>

            <h5 class="ul">' . _('Support Contact Settings') . '</h5>

            <table class="table table-condensed table-no-border table-auto-width">
                <tr>
                    <td class="vt">
                        <label>' . _('Name') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" name="saml_contact_support_name" value="' . htmlentities($saml_contact_support_name) . '" class="form-control">
                    </td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('Email') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" name="saml_contact_support_email" value="' . htmlentities($saml_contact_support_email) . '" class="form-control">
                    </td>
                </tr>
            </table>

            <h5 class="ul">' . _('Styling and Branding') . '</h5>

            <table class="table table-condensed table-no-border table-auto-width">
                <tr>
                    <td class="vt">
                        <label>' . _('SAML Login Text (helper text)') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" name="saml_login_text" value="' . htmlentities($saml_login_text) . '" class="form-control">
                    </td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('Login Button Text') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" name="saml_login_button_text" value="' . htmlentities($saml_login_button_text) . '" class="form-control">
                    </td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('Login Button Styles (CSS)') . ':</label>
                    </td>
                    <td>
                        <textarea style="width:100%; height:auto;" class="form-control" rows="6" name="saml_login_button_styles">'.htmlentities($saml_login_button_styles).'</textarea>
                    </td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('Login Button Logo/Image') . ':</label>
                    </td>
                    <td>
            ';

            if(!empty($saml_login_button_logo)) {
                $output .= '
                    <img src="'.$saml_login_button_logo.'" alt="Login Button Logo" />
                    <br />
                ';
            }

            $output .= '
                        <input type="file" accept=".jpg,.png,.jpeg" name="saml_login_button_logo">
                    </td>
                </tr>
            </table>

            <script>
                function generateSpKeys() {
                    var saml_sp_private_key = document.getElementById("saml_sp_private_key");
                    var saml_sp_public_key = document.getElementById("saml_sp_public_key");
                    var get_keys_url = "'.get_option('url').'includes/components/samlauthentication/make-keys.php";

                    if(saml_sp_public_key.value.trim() || saml_sp_private_key.value.trim()) {
                        if(confirm("Are you sure you want to overwrite the existing keys?")) {
                            $.get(get_keys_url, function(data, status){
                                data = JSON.parse(data);
                                saml_sp_private_key.value = data.private_key;
                                saml_sp_public_key.value = data.public_key;
                            });
                        }
                    } else {
                        $.get(get_keys_url, function(data, status){
                            data = JSON.parse(data);
                            saml_sp_private_key.value = data.private_key;
                            saml_sp_public_key.value = data.public_key;
                        });
                    }
                }

                function parseIdPMetadata() {
                    var metadata_url = document.getElementById("saml_idp_metadata_url");
                    var entity_id = document.getElementById("saml_idp_entityid");
                    var sso_url = document.getElementById("saml_idp_sso_url");
                    var sls_url = document.getElementById("saml_idp_sls_url");
                    var x509 = document.getElementById("saml_idp_x509_cert");
                    var get_metadata_url = "'.get_option('url').'includes/components/samlauthentication/parse-metadata.php?url="+metadata_url.value;

                    if(!metadata_url.value) {
                        alert("Please provide a Metadata URL for your IdP.");
                        return false;
                    }

                    $.get(get_metadata_url, function(data, status){
                        data = JSON.parse(data);
                        entity_id.value = data.entityId;
                        sso_url.value = data.singleSignOnService.url;
                        sls_url.value = data.singleLogoutService.url;
                        x509.value = data.x509cert;
                    });
                }
            </script>

            ';

            return $output;
            break;
        case COMPONENT_CONFIGMODE_SAVESETTINGS:
            $saml_enabled = checkbox_binary(grab_array_var($inargs, "saml_enabled", false));
            $saml_idp_metadata_url = grab_array_var($inargs, "saml_idp_metadata_url", "");
            $saml_idp_sso_url = grab_array_var($inargs, "saml_idp_sso_url", "");
            $saml_idp_sls_url = grab_array_var($inargs, "saml_idp_sls_url", "");
            $saml_idp_x509_cert = grab_array_var($inargs, "saml_idp_x509_cert", "");
            $saml_idp_username_attr = grab_array_var($inargs, "saml_idp_username_attr", "");
            $saml_idp_entityid = grab_array_var($inargs, "saml_idp_entityid", "");
            $saml_debug = checkbox_binary(grab_array_var($inargs, "saml_debug", false));
            $saml_strict = checkbox_binary(grab_array_var($inargs, "saml_strict", false));
            $saml_force_sso = checkbox_binary(grab_array_var($inargs, "saml_force_sso", false));
            $saml_login_button_logo = grab_array_var($inargs, "saml_login_button_logo", "");
            $saml_login_button_styles = grab_array_var($inargs, "saml_login_button_styles", "");
            $saml_login_text = grab_array_var($inargs, "saml_login_text", "");
            $saml_login_button_text = grab_array_var($inargs, "saml_login_button_text", "");
            $saml_organization_url = grab_array_var($inargs, "saml_organization_url", "");
            $saml_organization_name = grab_array_var($inargs, "saml_organization_name", "");
            $saml_organization_display_name = grab_array_var($inargs, "saml_organization_display_name", "");
            $saml_organization_locale = grab_array_var($inargs, "saml_organization_locale", "");
            $saml_contact_support_name = grab_array_var($inargs, "saml_contact_support_name", "");
            $saml_contact_support_email = grab_array_var($inargs, "saml_contact_support_email", "");
            $saml_contact_technical_name = grab_array_var($inargs, "saml_contact_technical_name", "");
            $saml_contact_technical_email = grab_array_var($inargs, "saml_contact_technical_email", "");
            $saml_sp_private_key = grab_array_var($inargs, "saml_sp_private_key", "");
            $saml_sp_public_key = grab_array_var($inargs, "saml_sp_public_key", "");
            $saml_nameid_encrypted = checkbox_binary(grab_array_var($inargs, "saml_nameid_encrypted", false));
            $saml_authn_requests_signed = checkbox_binary(grab_array_var($inargs, "saml_authn_requests_signed", false));
            $saml_logout_requests_signed = checkbox_binary(grab_array_var($inargs, "saml_logout_requests_signed", false));
            $saml_logout_responses_signed = checkbox_binary(grab_array_var($inargs, "saml_logout_responses_signed", false));
            $saml_want_messages_signed = checkbox_binary(grab_array_var($inargs, "saml_want_messages_signed", false));
            $saml_want_assertions_encrypted = checkbox_binary(grab_array_var($inargs, "saml_want_assertions_encrypted", false));
            $saml_want_assertions_signed = checkbox_binary(grab_array_var($inargs, "saml_want_assertions_signed", false));
            $saml_want_nameid_encrypted = checkbox_binary(grab_array_var($inargs, "saml_want_nameid_encrypted", false));
            $saml_requested_authn_context = checkbox_binary(grab_array_var($inargs, "saml_requested_authn_context", false));
            $saml_want_xml_validation = checkbox_binary(grab_array_var($inargs, "saml_want_xml_validation", true));
            $saml_relax_destination_validation = checkbox_binary(grab_array_var($inargs, "saml_relax_destination_validation", false));
            $saml_allow_repeat_attribute_name = checkbox_binary(grab_array_var($inargs, "saml_allow_repeat_attribute_name", false));
            $saml_destination_strictly_matches = checkbox_binary(grab_array_var($inargs, "saml_destination_strictly_matches", false));
            $saml_reject_unsolicited_responses_with_in_response_to = checkbox_binary(grab_array_var($inargs, "saml_reject_unsolicited_responses_with_in_response_to", false));
            $saml_want_nameid = checkbox_binary(grab_array_var($inargs, "saml_want_nameid", false));

            set_option("saml2_nameid_encrypted", $saml_nameid_encrypted);
            set_option("saml2_authn_requests_signed", $saml_authn_requests_signed);
            set_option("saml2_logout_requests_signed", $saml_logout_requests_signed);
            set_option("saml2_logout_responses_signed", $saml_logout_responses_signed);
            set_option("saml2_want_messages_signed", $saml_want_messages_signed);
            set_option("saml2_want_assertions_encrypted", $saml_want_assertions_encrypted);
            set_option("saml2_want_assertions_signed", $saml_want_assertions_signed);
            set_option("saml2_want_nameid_encrypted", $saml_want_nameid_encrypted);
            set_option("saml2_requested_authn_context", $saml_requested_authn_context);
            set_option("saml2_want_xml_validation", $saml_want_xml_validation);
            set_option("saml2_relax_destination_validation", $saml_relax_destination_validation);
            set_option("saml2_allow_repeat_attribute_name", $saml_allow_repeat_attribute_name);
            set_option("saml2_destination_strictly_matches", $saml_destination_strictly_matches);
            set_option("saml2_reject_unsolicited_responses_with_in_response_to", $saml_reject_unsolicited_responses_with_in_response_to);
            set_option("saml2_want_nameid", $saml_want_nameid);
            set_option("saml2_enabled", $saml_enabled);
            set_option("saml2_debug", $saml_debug);
            set_option("saml2_idp_metadata_url", $saml_idp_metadata_url);
            set_option("saml2_idp_sso_url", $saml_idp_sso_url);
            set_option("saml2_idp_sls_url", $saml_idp_sls_url);
            set_option("saml2_idp_x509_cert", $saml_idp_x509_cert);
            set_option("saml2_idp_username_attr", $saml_idp_username_attr);
            set_option("saml2_idp_entityid", $saml_idp_entityid);
            set_option("saml2_force_sso", $saml_force_sso);
            set_option("saml2_login_text", $saml_login_text);
            set_option("saml2_login_button_logo", $saml_login_button_logo);
            set_option("saml2_login_button_text", $saml_login_button_text);
            set_option("saml2_login_button_styles", $saml_login_button_styles);
            set_option("saml2_strict", $saml_strict);
            set_option("saml2_organization_name", $saml_organization_name);
            set_option("saml2_organization_display_name", $saml_organization_display_name);
            set_option("saml2_organization_url", $saml_organization_url);
            set_option("saml2_organization_locale", $saml_organization_locale);
            set_option("saml2_contact_support_name", $saml_contact_support_name);
            set_option("saml2_contact_support_email", $saml_contact_support_email);
            set_option("saml2_contact_technical_name", $saml_contact_technical_name);
            set_option("saml2_contact_technical_email", $saml_contact_technical_email);
            set_option("saml2_sp_public_key", $saml_sp_public_key);
            set_option("saml2_sp_private_key", $saml_sp_private_key);

            break;
        default:
            break;
    }
}

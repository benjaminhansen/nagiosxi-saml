<?php

// include the xi component helper
require_once(dirname(__FILE__) . '/../componenthelper.inc.php');

// Testing the inclusion of the common include
require_once(dirname(__FILE__) . '../../../common.inc.php');

samlauthentication_component_init();

function samlauthentication_component_init() {
    // information to pass to xi about our component
    $args = array(
        COMPONENT_NAME =>           "samlauthentication",
        COMPONENT_VERSION =>        "1.0",
        COMPONENT_AUTHOR =>         "BJ Hansen <bjhansen@ualr.edu>",
        COMPONENT_DESCRIPTION =>    "SAML Authentication Component for Nagios XI",
        COMPONENT_CONFIGFUNCTION => "saml_config_func",
        COMPONENT_TITLE =>          "SAML Authentication"
        );

    // register with xi
    register_component("samlauthentication", $args);

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
            $saml_debug = get_option('saml2_debug', false);
            $saml_idp_sso_url = get_option('saml2_idp_sso_url');
            $saml_idp_sls_url = get_option('saml2_idp_sls_url');
            $saml_idp_x509_cert = get_option('saml2_idp_x509_cert');
            $saml_idp_metadata_url = get_option('saml2_idp_metadata_url');
            $saml_idp_username_attr = get_option('saml2_idp_username_attr');
            $saml_idp_entityid = get_option('saml2_idp_entityid');
            $saml_allow_bypass = get_option('saml2_allow_bypass', false);
            $saml_force_sso = get_option('saml2_force_sso', false);

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
                            <input type="checkbox" class="checkbox" name="saml_force_sso" ' . is_checked($saml_force_sso, true) . '>
                            '._('Force SAML SSO By Default (users will not be presented with the default Nagios XI login page)').'
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
                        <input type="text" size="40" name="saml_idp_metadata_url" value="' . htmlentities($saml_idp_metadata_url) . '" class="form-control">
                    </td>
                </tr>

                <tr>
                    <td class="vt">
                        <label>' . _('Entity ID') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" name="saml_idp_entityid" value="' . htmlentities($saml_idp_entityid) . '" class="form-control">
                    </td>
                </tr>

                <tr>
                    <td class="vt">
                        <label>' . _('Single Sign-On (SSO) URL') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" name="saml_idp_sso_url" value="' . htmlentities($saml_idp_sso_url) . '" class="form-control">
                    </td>
                </tr>

                <tr>
                    <td class="vt">
                        <label>' . _('Single Logout (SLS) URL') . ':</label>
                    </td>
                    <td>
                        <input type="text" size="40" name="saml_idp_sls_url" value="' . htmlentities($saml_idp_sls_url) . '" class="form-control">
                    </td>
                </tr>

                <tr>
                    <td class="vt">
                        <label>' . _('x509 Certificate') . ':</label>
                    </td>
                    <td>
                        <textarea style="width:100%; height:auto;" class="form-control" rows="6" name="saml_idp_x509_cert">'.htmlentities($saml_idp_x509_cert).'</textarea>
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

            <h5 class="ul">' . _('Serivce Provider (SP) Values') . '</h5>

            <table class="table table-condensed table-no-border table-auto-width">
                <tr>
                    <td class="vt">
                        <label>' . _('Entity ID') . ':</label>
                    </td>
                    <td>'.get_option('url').'includes/components/samlauthentication/?metadata</td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('Assertion Consumer Service (ACS)') . ':</label>
                    </td>
                    <td>'.get_option('url').'includes/components/samlauthentication/?acs</td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('Single Logout (SLS)') . ':</label>
                    </td>
                    <td>'.get_option('url').'includes/components/samlauthentication/?sls</td>
                </tr>
                <tr>
                    <td class="vt">
                        <label>' . _('NameID Format') . ':</label>
                    </td>
                    <td>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</td>
                </tr>
            </table>

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
            $saml_allow_bypass = checkbox_binary(grab_array_var($inargs, "saml_allow_bypass", false));
            $saml_force_sso = checkbox_binary(grab_array_var($inargs, "saml_force_sso", false));

            set_option("saml2_enabled", $saml_enabled);
            set_option("saml2_debug", $saml_debug);
            set_option("saml2_idp_metadata_url", $saml_idp_metadata_url);
            set_option("saml2_idp_sso_url", $saml_idp_sso_url);
            set_option("saml2_idp_sls_url", $saml_idp_sls_url);
            set_option("saml2_idp_x509_cert", $saml_idp_x509_cert);
            set_option("saml2_idp_username_attr", $saml_idp_username_attr);
            set_option("saml2_idp_entityid", $saml_idp_entityid);
            set_option("saml2_force_sso", $saml_force_sso);
            set_option("saml2_allow_bypass", $saml_allow_bypass);

            break;
        default:
            break;
    }
}

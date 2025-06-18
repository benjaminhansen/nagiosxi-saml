<?php

use OneLogin\Saml2\Settings as Saml2Settings;
use OneLogin\Saml2\Auth as Saml2Auth;
use OneLogin\Saml2\Error as Saml2Error;
use OneLogin\Saml2\Utils as Saml2Utils;

// include the xi component helper
require_once(dirname(__FILE__) . '/../componenthelper.inc.php');

// include the xi common include
require_once(dirname(__FILE__) . '../../../common.inc.php');

// include the composer autoloader
require __DIR__.'/vendor/autoload.php';

// set up Nagios environment
pre_init();
init_session();

function saml_is_enabled() {
    return get_option('saml2_enabled', false);
}

// get the app's base url.
// This is required for the component to function and we will bail out if we don't have it.
$app_url = get_option('url');
if(empty($app_url)) {
    die('Unable to retrieve the app url from the database');
}

// check if saml debugging has been enabled via the admin console
$saml_debug = get_option('saml2_debug', false);

// check if saml strict mode has been enabled via the admin console
$saml_strict = get_option('saml2_strict', false);

// craft the base url of the component, to be used later
$base_url = "{$app_url}includes/components/samlauthentication/";

// craft the saml settings array for the OneLogin plugin
$saml2_settings = [
    'debug' => $saml_debug,

    'strict' => $saml_strict,

    'sp' => [
        'entityId' => "{$base_url}?metadata",
        'assertionConsumerService' => [
            'url' => "{$base_url}?acs",
        ],
        'singleLogoutService' => [
            'url' => "{$base_url}?sls",
        ],
        'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        'x509cert' => get_option('saml2_sp_public_key'),
        'privateKey' => get_option('saml2_sp_private_key'),
    ],

    'idp' => [
        'entityId' => get_option('saml2_idp_entityid'),
        'singleSignOnService' => [
            'url' => get_option('saml2_idp_sso_url'),
        ],
        'singleLogoutService' => [
            'url' => get_option('saml2_idp_sls_url'),
        ],
        'x509cert' => get_option('saml2_idp_x509_cert'),
    ],

    'organization' => [
        get_option('saml2_organization_locale') => [
            'name' => get_option('saml2_organization_name'),
            'displayname' => get_option('saml2_organization_display_name'),
            'url' => get_option('saml2_organization_url')
        ],
    ],

    'contactPerson' => [
        'technical' => [
            'givenName' => get_option('saml2_contact_technical_name'),
            'emailAddress' => get_option('saml2_contact_technical_email'),
        ],
        'support' => [
            'givenName' => get_option('saml2_contact_support_name'),
            'emailAddress' => get_option('saml2_contact_support_email'),
        ],
    ],

    'security' => [
        // Indicates that the nameID of the <samlp:logoutRequest> sent by this SP
        // will be encrypted.
        'nameIdEncrypted' => get_option('saml2_nameid_encrypted', false),

        // Indicates whether the <samlp:AuthnRequest> messages sent by this SP
        // will be signed.  [Metadata of the SP will offer this info]
        'authnRequestsSigned' => get_option('saml2_authn_requests_signed', false),

        // Indicates whether the <samlp:logoutRequest> messages sent by this SP
        // will be signed.
        'logoutRequestSigned' => get_option('saml2_logout_requests_signed', false),

        // Indicates whether the <samlp:logoutResponse> messages sent by this SP
        // will be signed.
        'logoutResponseSigned' => get_option('saml2_logout_responses_signed', false),

        /** signatures and encryptions required **/

        // Indicates a requirement for the <samlp:Response>, <samlp:LogoutRequest>
        // and <samlp:LogoutResponse> elements received by this SP to be signed.
        'wantMessagesSigned' => get_option('saml2_want_messages_signed', false),

        // Indicates a requirement for the <saml:Assertion> elements received by
        // this SP to be encrypted.
        'wantAssertionsEncrypted' => get_option('saml2_want_assertions_encrypted', false),

        // Indicates a requirement for the <saml:Assertion> elements received by
        // this SP to be signed. [Metadata of the SP will offer this info]
        'wantAssertionsSigned' => get_option('saml2_want_assertions_signed', false),

        // Indicates a requirement for the NameID element on the SAMLResponse
        // received by this SP to be present.
        'wantNameId' => get_option('saml2_want_nameid', true),

        // Indicates a requirement for the NameID received by
        // this SP to be encrypted.
        'wantNameIdEncrypted' => get_option('saml2_want_nameid_encrypted', false),

        // Authentication context.
        // Set to false and no AuthContext will be sent in the AuthNRequest.
        // Set true or don't present this parameter and you will get an AuthContext 'exact' 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'.
        // Set an array with the possible auth context values: array ('urn:oasis:names:tc:SAML:2.0:ac:classes:Password', 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509').
        'requestedAuthnContext' => get_option('saml2_requested_authn_context', false),

        // Indicates if the SP will validate all received xmls.
        // (In order to validate the xml, 'strict' and 'wantXMLValidation' must be true).
        'wantXMLValidation' => get_option('saml2_want_xml_validation', true),

        // If true, SAMLResponses with an empty value at its Destination
        // attribute will not be rejected for this fact.
        'relaxDestinationValidation' => get_option('saml2_relax_destination_validation', false),

        // If true, the toolkit will not raised an error when the Statement Element
        // contain atribute elements with name duplicated
        'allowRepeatAttributeName' => get_option('saml2_allow_repeat_attribute_name', false),

        // If true, Destination URL should strictly match to the address to
        // which the response has been sent.
        // Notice that if 'relaxDestinationValidation' is true an empty Destintation
        // will be accepted.
        'destinationStrictlyMatches' => get_option('saml2_destination_strictly_matches', false),

        // If true, SAMLResponses with an InResponseTo value will be rejectd if not
        // AuthNRequest ID provided to the validation method.
        'rejectUnsolicitedResponsesWithInResponseTo' => get_option('saml2_reject_unsolicited_responses_with_in_response_to', false),
    ],
];

// instantiate the Saml2 auth object using the settings array from above
$auth = new Saml2Auth($saml2_settings);

// metadata
if(isset($_GET['metadata'])) {
    try {
        $settings = new Saml2Settings($saml2_settings, true);
        $metadata = $settings->getSPMetadata();
        $errors = $settings->validateMetadata($metadata);
        if (empty($errors)) {
            header('Content-Type: text/xml');
            echo $metadata;
        } else {
            throw new Saml2Error(
                'Invalid SP metadata: '.implode(', ', $errors),
                Saml2Error::METADATA_SP_INVALID
            );
        }
    } catch(Exception $e) {
        die($e->getMessage());
    }
}

// assertion consumer service
else if(isset($_GET['acs'])) {
    if(!saml_is_enabled()) {
        header("Location: {$app_url}login.php");
        return false;
    }

    if (isset($_SESSION) && isset($_SESSION['AuthNRequestID'])) {
        $requestID = $_SESSION['AuthNRequestID'];
    } else {
        $requestID = null;
    }

    $auth->processResponse($requestID);

    $errors = $auth->getErrors();

    if (!empty($errors)) {
        echo '<p>',implode(', ', $errors),'</p>';
        if ($auth->getSettings()->isDebugActive()) {
            echo '<p>'.htmlentities($auth->getLastErrorReason()).'</p>';
        }
    }

    if (!$auth->isAuthenticated()) {
        echo "<p>Not authenticated</p>";
        exit();
    }

    $username_attribute = get_option('saml2_idp_username_attr');

    $_SESSION['samlUserdata'] = $auth->getAttributes();
    $_SESSION['samlNameId'] = $auth->getNameId();
    $_SESSION['samlNameIdFormat'] = $auth->getNameIdFormat();
    $_SESSION['samlNameIdNameQualifier'] = $auth->getNameIdNameQualifier();
    $_SESSION['samlNameIdSPNameQualifier'] = $auth->getNameIdSPNameQualifier();
    $_SESSION['samlSessionIndex'] = $auth->getSessionIndex();
    unset($_SESSION['AuthNRequestID']);
    if (isset($_POST['RelayState']) && Saml2Utils::getSelfURL() != $_POST['RelayState']) {
        $username = $_SESSION['samlUserdata'][$username_attribute][0];
        $_SESSION["user_id"] = get_user_id($username);

        if(is_null($_SESSION["user_id"])) {
            // TO DO: create the user, then log them in (Just-in-time provisioning)
            session_destroy();
            die('You are not authorized to log into this service!');
        }

        $_SESSION["username"] = $username;
        if (empty($_SESSION["session_id"])) {
            $_SESSION["session_id"] = user_generate_session();
        }

        // everything looks good! Let the user in!
        header("Location: {$app_url}index.php");
        return false;
    }
}

// single logout service
else if(isset($_GET['sls'])) {
    if(!saml_is_enabled()) {
        header("Location: {$app_url}login.php");
        return false;
    }

    $returnTo = null;
    $parameters = array();
    $nameId = null;
    $sessionIndex = null;
    $nameIdFormat = null;
    $samlNameIdNameQualifier = null;
    $samlNameIdSPNameQualifier = null;

    if (isset($_SESSION['samlNameId'])) {
        $nameId = $_SESSION['samlNameId'];
    }

    if (isset($_SESSION['samlNameIdFormat'])) {
        $nameIdFormat = $_SESSION['samlNameIdFormat'];
    }

    if (isset($_SESSION['samlNameIdNameQualifier'])) {
        $samlNameIdNameQualifier = $_SESSION['samlNameIdNameQualifier'];
    }

    if (isset($_SESSION['samlNameIdSPNameQualifier'])) {
        $samlNameIdSPNameQualifier = $_SESSION['samlNameIdSPNameQualifier'];
    }

    if (isset($_SESSION['samlSessionIndex'])) {
        $sessionIndex = $_SESSION['samlSessionIndex'];
    }

    $auth->logout($returnTo, $parameters, $nameId, $sessionIndex, false, $nameIdFormat, $samlNameIdNameQualifier, $samlNameIdSPNameQualifier);
}

// single sign-on service
else if(isset($_GET['sso'])) {
    if(!saml_is_enabled()) {
        header("Location: {$app_url}login.php");
        return false;
    }

    $auth->login();
}

// invalid
else {
    if(!saml_is_enabled()) {
        header("Location: {$app_url}login.php");
        return false;
    }

    die('Invalid Request!');
}

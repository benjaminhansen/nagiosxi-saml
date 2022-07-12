<?php

// ini_set('display_errors', 1);
// ini_set('display_startup_errors', 1);
// error_reporting(E_ALL);

use OneLogin\Saml2\Settings as Saml2Settings;
use OneLogin\Saml2\Auth as Saml2Auth;
use OneLogin\Saml2\Error as Saml2Error;
use OneLogin\Saml2\Utils as Saml2Utils;

// include the xi component helper
require_once(dirname(__FILE__) . '/../componenthelper.inc.php');

// Testing the inclusion of the common include
require_once(dirname(__FILE__) . '../../../common.inc.php');

// include the composer autoloader
require __DIR__."/vendor/autoload.php";

pre_init();
init_session();

$app_url = get_option('url');
if(empty($app_url)) {
    die('Unable to retrieve the app url from the database');
}

$saml_enabled = get_option('saml2_enabled', false);
if(!$saml_enabled) {
    header("Location: {$app_url}login.php");
    return false;
}

$saml_debug = get_option('saml2_debug', false);

$base_url = "{$app_url}includes/components/samlauthentication/";

$saml2_settings = [
    'debug' => $saml_debug,

    'sp' => array (
            'entityId' => $base_url.'?metadata',
            'assertionConsumerService' => array (
                'url' => $base_url.'?acs',
            ),
            'singleLogoutService' => array (
                'url' => $base_url.'?sls',
            ),
            'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        ),
    'idp' => array (
        'entityId' => get_option('saml2_idp_entityid'),
        'singleSignOnService' => array (
            'url' => get_option('saml2_idp_sso_url'),
        ),
        'singleLogoutService' => array (
            'url' => get_option('saml2_idp_sls_url'),
        ),
        'x509cert' => get_option('saml2_idp_x509_cert'),
    ),
];

$auth = new Saml2Auth($saml2_settings);

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

else if(isset($_GET['acs'])) {
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
        // To avoid 'Open Redirect' attacks, before execute the
        // redirection confirm the value of $_POST['RelayState'] is a // trusted URL.
        // $auth->redirectTo($_POST['RelayState']);

        $username = $_SESSION['samlUserdata'][$username_attribute][0];
        $_SESSION["user_id"] = get_user_id($username);

        if(is_null($_SESSION["user_id"])) {
            die('You are not authorized to log into this service!');
        }

        $_SESSION["username"] = $username;
        if (empty($_SESSION["session_id"])) {
            $_SESSION["session_id"] = user_generate_session();
        }

        header("Location: {$app_url}index.php");
        return false;
    }
}

else if(isset($_GET['sls'])) {
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

else if(isset($_GET['sso'])) {
    $auth->login();
}

else {
    die('Invalid Request!');
}

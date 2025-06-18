<?php

use OneLogin\Saml2\IdPMetadataParser;

// include the composer autoloader
require __DIR__."/vendor/autoload.php";

// check if the 'url' parameter is set in the GET request
$url = $_GET['url'];
if(!$url) {
    return;
}

// parse the SAML IdP metadata from the provided URL
$metadata = IdPMetadataParser::parseRemoteXml($url);

// return the IdP metadata as a JSON response
echo json_encode($metadata['idp']);

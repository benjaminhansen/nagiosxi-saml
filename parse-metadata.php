<?php

use OneLogin\Saml2\IdPMetadataParser;

// include the composer autoloader
require __DIR__."/vendor/autoload.php";

$url = $_GET['url'];
$metadata = IdPMetadataParser::parseRemoteXml($url);

echo json_encode($metadata['idp']);

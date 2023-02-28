<?php

    # $spBaseUrl = 'https://<your_domain>'; //or http://<your_domain>
    $spBaseUrl = 'http://ec2-15-160-109-130.eu-south-1.compute.amazonaws.com';

    $settingsInfo = array (
        'sp' => array (
            'entityId' => $spBaseUrl.'/demo1/metadata.php',
            'assertionConsumerService' => array (
                'url' => $spBaseUrl.'/demo1/index.php?acs',
            ),
            'singleLogoutService' => array (
                'url' => $spBaseUrl.'/demo1/index.php?sls',
            ),
            'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        ),
        'idp' => array (
            'entityId' => 'https://sts.windows.net/c16e514b-893e-4a01-9a30-b8fef514a650/',
            'singleSignOnService' => array (
                'url' => 'https://login.microsoftonline.com/c16e514b-893e-4a01-9a30-b8fef514a650/saml2',
            ),
            'singleLogoutService' => array (
                'url' => 'https://login.microsoftonline.com/c16e514b-893e-4a01-9a30-b8fef514a650/saml2',
            ),
            'x509cert' => file_get_contents(__DIR__ . '/../certs/x509.cert'),
        ),
    );

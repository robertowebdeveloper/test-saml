<?php
/**
 *  SAML Handler
 */
error_reporting(-1);
ini_set('display_errors', 'On');

require_once dirname(__DIR__) . '/_toolkit_loader.php';

require_once 'settings.php';

$auth = new OneLogin_Saml2_Auth($settingsInfo);

if (isset($_GET['sso'])) {
    $auth->login();

    # If AuthNRequest ID need to be saved in order to later validate it, do instead
    # $ssoBuiltUrl = $auth->login(null, array(), false, false, true);
    # $_SESSION['AuthNRequestID'] = $auth->getLastRequestID();
    # header('Pragma: no-cache');
    # header('Cache-Control: no-cache, must-revalidate');
    # header('Location: ' . $ssoBuiltUrl);
    # exit();

} else if (isset($_GET['sso2'])) {
    $returnTo = $spBaseUrl . '/' . $directory . '/attrs.php';
    $auth->login($returnTo);
} else if (isset($_GET['slo'])) {
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

    # If LogoutRequest ID need to be saved in order to later validate it, do instead
    # $sloBuiltUrl = $auth->logout(null, $paramters, $nameId, $sessionIndex, true);
    # $_SESSION['LogoutRequestID'] = $auth->getLastRequestID();
    # header('Pragma: no-cache');
    # header('Cache-Control: no-cache, must-revalidate');
    # header('Location: ' . $sloBuiltUrl);
    # exit();

} else if (isset($_GET['acs'])) {

    $name = null;
    $username = null;
    $email = null;
    $username = null;
    $company = null;
    $userId = null;

    if (!isset($_POST["SAMLResponse"])) {
        echo "<p>SAMLResponse is not present.</p>";
    } else {
        $samlResponse = base64_decode($_POST["SAMLResponse"]);

        $response = new SimpleXMLElement($samlResponse);
        $arr = json_decode(json_encode($response),true);

        foreach ($arr["Assertion"]["AttributeStatement"]["Attribute"] as $attribute) {
            if (stripos($attribute["@attributes"]["Name"], '/identity/claims/givenname') !== false) {
                $name = $attribute["AttributeValue"];
            } else if (stripos($attribute["@attributes"]["Name"], '/identity/claims/surname') !== false) {
                $surname = $attribute["AttributeValue"];
            } else if (stripos($attribute["@attributes"]["Name"], '/identity/claims/emailaddress') !== false) {
                $email = $attribute["AttributeValue"];
            } else if (stripos($attribute["@attributes"]["Name"], '/identity/claims/name') !== false) {
                $username = $attribute["AttributeValue"];
            } else if ($attribute["@attributes"]["Name"] == "company") {
                $company = $attribute["AttributeValue"];
            } else if ($attribute["@attributes"]["Name"] == "UserID") {
                $userId = $attribute["AttributeValue"];
            }
        }

        echo '<style>
            table {
                width: 600px;
                border-collapse: collapse;
            }
            table td, table th {
                padding: 12px;
                border: 1px solid #333;
            }
        </style>';

        echo '<table>
            <tr>
                <td>Nome:</td>
                <td>' . $name . '</td>
            </tr>
            <tr>
                <td>Cognome:</td>
                <td>' . $surname . '</td>
            </tr>
            <tr>
                <td>Email:</td>
                <td>' . $email . '</td>
            </tr>
            <tr>
                <td>Username:</td>
                <td>' . $username . '</td>
            </tr>
            <tr>
                <td>Company:</td>
                <td>' . $company . '</td>
            </tr>
            <tr>
                <td>UserID:</td>
                <td>' . $userId . '</td>
            </tr>
        </table>';

        die;
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

    $_SESSION['samlUserdata'] = $auth->getAttributes();
    $_SESSION['samlNameId'] = $auth->getNameId();
    $_SESSION['samlNameIdFormat'] = $auth->getNameIdFormat();
    $_SESSION['samlNameIdNameQualifier'] = $auth->getNameIdNameQualifier();
    $_SESSION['samlNameIdSPNameQualifier'] = $auth->getNameIdSPNameQualifier();
    $_SESSION['samlSessionIndex'] = $auth->getSessionIndex();
    unset($_SESSION['AuthNRequestID']);
    if (isset($_POST['RelayState']) && OneLogin_Saml2_Utils::getSelfURL() != $_POST['RelayState']) {
        // To avoid 'Open Redirect' attacks, before execute the 
        // redirection confirm the value of $_POST['RelayState'] is a // trusted URL.
        $auth->redirectTo($_POST['RelayState']);
    }
} else if (isset($_GET['sls'])) {
    if (isset($_SESSION) && isset($_SESSION['LogoutRequestID'])) {
        $requestID = $_SESSION['LogoutRequestID'];
    } else {
        $requestID = null;
    }

    $auth->processSLO(false, $requestID);
    $errors = $auth->getErrors();
    if (empty($errors)) {
        echo '<p>Sucessfully logged out</p>';
    } else {
        echo '<p>', htmlentities(implode(', ', $errors)), '</p>';
        if ($auth->getSettings()->isDebugActive()) {
            echo '<p>'.htmlentities($auth->getLastErrorReason()).'</p>';
        }
    }
}

if (isset($_SESSION['samlUserdata'])) {
    if (!empty($_SESSION['samlUserdata'])) {
        $attributes = $_SESSION['samlUserdata'];
        echo 'You have the following attributes:<br>';
        echo '<table><thead><th>Name</th><th>Values</th></thead><tbody>';
        foreach ($attributes as $attributeName => $attributeValues) {
            echo '<tr><td>' . htmlentities($attributeName) . '</td><td><ul>';
            foreach ($attributeValues as $attributeValue) {
                echo '<li>' . htmlentities($attributeValue) . '</li>';
            }
            echo '</ul></td></tr>';
        }
        echo '</tbody></table>';
    } else {
        echo "<p>You don't have any attribute</p>";
    }

    echo '<p><a href="?slo" >Logout</a></p>';
} else {
    echo parseHtml('
        <div class="box">
            <a href="?sso">Login</a>
            <a href="?sso2">Login and access with attrs</a>
            <a href="?slo">Logout</a>
        </div>
    ');
}



function parseHtml(string $html): string
{
    $template = file_get_contents(__DIR__ . '/template.html');
    return str_replace("#*placeholder*#",$html,$template);
}
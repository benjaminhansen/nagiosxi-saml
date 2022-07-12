# NagiosXI SAML Authentication

Adds SAML SSO capabilities to a Nagios XI installation.

Uses OneLogin's php-saml library to provide SAML connectivity and features.

## Installing
* Clone/place the contents of this repo on your Nagios XI server into the <code><nagiosxi_root>/html/includes/components/samlauthentication</code> directory. You will have to create the <code>samlauthentication</code> directory.
* Run <code>composer install</code> from inside the <code>samlauthentication</code> directory to install all dependencies
* Log into your NagiosXI web interface and go to Admin > Manage Components
* Look for the "SAML Authentication" component and click on the Edit Setting (wrench) icon
* Enable the desired options under the "Global Settings" section
* Provide values for your SSO provider under the "Identity Provider (SSO) Setting" section
* Use the values under the "Service Provider (SP) Values" section to configure the application in your IDP
* Click Apply Settings

## Authentication Providers
This component has only been tested with Azure AD and SimpleSAMLphp as Identity Providers, but it should work just fine with any other providers that support SAML 2.0.

## Gotchas and Caveats
* Users must be pre-populated in the NagiosXI interface, either by hand or via the out-of-box Active Directory/LDAP integration. Just-in-time (JIT) user provisioning is not available, yet...

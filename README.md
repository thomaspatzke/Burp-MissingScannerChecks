# IMPORTANT: Archived Project

This project is not maintained anymore, please fork and do changes on your own.

# Burp Missing Scanner Checks

This burp extension implements some passive scanner checks which are
missing in Burp suite:

* DOM-based XSS (REs are based on those from https://code.google.com/p/domxsswiki/wiki/FindingDOMXSS)

* Missing HTTP headers:

  * Strict-Transport-Security

  * X-Content-Type-Options: nosniff

  * X-XSS-Protection

* Multiple occurrences of the checked headers.

* Redirection from HTTP to HTTPS

All checks can be enabled separately in an own extension tab and a default config can be stored.

## TODO

* See TODO markers in the code.

* Further possibilities to redirect from HTTP to HTTPS (meta refresh, links, referer checking)

* Active scanner check: Actively test directories for listings

* Active scanner check: Add parameters like debug, admin, test etc. and check if something
  interesting appears on the page.

* Active Scanner check: Reaction of the web application and server to
  requests with different/missing host headers.

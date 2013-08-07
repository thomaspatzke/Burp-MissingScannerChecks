# Burp Additonal Scanner Checks Extension
# Copyright 2013 Thomas Skora <thomas@skora.net>
#
# Parts of this code (DOMXSS REs) are based on work licensed under LGPL
# and can be found here:
# https://code.google.com/p/domxsswiki/wiki/FindingDOMXSS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from burp import (IBurpExtender, IScannerCheck, IScanIssue)
from array import array
import re

STSMinimum = 60 * 60 * 24 * 30            # Minimum for Strict Transport Security: 30 days (TODO: make configurable)

class BurpExtender(IBurpExtender, IScannerCheck, IScanIssue):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Missing Scanner Checks")
        self.out = callbacks.getStdout()
        callbacks.registerScannerCheck(self)

        self.domXSSSourcesRE = re.compile("(location\s*[\[.])|([.\[]\s*[\"']?\s*(arguments|dialogArguments|innerHTML|write(ln)?|open(Dialog)?|showModalDialog|cookie|URL|documentURI|baseURI|referrer|name|opener|parent|top|content|self|frames)\W)|(localStorage|sessionStorage|Database)")
        # NOTE: done some optimizations here, original RE caused too much noise
        # - added leading dot in the first part - original recognized "<a href=..." etc.
        # - removed "value" in first part
        self.domXSSSinksRE = re.compile("(\.(src|href|data|location|code|action)\s*[\"'\]]*\s*\+?\s*=)|((replace|assign|navigate|getResponseHeader|open(Dialog)?|showModalDialog|eval|evaluate|execCommand|execScript|setTimeout|setInterval)\s*[\"'\]]*\s*\()")
        self.domXSSjQuerySinksRE = re.compile("after\(|\.append\(|\.before\(|\.html\(|\.prepend\(|\.replaceWith\(|\.wrap\(|\.wrapAll\(|\$\(|\.globalEval\(|\.add\(|jQUery\(|\$\(|\.parseHTML\(")
        self.headerSTSRE = re.compile("^Strict-Transport-Security:.*?max-age=\"?(\d+)\"?", re.I) # TODO: multiple max-age directives cause confusion!
        self.headerXCTORE = re.compile("^X-Content-Type-Options:\s*nosniff", re.I)
        self.headerXXP = re.compile("^X-XSS-Protection:\s*(\d)(?:\s*;\s*mode\s*=\s*\"?(block)\"?)?", re.I)

    ### IScannerCheck ###
    def doPassiveScan(self, baseRequestResponse):
        scanIssues = list()
        analyzedResponse = self.helpers.analyzeResponse(baseRequestResponse.getResponse())
        responseHeaders = analyzedResponse.getHeaders()
        bodyOffset = analyzedResponse.getBodyOffset()
        responseBody = baseRequestResponse.getResponse()[analyzedResponse.getBodyOffset():].tostring()

        # Identify DOMXSS sources and sinks
        domXSSSources = self.domXSSSourcesRE.finditer(responseBody)
        domXSSSinks = self.domXSSSinksRE.finditer(responseBody)
        domXSSjQuerySinks = self.domXSSjQuerySinksRE.finditer(responseBody)

        domXSSSourcesPos = map(lambda(match): array('i', (match.start() + bodyOffset, match.end() + bodyOffset)), domXSSSources)
        domXSSSinksPos = map(lambda(match): array('i', (match.start() + bodyOffset, match.end() + bodyOffset)), domXSSSinks)
        domXSSjQuerySinksPos = map(lambda(match): array('i', (match.start() + bodyOffset, match.end() + bodyOffset)), domXSSjQuerySinks)

        if len(domXSSSourcesPos) + len(domXSSSinksPos) + len(domXSSjQuerySinksPos) > 0:
            scanIssues.append(DOMXSSScanIssue(
                baseRequestResponse,
                domXSSSourcesPos,
                domXSSSinksPos,
                domXSSjQuerySinksPos,
                self.helpers,
                self.callbacks
                ))

        return scanIssues

class DOMXSSScanIssue(IScanIssue):
    def __init__(self, requestResponse, sourcesPos, sinksPos, jQuerySinksPos, helpers, callbacks):
        analyzedRequest = helpers.analyzeRequest(requestResponse)
        self.findingUrl = analyzedRequest.getUrl()
        self.sourcesPos = sourcesPos
        self.sinksPos = sinksPos + jQuerySinksPos
        self.requestResponse = callbacks.applyMarkers(requestResponse, None, normalizePos(self.sourcesPos + self.sinksPos))

    def getUrl(self):
        return self.findingUrl

    def getIssueName(self):
        return "Possible DOM-based Cross-site scripting"

    def getIssueType(self):
        return 2097930

    def getSeverity(self):
        if len(self.sinksPos) > 0:
            return "High"
        else:
            return "Low"

    def getConfidence(self):
        return "Tentative"

    def getIssueBackground(self):
        msg = "<p>DOM-based cross-site scripting (XSS) is a variant of the well-known XSS vulnerabilities where the issue is located in client-side JavaScript code. \
        As in classical XSS, the vulnerability causes code execution in the context of the users session within the application. An attacker can perform a wide \
        variety of actions, like session hijacking etc. The vulnerability is caused by copying data from non-trustworthy sources (user input, URL) into the DOM with \
        insecure methods.</p> \
        <p>Such vulnerabilities are hard to detect with classical methods like checking the response for occurrences of previous inputs or parameters. This scan \
        issue has detected the usage of insecure sources or sinks in the JavaScript code of the page. Further manual checks must be performed to verify the impact \
        of their usage</p>"
        return msg

    def getRemediationBackground(self):
        msg = "DOM-based XSS can be prevented by usage of secure methods that only operate on the content text of the DOM instead of modifying the DOM structure. E.g. \
        usage of the innerText attribute instead of innerHTML or the text() method of jQuery instead of html() to insert user content into the DOM. If these methods are \
        not applicable in a particular use case, the user input has to be filtered and sanitized before it is passed into the DOM by insecure methods."
        return msg

    def getIssueDetail(self):
        msg = "The scanner check has detected occurrences of unsafe "
        if len(self.sinksPos) > 0 and len(self.sourcesPos) > 0:
            msg += "sources and sinks. If data flows from unsafe sources into unsafe sinks without being sanitized then it is quite certain that the web application is \
            vulnerable against DOM-based XSS. "
        elif len(self.sinksPos) > 0:
            msg += "sinks. Be aware that there are potential unsafe sources which are not detected by the patterns used in the scanner check, e.g. data loaded by the \
            XmlHttpRequest API. Furthermore there is the possibility that the sources and sinks are distributed in different files. "
        elif len(self.sourcesPos) > 0:
            msg += "sources. Generally there must be a sink for code execution caused by unsafe sources. This could be located in a different part of the web application \
            or be unrecognized by the scanner module. "
        msg += "See the response tab to review the occurrences."
        return msg

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return [self.requestResponse]

    def getHttpService(self):
        return self.requestResponse.getHttpService()

def normalizePos(uPos):
    sortedPos = sorted(uPos)
    normPos = list()
    prevPos = None
    for pos in sortedPos:
        if not prevPos:
            prevPos = pos
        elif prevPos[1] > pos[0]:
            if prevPos[1] < pos[1]:
                prevPos[1] = pos[1]
        else:
            normPos.append(prevPos)
            prevPos = pos
    normPos.append(prevPos)
    return normPos

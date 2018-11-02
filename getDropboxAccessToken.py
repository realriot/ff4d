#!/usr/bin/python
# Copyright (c) 2014-2018 Sascha Schmidt <sascha@schmidt.ps>
# http://blog.schmidt.ps
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
from dropbox import DropboxOAuth2FlowNoRedirect

print ""
print "********************************************************************************"
print "* This script helps you to fetch an access token for your Dropbox application. *"
print "*                                                                              *"
print "* Copyright 2014-2018 by Sascha Schmidt <sascha@schmidt.ps>                    *"
print "* https://schmidt.ps                                                           *"
print "********************************************************************************"
print ""

app_key = raw_input("1.) Enter your 'App key': ").strip()
app_secret = raw_input("2.) Enter your 'App secret': ").strip()

auth_flow = DropboxOAuth2FlowNoRedirect(app_key, app_secret)
authorize_url = auth_flow.start()

authorize_url = "https://www.dropbox.com/oauth2/authorize?response_type=code&client_id=" + app_key

print "3.) Now open this url and confirm the requested permission."
print ""
print authorize_url
print ""
auth_code = raw_input("4.) Enter the given access code': ").strip()

try:
  oauth_result = auth_flow.finish(auth_code)
except Exception, e:
  print "Could not finish the Dropbox authorization flow. (" + str(e) + ")\n"
  sys.exit(-1)

print ""
print "This access token allows your app to access your dropbox:"
print oauth_result.access_token
print ""

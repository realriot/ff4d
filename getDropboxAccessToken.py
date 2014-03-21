#!/usr/bin/python
# Copyright (c) 2014 Sascha Schmidt <sascha@schmidt.ps>
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
import sys, dropbox

print ""
print "********************************************************************************"
print "* This script helps you to fetch an access token for your Dropbox application. *"
print "*                                                                              *"
print "* Copyright 2014 by Sascha Schmidt <sascha@schmidt.ps>                         *"
print "* http://blog.schmidt.ps                                                       *"
print "********************************************************************************"
print ""

app_key = raw_input("1.) Enter your 'App key': ").strip()
app_secret = raw_input("2.) Enter your 'App secret': ").strip()

try:
  flow = dropbox.client.DropboxOAuth2FlowNoRedirect(app_key, app_secret)
  authorize_url = flow.start()
except dropbox.rest.ErrorResponse, e:
  print "Could not start the Dropbox authorization flow. (" + e.error_msg + ")\n"
  sys.exit(-1)

print "3.) Now open this url and confirm the requested permission."
print ""
print authorize_url
print ""
code = raw_input("4.) Enter the given access code': ").strip()
try:
  access_token, user_id = flow.finish(code)
except dropbox.rest.ErrorResponse, e:
  print "Could not finish the Dropbox authorization flow. (" + e.error_msg + ")\n"
  sys.exit(-1)

print ""
print "This access token allows your app to access your dropbox:"
print access_token
print ""

# Validate the access_token and show some user informations.
try:
  client = dropbox.client.DropboxClient(access_token)
  account_info = client.account_info()
except dropbox.rest.ErrorResponse, e:
  print "Could not validate the new access token. (" + e.error_msg + ")\n"
  sys.exit(-1)

print "- Your account -"
print "Display name   : " + account_info['display_name']
print "Email          : " + account_info['email']
print "Userid         : " +  str(account_info['uid'])
print "Country        : " + account_info['country']
print "Referral link  : " + account_info['referral_link']
print "Space used     : " + str(account_info['quota_info']['normal']/1024/1024/1024) + " GB"
print "Space available: " + str(account_info['quota_info']['quota']/1024/1024/1024) + " GB"
print ""

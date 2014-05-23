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
import sys, json, urllib, urllib2, httplib, dropbox

########################
# Class: API transport #
########################
class apiRequest():
  def __init__(self):
    self.headers = None
    pass

  # Function to handle GET API request.
  def get(self, url, args=None, argheaders=None, retresp=False):
    user_agent = "apiRequest/tools.schmidt.ps"
    headers = {'User-Agent' : user_agent}

    # Add arguments to request string.
    if args != None and len(args) > 0:
      url = url + '?' + urllib.urlencode(args)

    # Add additionally given class headers.
    if self.headers != None:
      headers.update(self.headers)

    # Add additionally given headers.
    if argheaders != None:
      headers.update(argheaders)

    try:
      req = urllib2.Request(url, None, headers)
      response = urllib2.urlopen(req)

      # If retresp is TRUE return the raw response object.
      if retresp == True:
        return response
      else:
        return json.loads(response.read())
    except urllib2.HTTPError, e:
      raise Exception, 'apiRequest failed. HTTPError: ' + str(e.code)
    except urllib2.URLError, e:
      raise Exception, 'apiRequest failed. URLError: ' + str(e.reason)
    except httplib.HTTPException, e:
      raise Exception, 'apiRequest failed. HTTPException: ' + str(e)
    except Exception, e:
      raise Exception, 'apiRequest failed. Unknown exception: ' + str(e)

  # Function to handle POST API request.
  def post(self, url, args=None, argheaders=None, body=None):
    user_agent = "apiRequest/tools.schmidt.ps"
    headers = {'User-Agent' : user_agent}

    if args != None:
      args = urllib.urlencode(args)

    # Add additionally given class headers.
    if self.headers != None:
      headers.update(self.headers)

    # Add additionally given headers.
    if argheaders != None:
      headers.update(argheaders)

    # Add body if defined.
    if args == None and body != None:
      headers.update({'Content-type' : 'application/octet-stream'})
      args = body

    try:
      req = urllib2.Request(url, args, headers)
      response = urllib2.urlopen(req)
      return json.loads(response.read())
    except urllib2.HTTPError, e:
      raise Exception, 'apiRequest failed. HTTPError: ' + str(e.code)
    except urllib2.URLError, e:
      raise Exception, 'apiRequest failed. URLError: ' + str(e.reason)
    except httplib.HTTPException, e:
      raise Exception, 'apiRequest failed. HTTPException: ' + str(e)
    except Exception, e:
      from traceback import print_exc
      print_exc()
      raise Exception, 'apiRequest failed. Unknown exception: ' + str(e)

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
authorize_url = "https://www.dropbox.com/1/oauth2/authorize?response_type=code&client_id=" + app_key

print "3.) Now open this url and confirm the requested permission."
print ""
print authorize_url
print ""
code = raw_input("4.) Enter the given access code': ").strip()

ar = apiRequest()
result = "" 
access_token = ""
try:
  args = {"code"          : code,
          "grant_type"    : "authorization_code",
          "client_id"     : app_key,
          "client_secret" : app_secret}
  result = ar.post("https://api.dropbox.com/1/oauth2/token", args) 
  access_token = result['access_token'] 
  ar.headers = {'Authorization' : 'Bearer ' + access_token}
except Exception, e:
  print "Could not finish the Dropbox authorization flow. (" + str(e) + ")\n"
  sys.exit(-1)

print ""
print "This access token allows your app to access your dropbox:"
print access_token
print ""

# Validate the access_token and show some user informations.
try:
  account_info = ar.get('https://api.dropbox.com/1/account/info')
except Exception, e:
  print "Could not validate the new access token. (" + str(e) + ")\n"
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

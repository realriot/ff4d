#!/usr/bin/python

# Copyright (c) 2014 Sascha Schmidt <sascha@schmidt.ps> (author)
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

# Error codes: http://docs.python.org/2/library/errno.html

from __future__ import with_statement

import os, sys, pwd, errno, json, argparse, urllib, urllib2, httplib, traceback
from time import time, mktime, sleep
from datetime import datetime
from stat import S_IFDIR, S_IFLNK, S_IFREG
from fuse import FUSE, FuseOSError, Operations
from errno import *

##################################
# Class: FUSE Dropbox operations #
##################################
class Dropbox(Operations):
  def __init__(self, apiRequest):
    self.ar = apiRequest
    self.cache = {}
    self.openfh = {}
    self.runfh = {} 

  #######################################
  # Wrapper functions around API calls. #
  #######################################

  # Get Dropbox metadata of path.
  def dbxMetadata(self, path, mhash=None):
    args = {'file_limit'         : 25000,
            'list'               : True,
            'include_media_info' : False}

    if mhash != None:
      args.update({'hash' : mhash})

    result = self.ar.get('https://api.dropbox.com/1/metadata/auto' + path, args)
    return result

  # Rename a Dropbox file/directory object.
  def dbxFileMove(self, old, new):
    args = {'root'      : 'auto', 
            'from_path' : old,
            'to_path'   : new}
    result = self.ar.post('https://api.dropbox.com/1/fileops/move', args)
    return result

  # Delete a Dropbox file/directory object.
  def dbxFileDelete(self, path):
    args = {'root' : 'auto',
            'path' : path}
    result = self.ar.post('https://api.dropbox.com/1/fileops/delete', args)
    return result

  # Create a Dropboy folder.
  def dbxFileCreateFolder(self, path):
    args = {'root' : 'auto',
            'path' : path}
    result = self.ar.post('https://api.dropbox.com/1/fileops/create_folder', args)
    return result

  # Upload chunk of data to Dropbox.
  def dbxChunkedUpload(self, data, upload_id, offset=0):
    args = {'offset' : offset}

    # Add upload_id if its not the first chunk.
    if upload_id != "":
      args.update({'upload_id' : upload_id})

    result = self.ar.post('https://api-content.dropbox.com/1/chunked_upload?' + urllib.urlencode(args), None, None, data)
    return result

  # Commit chunked upload to Dropbox.
  def dbxCommitChunkedUpload(self, path, upload_id):
    args = {'upload_id' : upload_id}
    result = self.ar.post('https://api-content.dropbox.com/1/commit_chunked_upload/auto' + path, args)
    return result

  # Get Dropbox filehandle.
  def dbxFilehandle(self, path, seek=False):
    seekheader = None
    if seek != False:
      seekheader = {'Range' : 'bytes=' + str(seek)}
    result = self.ar.get('https://api-content.dropbox.com/1/files/auto' + path, None, seekheader, True)
    return result


  #####################
  # Helper functions. #
  #####################

  # Get a valid and unique filehandle.
  def getFH(self, mode='r'):
    for i in range(1,8193):
      if i not in self.openfh:
        self.openfh[i] = {'mode' : mode, 'f' : False, 'lock' : False, 'eoffset': 0}
        self.runfh[i] = False
        return i
    return False

  # Release a filehandle.
  def releaseFH(self, fh):
    if fh in self.openfh:
      self.openfh.pop(fh)
      self.runfh.pop(fh)
    else:
      return False

  # Remove item from cache.
  def removeFromCache(self, path):
    if debug == True: appLog('debug', 'Called removeFromCache() Path: ' + path)

    # Check whether this path exists within cache.
    if path in self.cache:
      item = self.cache[path]

      # If this is a directory, remove all childs.
      if item['is_dir'] == True and 'contents' in item:
        # Remove folder items from cache.
        if debug == True: appLog('debug', 'Removing childs of path from cache')
        for tmp in item['contents']:
          if debug == True: appLog('debug', 'Removing from cache: ' + tmp['path'])
          if tmp['path'] in self.cache:
            self.cache.pop(tmp['path'])
      else:
        if os.path.dirname(path) in self.cache:
          if self.cache[os.path.dirname(path)]['is_dir'] == True: 
            if debug == True: appLog('debug', 'Removing parent path from file in cache')
            self.cache.pop(os.path.dirname(path))
      if debug == True: appLog('debug', 'Removing from cache: ' + path)
      self.cache.pop(path)
      return True
    else:
      if debug == True: appLog('debug', 'Path not in cache: ' + path)
      return False

  # Get metadata for a file or folder from the Dropbox API or local cache.
  def getDropboxMetadata(self, path, deep=False):
    # Metadata exists within cache.
    if path in self.cache:
      if debug == True: appLog('debug', 'Found cached metadata for: ' + path)
      item = self.cache[path]

      # Check whether this is a directory and if there any remote changes.
      if item['is_dir'] == True and item['cachets']<int(time()) or (deep == True and 'contents' not in item):
        # Set temporary hash value for directory non-deep cache entry.
        if deep == True and 'contents' not in item:
          item['hash'] = '0' 
        if debug == True: appLog('debug', 'Metadata directory deepcheck: ' + str(deep))
        if debug == True: appLog('debug', 'Cache expired for: ' + path)
        if debug == True: appLog('debug', 'cachets: ' + str(item['cachets']) + ' - ' + str(int(time())))
        if debug == True: appLog('debug', 'Checking for changes on the remote endpoint for folder: ' + path)
        try:
          item = self.dbxMetadata(path, item['hash'])
          if 'is_deleted' in item and item['is_deleted'] == True:
            return False
          if debug == True: appLog('debug', 'Remote endpoint signalizes changes. Updating local cache for folder: ' + path)
          if debug_raw == True: appLog('debug', 'Data from Dropbox API call: metadata(' + path + ')')
          if debug_raw == True: appLog('debug', str(item))

          # Remove outdated data from cache.
          self.removeFromCache(path)

          # Cache new data.
          cachets = int(time())+cache_time
          item.update({'cachets':cachets})
          self.cache[path] = item
          for tmp in item['contents']:
            if tmp['is_dir'] == False:
              if 'is_deleted' not in tmp or ('is_deleted' in tmp and tmp['is_deleted'] == False):
                tmp.update({'cachets':cachets})
                self.cache[tmp['path']] = tmp
        except Exception, e:
          if debug == True: appLog('debug', 'No remote changes detected for folder: ' + path, traceback.format_exc())
      return item
    # No cached data found, do an Dropbox API request to fetch the metadata.
    else:
      if debug == True: appLog('debug', 'No cached metadata for: ' + path)
      try:
        # If the path already exists, this path (file/dir) does not exist.
        if os.path.dirname(path) in self.cache and 'contents' in self.cache[os.path.dirname(path)]:
          if debug == True: appLog('debug', 'Basepath exists in cache for: ' + path)
          return False

        item = self.dbxMetadata(path)
        if 'is_deleted' in item and item['is_deleted'] == True:
          return False
        if debug_raw == True: appLog('debug', 'Data from Dropbox API call: metadata(' + path + ')')
        if debug_raw == True: appLog('debug', str(item))
      except Exception, e:
        appLog('error', 'Could not fetch metadata for: ' + path, traceback.format_exc())
        if str(e) == 'apiRequest failed. HTTPError: 404':
          return False
        else:
          raise FuseOSError(EREMOTEIO)

      # Cache metadata if user wants to use the cache.
      cachets = int(time())+cache_time
      item.update({'cachets':cachets})
      self.cache[path] = item
      # Cache files if this item is a file.
      if item['is_dir'] == True:
        for tmp in item['contents']:
          if 'is_deleted' not in tmp or ('is_deleted' in tmp and tmp['is_deleted'] == False):
            tmp.update({'cachets':cachets})
            self.cache[tmp['path']] = tmp
      return item

  #########################
  # Filesystem functions. #
  #########################
  def mkdir(self, path, mode):
    path = path.encode('utf-8')
    if debug == True: appLog('debug', 'Called: mkdir() - Path: ' + path)
    try:
      self.dbxFileCreateFolder(path)
    except Exception, e:
      appLog('error', 'Could not create folder: ' + path, traceback.format_exc())
      raise FuseOSError(EIO)

    # Remove outdated data from cache.
    self.removeFromCache(os.path.dirname(path))
    return 0

  # Remove a directory.
  def rmdir(self, path):
    path = path.encode('utf-8')
    if debug == True: appLog('debug', 'Called: rmdir() - Path: ' + path)
    try:
      self.dbxFileDelete(path)
    except Exception, e:
      appLog('error', 'Could not delete folder: ' + path, traceback.format_exc())
      raise FuseOSError(EIO)
    if debug == True: appLog('debug', 'Successfully deleted folder: ' + path) 

    # Remove outdated data from cache.
    self.removeFromCache(path)
    self.removeFromCache(os.path.dirname(path))
    return 0

  # Remove a file.
  def unlink(self, path):
    path = path.encode('utf-8')
    if debug == True: appLog('debug', 'Called: unlink() - Path: ' + path)

    # Remove data from cache.
    self.removeFromCache(path)

    # Delete file.
    try:
      self.dbxFileDelete(path)
    except Exception, e:
      appLog('error', 'Could not delete file: ' + path, traceback.format_exc())
      raise FuseOSError(EIO)
    if debug == True: appLog('debug', 'Successfully deleted file: ' + path)

    return 0

  # Rename a file or directory.
  def rename(self, old, new):
    old = old.encode('utf-8')
    new = new.encode('utf-8')
    if debug == True: appLog('debug', 'Called: rename() - Old: ' + old + ' New: ' + new)
    try:
      self.dbxFileMove(old, new)
    except Exception, e:
      appLog('error', 'Could not rename object: ' + old, traceback.format_exc())
      raise FuseOSError(EIO)
    if debug == True: appLog('debug', 'Successfully renamed object: ' + old)
    if debug_raw == True: appLog('debug', str(result))

    # Remove outdated data from cache.
    self.removeFromCache(old)
    return 0

  # Read data from a remote filehandle.
  def read(self, path, length, offset, fh):
    path = path.encode('utf-8')
    # Wait while this function is not threadable.
    while self.openfh[fh]['lock'] == True:
      pass

    self.runfh[fh] = True
    if debug == True: appLog('debug', 'Called: read() - Path: ' + path + ' Length: ' + str(length) + ' Offset: ' + str(offset) + ' FH: ' + str(fh))
    if debug == True: appLog('debug', 'Excpected offset: ' + str(self.openfh[fh]['eoffset']))
    if fh in self.openfh:
      if self.openfh[fh]['f'] == False:
        try:
          self.openfh[fh]['f'] = self.dbxFilehandle(path, offset)
        except Exception, e:
          appLog('error', 'Could not open remote file: ' + path, traceback.format_exc())
          raise FuseOSError(EIO) 
      else:
        if debug == True: appLog('debug', 'FH handle for reading process already opened')
        if self.openfh[fh]['eoffset'] != offset:
          if debug == True: appLog('debug', 'Requested offset differs from expected offset. Seeking to: ' + str(offset))
          self.openfh[fh]['f'] = self.dbxFilehandle(path, offset)
        pass

    # Read from FH.
    rbytes = ''
    try:
      rbytes = self.openfh[fh]['f'].read(length)
    except Exception, e:
      appLog('error', 'Could not read data from remotefile: ' + path, traceback.format_exc())
      raise FuseOSError(EIO)

    if debug == True: appLog('debug', 'Read bytes from remote source: ' + str(len(rbytes)))
    self.openfh[fh]['lock'] = False
    self.runfh[fh] = False
    self.openfh[fh]['eoffset'] = offset + len(rbytes)
    return rbytes

  # Write data to a filehandle.
  def write(self, path, buf, offset, fh):
    path = path.encode('utf-8')
    if debug == True: appLog('debug', 'Called: write() - Path: ' + path + ' Offset: ' + str(offset) + ' FH: ' + str(fh))
    try:
      # Check for the beginning of the file.
      if fh in self.openfh:
        if self.openfh[fh]['f'] == False: 
          if debug == True: appLog('debug', 'Uploading first chunk to Dropbox...')
          # Check if the write request exceeds the maximum buffer size.
          if len(buf) >= write_cache or len(buf) < 4096: 
            if debug == True: appLog('debug', 'Cache exceeds configured write_cache. Uploading...')
            result = self.dbxChunkedUpload(buf, "", 0)
            self.openfh[fh]['f'] = {'upload_id':result['upload_id'], 'offset':result['offset'], 'buf':''}
          else:
            if debug == True: appLog('debug', 'Buffer does not exceed configured write_cache. Caching...')
            self.openfh[fh]['f'] = {'upload_id':'', 'offset':0, 'buf':buf}
          return len(buf) 
        else:
          if debug == True: appLog('debug', 'Uploading another chunk to Dropbox...')
          if len(buf)+len(self.openfh[fh]['f']['buf']) >= write_cache or len(buf) < 4096:
            if debug == True: appLog('debug', 'Cache exceeds configured write_cache. Uploading...')
            result = self.dbxChunkedUpload(self.openfh[fh]['f']['buf']+buf, self.openfh[fh]['f']['upload_id'], self.openfh[fh]['f']['offset'])
            self.openfh[fh]['f'] = {'upload_id':result['upload_id'], 'offset':result['offset'], 'buf':''}
          else:
            if debug == True: appLog('debug', 'Buffer does not exceed configured write_cache. Caching...')
            self.openfh[fh]['f'].update({'buf':self.openfh[fh]['f']['buf']+buf})
          return len(buf) 
      else:
        raise FuseOSError(EIO) 
    except Exception, e:
      appLog('error', 'Could not write to remote file: ' + path, traceback.format_exc())
      raise FuseOSError(EIO)

  # Open a filehandle.
  def open(self, path, flags):
    path = path.encode('utf-8')
    if debug == True: appLog('debug', 'Called: open() - Path: ' + path + ' Flags: ' + str(flags))

    # Validate flags.
    if flags & os.O_APPEND:
      if debug == True: appLog('debug', 'O_APPEND mode not supported for open()') 
      raise FuseOSError(EOPNOTSUPP)

    fh = self.getFH('r')
    if debug == True: appLog('debug', 'Returning unique filehandle: ' + str(fh))
    return fh

  # Create a file.
  def create(self, path, mode):
    path = path.encode('utf-8')
    if debug == True: appLog('debug', 'Called: create() - Path: ' + path + ' Mode: ' + str(mode))

    fh = self.getFH('w')
    if debug == True: appLog('debug', 'Returning unique filehandle: ' + str(fh))

    now = datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0000')
    cachedfh = {'bytes':0, 'modified':now, 'path':path, 'is_dir':False}
    self.cache[path] = cachedfh

    return fh

  # Release (close) a filehandle.
  def release(self, path, fh):
    path = path.encode('utf-8')
    if debug == True: appLog('debug', 'Called: release() - Path: ' + path + ' FH: ' + str(fh))

    # Check to finish Dropbox upload.
    if type(self.openfh[fh]['f']) is dict and 'upload_id' in self.openfh[fh]['f'] and self.openfh[fh]['f']['upload_id'] != "":
      # Flush still existing data in buffer.
      if self.openfh[fh]['f']['buf'] != "":
        if debug == True: appLog('debug', 'Flushing write buffer to Dropbox')
        result = self.dbxChunkedUpload(self.openfh[fh]['f']['buf'], self.openfh[fh]['f']['upload_id'], self.openfh[fh]['f']['offset'])
      if debug == True: appLog('debug', 'Finishing upload to Dropbox')
      result = self.dbxCommitChunkedUpload(path, self.openfh[fh]['f']['upload_id'])

    # Remove outdated data from cache if handle was opened for writing.
    if self.openfh[fh]['mode'] == 'w':
      self.removeFromCache(os.path.dirname(path))

    self.releaseFH(fh)
    if debug == True: appLog('debug', 'Released filehandle: ' + str(fh))

    return 0

  # Truncate a file to overwrite it.
  def truncate(self, path, length, fh=None):
    path = path.encode('utf-8')
    if debug == True: appLog('debug', 'Called: truncate() - Path: ' + path + " Size: " + str(length))
    return 0

  # List the content of a directory.
  def readdir(self, path, fh):
    path = path.encode('utf-8')
    if debug == True: appLog('debug', 'Called: readdir() - Path: ' + path)

    # Fetch folder informations.
    fusefolder = ['.', '..']
    metadata = self.getDropboxMetadata(path, True)

    # Loop through the Dropbox API reply to build fuse structure.
    for item in metadata['contents']:
      # Append entry to fuse foldercontent.
      folderitem = os.path.basename(item['path'])
      fusefolder.append(folderitem)

    # Loop through the folder content.
    for item in fusefolder:
      yield item

  # Get properties for a directory or file.
  def getattr(self, path, fh=None):
    path = path.encode('utf-8')
    if debug == True: appLog('debug', 'Called: getattr() - Path: ' + path)

    # Get userid and groupid for current user.
    uid = pwd.getpwuid(os.getuid()).pw_uid
    gid = pwd.getpwuid(os.getuid()).pw_gid

    # Get current time.
    now = int(time())

    # Check wether data exists for item.
    item = self.getDropboxMetadata(path)
    if item == False:
      #raise FuseOSError(ENOENT)
      raise FuseOSError(ENOENT)

    # Handle last modified times.
    if 'modified' in item:
      modified = item['modified']
      modified = mktime(datetime.strptime(modified, '%a, %d %b %Y %H:%M:%S +0000').timetuple())
    else:
      modified = int(now)

    if item['is_dir'] == True: 
      # Get st_nlink count for directory.
      properties = dict(
        st_mode=S_IFDIR | 0755,
        st_size=0,
        st_ctime=modified,
        st_mtime=modified,
        st_atime=now,
        st_uid=uid,
        st_gid=gid,
        st_nlink=2
      )
      if debug == True: appLog('debug', 'Returning properties for directory: ' + path + ' (' + str(properties) + ')')
      return properties 
    else:
      properties = dict(
        st_mode=S_IFREG | 0755,
        st_size=item['bytes'],
        st_ctime=modified,
        st_mtime=modified,
        st_atime=now,
        st_uid=uid,
        st_gid=gid,
        st_nlink=1,
      )
      if debug == True: appLog('debug', 'Returning properties for file: ' + path + ' (' + str(properties) + ')')
      return properties 

  # Flush filesystem cache. Always true in this case.
  def fsync(self, path, fdatasync, fh):
    path = path.encode('utf-8')
    if debug == True: appLog('debug', 'Called: fsync() - Path: ' + path)

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
      appLog('error', 'apiRequest failed. HTTPError: ' + str(e.code))
      raise Exception, 'apiRequest failed. HTTPError: ' + str(e.code)
    except urllib2.URLError, e:
      appLog('error', 'apiRequest failed. URLError: ' + str(e.reason))
      raise Exception, 'apiRequest failed. URLError: ' + str(e.reason)
    except httplib.HTTPException, e:
      appLog('error', 'apiRequest failed. HTTPException: ' + traceback.format_exc())
      raise Exception, 'apiRequest failed. HTTPException: ' + traceback.format_exc()
    except Exception, e:
      appLog('error', 'apiRequest failed. Unknown exception: ' + traceback.format_exc())
      raise Exception, 'apiRequest failed. Unknown exception: ' + traceback.format_exc()

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
      appLog('error', 'apiRequest failed. HTTPError: ' + str(e.code))
      raise Exception, 'apiRequest failed. HTTPError: ' + str(e.code)
    except urllib2.URLError, e:
      appLog('error', 'apiRequest failed. URLError: ' + str(e.reason))
      raise Exception, 'apiRequest failed. URLError: ' + str(e.reason)
    except httplib.HTTPException, e:
      appLog('error', 'apiRequest failed. HTTPException: ' + traceback.format_exc())
      raise Exception, 'apiRequest failed. HTTPException: ' + traceback.format_exc()
    except Exception, e:
      from traceback import print_exc
      print_exc()
      appLog('error', 'apiRequest failed. Unknown exception: ' + traceback.format_exc())
      raise Exception, 'apiRequest failed. Unknown exception: ' + traceback.format_exc()

###########################
# Class: API authorization#
###########################
class apiAuth:
  def __init__(self):
    self.access_token = False
    self.apiRequest = apiRequest() 
    if debug == True: appLog('debug', 'Initialzed apiAuth')

  # Get code for polling.
  def getCode(self, provider, appkey):
    if debug == True: appLog('debug', 'Trying to fetch apiAuth code: ' + provider + ' ' + appkey)
    try:
      args = {'get_code': '', 'provider': provider, 'appkey': appkey}
      result = self.apiRequest.get("https://tools.schmidt.ps/authApp", args)
      data = json.loads(result)
    except Exception, e:
      if debug == True: appLog('debug', 'Failed to fetch apiAuth code', traceback.format_exc())
      return None

    if 'error' in data:
      if debug == True: appLog('debug', 'Error in reply of apiAuth code-request')
      return None

    if debug == True: appLog('debug', 'Got valid apiAuth code: ' + str(data['code']))
    return data['code']

  # Poll code and wait for result.
  def pollCode(self, code):
    loop = True
    print "Waiting for authorization..."
    while loop == True:
      args = {'poll_code': code}
      result = self.apiRequest.get("https://tools.schmidt.ps/authApp", args)
      data = json.loads(result)

      if 'error' in data:
        return False

      if data['state'] == 'invalid':
        return None
      if data['state'] == 'valid':
        return data['authkey']
      sleep(1)
    return False

#####################
# Global functions. #
#####################

# Log messages to stdout.
def appLog(mode, text, reason=""):
  msg = "[" + mode.upper() + "] " + text
  if reason != "":
    msg = msg + " (" + reason + ")" 
  print msg

# Let the user authorize this application.
def getAccessToken():
  dropbox_appkey = "fg7v60fm9f5ud7n"
  sandbox_appkey = "nstd2c6lbyj4z9b"
  
  print ""
  print "Please choose which permission this application will request:"
  print "Enter 'd' - This application will have access to your whole"
  print "            Dropbox."
  print "Enter 's' - This application will just have access to its"
  print "            own application folder."
  print ""
  validinput = False
  while validinput == False:
    perm = raw_input("Please enter permission key: ").strip() 
    if perm.lower() == 'd' or perm.lower() == 's':
      validinput = True

  appkey = ""
  if perm.lower() == 'd':
    appkey = "fg7v60fm9f5ud7n"
  if perm.lower() == 's':
    appkey = "nstd2c6lbyj4z9b"

  aa = apiAuth()
  code = aa.getCode('dropbox', appkey)
  if code is not None:
    print ""
    print "Please visit http://tools.schmidt.ps/authApp and use the following"
    print "code to authorize this application: " + str(code)
    print ""

    authkey = aa.pollCode(code)
    if authkey != False and authkey != None:
      print "Thanks for granting permission\n"
      return authkey

    if authkey == None:
      print "Rejected permission"

    if authkey == False:
     print "Authorization request expired"
  else:
    print "Failed to start authorization process"

  return False

##############
# Main entry #
##############
# Global variables.
access_token = False
cache_time = 120 # Seconds
write_cache = 4194304 # Bytes
use_cache = False
allow_other = False
allow_root = False
debug = False
debug_raw = False
debug_fuse = False
if __name__ == '__main__':
  print '********************************************************'
  print '* FUSE Filesystem 4 Dropbox                            *'
  print '*                                                      *'
  print '* Copyright 2014                                       *'                  
  print '* Sascha Schmidt <sascha@schmidt.ps>                   *'
  print '*                                                      *'
  print '* https://github.com/realriot/ff4d/blob/master/LICENSE *'
  print '********************************************************'
  print ''

  parser = argparse.ArgumentParser()
  parser.add_argument('-d', '--debug', help='Show debug output', action='store_true', default=False)
  parser.add_argument('-dr', '--debug-raw', help='Show raw debug output', action='store_true', default=False)
  parser.add_argument('-df', '--debug-fuse', help='Show FUSE debug output', action='store_true', default=False)

  # Mutual exclusion of arguments. 
  atgroup = parser.add_mutually_exclusive_group()
  atgroup.add_argument('-ap', '--access-token-perm', help='Use this access token permanently (will be saved)', default=False)
  atgroup.add_argument('-at', '--access-token-temp', help='Use this access token only temporarily (will not be saved)', default=False)

  parser.add_argument('-ao', '--allow-other', help='Allow other users to access this FUSE filesystem', action='store_true', default=False)
  parser.add_argument('-ar', '--allow-root', help='Allow root to access this FUSE filesystem', action='store_true', default=False)
  parser.add_argument('-ct', '--cache-time', help='Cache Dropbox data for X seconds (120 by default)', default=120, type=int)
  parser.add_argument('-wc', '--write-cache', help='Cache X bytes (chunk size) before uploading to Dropbox (4 MB by default)', default=4194304, type=int)
  parser.add_argument('-bg', '--background', help='Pushes FF4D into background', action='store_false', default=True)
  
  parser.add_argument('mountpoint', help='Mount point for Dropbox source')
  args = parser.parse_args()

  # Set variables supplied by commandline.
  cache_time = args.cache_time
  write_cache = args.write_cache
  allow_other = args.allow_other
  allow_root = args.allow_root
  debug = args.debug
  debug_raw = args.debug_raw
  debug_fuse = args.debug_fuse

  # Check ranges and values of given arguments.
  if cache_time < 0:
    appLog('error', 'Only positive values for cache-time are possible')
    sys.exit(-1)
  if write_cache < 4096:
    appLog('error', 'The minimum write-cache has a size of 4096 Bytes')
    sys.exit(-1)

  # Check wether the mountpoint is a valid directory.
  mountpoint = args.mountpoint
  if not os.path.isdir(mountpoint):
    appLog('error', 'Given mountpoint is not a directory.')
    sys.exit(-1)

  # Check for an existing configuration file.
  try:
    scriptpath = os.path.dirname(sys.argv[0])
    f = open(scriptpath + '/ff4d.config', 'r')
    access_token = f.readline()
    if debug == True: appLog('debug', 'Got accesstoken from configuration file: ' + str(access_token))
  except Exception, e:
    pass

  # Check wether the user gave an Dropbox access_token as argument.
  if args.access_token_perm != False:
    if debug == True: appLog('debug', 'Got permanent accesstoken from command line: ' + args.access_token_perm)
    access_token = args.access_token_perm
  if args.access_token_temp != False:
    if debug == True: appLog('debug', 'Got temporary accesstoken from command line: ' + args.access_token_temp)
    access_token = args.access_token_temp

  # Check the need to fetch a new access_token.
  if access_token == False:
    appLog('info', 'No accesstoken available. Fetching a new one.')
    access_token = getAccessToken()
    if debug == True: appLog('debug', 'Got accesstoken from user input: ' + str(access_token))

  # Check wether an access_token exists.
  if access_token == False:
    appLog('error', 'No valid accesstoken available. Exiting.')
    sys.exit(-1)

  # Validate access_token.
  ar = apiRequest()
  account_info = ''
  try:
    headers = {'Authorization' : 'Bearer ' + access_token}
    account_info = ar.get('https://api.dropbox.com/1/account/info', None, headers)
  except Exception, e:
    appLog('error', 'Could not talk to Dropbox API.', traceback.format_exc())
    sys.exit(-1)
  ar.headers = {'Authorization' : 'Bearer ' + access_token}

  # Save valid access token to configuration file.
  if args.access_token_temp == False:
    try:
      scriptpath = os.path.dirname(sys.argv[0])
      f = open(scriptpath + '/ff4d.config', 'w')
      f.write(access_token)
      f.close()
      os.chmod(scriptpath + '/ff4d.config', 0600)
      if debug == True: appLog('debug', 'Wrote accesstoken to configuration file.\n')
    except Exception, e:
      appLog('error', 'Could not write configuration file.', traceback.format_exc())

  # Everything went fine and we're authed against the Dropbox api.
  print "Welcome " + account_info['display_name']
  print "Space used: " + str(account_info['quota_info']['normal']/1024/1024/1024) + " GB"
  print "Space available: " + str(account_info['quota_info']['quota']/1024/1024/1024) + " GB"
  print ""
  print "Starting FUSE..."
  try:
    FUSE(Dropbox(ar), mountpoint, foreground=args.background, debug=debug_fuse, sync_read=True, allow_other=allow_other, allow_root=allow_root)
  except Exception, e:
    appLog('error', 'Failed to start FUSE...', traceback.format_exc())
    sys.exit(-1)

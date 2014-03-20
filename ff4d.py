#!/usr/bin/python
# Copyright (c) 2014 Sascha Schmidt <sascha@schmidt.ps> (author)
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

import os, sys, pwd, errno, dropbox
from time import time, mktime
from datetime import datetime
from stat import S_IFDIR, S_IFLNK, S_IFREG
from fuse import FUSE, FuseOSError, Operations
from errno import *

# DEBUG settings.
debug = True
debug_raw = True
debug_unsupported = True

# Global variables.
access_token = False
write_cache = 4194304 # Bytes

# FUSE Class to handle operations.
class Dropbox(Operations):
  def __init__(self, access_token, client, restclient):
    self.access_token = access_token
    self.client = client
    self.restclient = restclient
    self.cache = {}
    self.openfh = {}

  #####################
  # Helper functions. #
  #####################

  # Get a valid and unique filehandle.
  def getFH(self):
    for i in range(1,8193):
      if i not in self.openfh:
        self.openfh[i] = False
        return i
    return False

  # Release a filehandle.
  def releaseFH(self, fh):
    if fh in self.openfh:
      self.openfh.pop(fh)
    else:
      return False

  # Upload data to Dropbox via RESTClient.
  def DropboxUploadChunk(self, data, upload_id = "", offset = 0):
    if upload_id != "":
      upload_id = "&upload_id=" + upload_id
    headers = { "Authorization" : "Bearer " + access_token }
    url = 'https://api-content.dropbox.com/1/chunked_upload?offset=' + str(offset) + upload_id
    result = restclient.request(
               "POST",
               url.encode("utf-8"),
               None,
               data,
               headers,
               False
             )
    return result 

  # Finish upload of chuncked data to Dropbox.
  def DropboxUploadChunkFinish(self, path, upload_id):
    headers = { "Authorization" : "Bearer " + access_token }
    post_params = { 'overwrite':True, 'upload_id':upload_id }
    result = restclient.request(
               "POST",
               "https://api-content.dropbox.com/1/commit_chunked_upload/sandbox" + path,
               post_params,
               None,
               headers,
               False
             )
    return result

  # Get metadata for a file or folder from the Dropbox API.
  def getDropboxMetadata(self, path):
    if path in self.cache:
      if debug == True: appLog('debug', 'Found cached metadata for path: ' + path)
      item = self.cache[path]

      # Check if we have to cache subitems of this object.
      if item['is_dir'] == True:
        for tmp in item['contents']:
          if tmp['is_dir'] == True:
            if tmp['path'] not in self.cache:
              if debug == True: appLog('debug', 'Subitem not found in cache: ' + tmp['path'].encode("utf-8"))
              try:
                subitem = client.metadata(tmp['path'].encode("utf-8"))
              except dropbox.rest.ErrorResponse, e:
                appLog('error', 'Could not fetch metadata for: ' + tmp['path'].encode("utf-8"), e.reason)
                if e.status == 404:
                  return False
                else:
                  raise FuseOSError(EREMOTEIO)
              # Cache newly fetched subfolder of cached folder.
              self.cache[tmp['path'].encode("utf-8")] = subitem
              if debug_raw == True: appLog('debug', 'Data from Dropbox API call: metadata(' + tmp['path'].encode("utf-8") + ')')
              if debug_raw == True: appLog('debug', str(subitem))
              # Cache files of subfolder.
              for subtmp in subitem['contents']:
                if subtmp['is_dir'] == False:
                  self.cache[subtmp['path'].encode("utf-8")] = subtmp
    else:
      if debug == True: appLog('debug', 'No cached metadata for path: ' + path)
      try:
        item = client.metadata(path)
        if item['is_dir'] == False:
           if 'is_deleted' in item:
             return False
           else:
             return item
      except dropbox.rest.ErrorResponse, e:
        appLog('error', 'Could not fetch metadata for: ' + path, e.reason)
        if e.status == 404:
          return False
        else:
          raise FuseOSError(EREMOTEIO)
      # If the item has the "deleted" flag.
      if 'is_deleted' in item:
        return False

      if debug_raw == True: appLog('debug', 'Data from Dropbox API call: metadata(' + path + ')')
      if debug_raw == True: appLog('debug', str(item))

      # Cache directory data.
      self.cache[path] = item
      for tmp in item['contents']:
         if tmp['is_dir'] == True:
           if debug == True: appLog('debug', 'Create sub-cache for path: ' + tmp['path'].encode("utf-8"))
           try:
             subitem = client.metadata(tmp['path'].encode("utf-8"))
           except dropbox.rest.ErrorResponse, e:
             appLog('error', 'Could not fetch metadata for: ' + tmp['path'].encode("utf-8"), e.reason)
             if e.status == 404:
               return False
             else:
               raise FuseOSError(EREMOTEIO)
           # Cache subfolder.
           self.cache[tmp['path'].encode("utf-8")] = subitem
           if debug_raw == True: appLog('debug', 'Data from Dropbox API call: metadata(' + tmp['path'].encode("utf-8") + ')')
           if debug_raw == True: appLog('debug', str(subitem))
           # Cache files of subfolder.
           for subtmp in subitem['contents']:
             if subtmp['is_dir'] == False:
               self.cache[subtmp['path'].encode("utf-8")] = subtmp
         else:
           # Cache file information.
           self.cache[tmp['path'].encode("utf-8")] = tmp
    return item

  #########################
  # Filesystem functions. #
  #########################
  def mkdir(self, path, mode):
    if debug == True: appLog('debug', 'Called: mkdir() - Path: ' + path)
    try:
      client.file_create_folder(path)
    except dropbox.rest.ErrorResponse, e:
      appLog('error', 'Could not create folder: ' + path, e.reason)
      raise FuseOSError(EIO)
    # Update cache.
    self.cache.pop(os.path.dirname(path))

  # Remove a directory.
  def rmdir(self, path):
    if debug == True: appLog('debug', 'Called: rmdir() - Path: ' + path)
    try:
      client.file_delete(path)
    except dropbox.rest.ErrorResponse, e:
      appLog('error', 'Could not delete folder: ' + path, e.reason)
      raise FuseOSError(EIO)

    # Finally remove folder from cache.
    self.cache.pop(path)
    self.cache.pop(os.path.dirname(path))
    if debug == True: appLog('debug', 'Successfully deleted folder: ' + path) 
    return 0

  # Remove a file.
  def unlink(self, path):
    if debug == True: appLog('debug', 'Called: unlink() - Path: ' + path)
    try:
      client.file_delete(path)
    except dropbox.rest.ErrorResponse, e:
      appLog('error', 'Could not delete file: ' + path, e.reason)
      raise FuseOSError(EIO)

    # Finally remove the file from cache.
    self.cache.pop(path)
    self.cache.pop(os.path.dirname(path))
    if debug == True: appLog('debug', 'Successfully deleted file: ' + path)
    return 0 

  # Rename a file or directory.
  def rename(self, old, new):
    if debug == True: appLog('debug', 'Called: rename() - Old: ' + old + ' New: ' + new)
    try:
      result = client.file_move(old, new)
    except dropbox.rest.ErrorResponse, e:
      appLog('error', 'Could not rename object: ' + old, e.reason)
      raise FuseOSError(EIO)
    # Update cache.
    if result['is_dir'] == True:
      self.cache.pop(old)
      self.cache.pop(new)
    else:
      self.cache.pop(old)
      self.cache.pop(os.path.dirname(old))
      self.cache.pop(os.path.dirname(new))
    if debug == True: appLog('debug', 'Successfully renamed object: ' + old)
    if debug_raw == True: appLog('debug', str(result))

  # Read data from a filehandle.
  def read(self, path, length, offset, fh):
    if debug == True: appLog('debug', 'Called: read() - Path: ' + path + ' Length: ' + str(length) + ' Offset: ' + str(offset) + ' FH: ' + str(fh))
    if fh in self.openfh:
      try:
        f = client.get_file(path)
        self.openfh[fh] = f
      except dropbox.rest.ErrorResponse, e:
        appLog('error', 'Could not open remote file: ' + path, e.error_msg)
        raise FuseOSError(EIO) 
    else:
      raise FuseOSError(EIO)

    if debug == True: appLog('debug', 'Reading ' + str(length) + ' bytes from source...')
    f = self.openfh[fh]
    return f.read(length)

  # Write data to a filehandle.
  def write(self, path, buf, offset, fh):
    if debug == True: appLog('debug', 'Called: write() - Path: ' + path + ' Offset: ' + str(offset) + ' FH: ' + str(fh))
    try:
      # Check for the beginning of the file.
      if fh in self.openfh:
        if self.openfh[fh] == False: 
          if debug == True: appLog('debug', 'Uploading first chunk to Dropbox...')
          # Check if the write request exceeds the maximum buffer size.
          if len(buf) >= write_cache or len(buf) < 4096: 
            if debug == True: appLog('debug', 'Cache exceeds configured write_cache. Uploading...')
            result = self.DropboxUploadChunk(buf, "", 0)
            print "Uploaded: " + str(result)
            print "Write bytes: " + str(len(buf))
            self.openfh[fh] = {'upload_id':result['upload_id'], 'offset':result['offset'], 'buf':''}

            # Check if we've finished the upload.
            if len(buf) < 4096:
              result = self.DropboxUploadChunkFinish(path, result['upload_id'])
          else:
            if debug == True: appLog('debug', 'Buffer does not exceed configured write_cache. Caching...') 
            self.openfh[fh] = {'upload_id':'', 'offset':0, 'buf':buf}
          return len(buf) 
        else:
          if debug == True: appLog('debug', 'Uploading another chunk to Dropbox...')
          if len(buf)+len(self.openfh[fh]['buf']) >= write_cache or len(buf) < 4096:
            if debug == True: appLog('debug', 'Cache exceeds configured write_cache. Uploading...')
            result = self.DropboxUploadChunk(self.openfh[fh]['buf']+buf, self.openfh[fh]['upload_id'], self.openfh[fh]['offset'])
            print "Uploaded: " + str(result)
            print "Write bytes: " + str(len(buf)+len(self.openfh[fh]['buf']))
            self.openfh[fh] = {'upload_id':result['upload_id'], 'offset':result['offset'], 'buf':''}

            # Check if we've finished the upload.
            if len(buf) < 4096:
              result = self.DropboxUploadChunkFinish(path, result['upload_id'])
          else:
            if debug == True: appLog('debug', 'Buffer does not exceed configured write_cache. Caching...')
            self.openfh[fh].update({'buf':self.openfh[fh]['buf']+buf})
          return len(buf) 
      else:
        raise FuseOSError(EIO) 
    except dropbox.rest.ErrorResponse, e:
      appLog('error', 'Could not write to remote file: ' + path, e.error_msg)
      raise FuseOSError(EIO)

  # Open a filehandle.
  def open(self, path, flags):
    if debug == True: appLog('debug', 'Called: open() - Path: ' + path + ' Flags: ' + str(flags))
    fh = self.getFH()
    if debug == True: appLog('debug', 'Returning unique filehandle: ' + str(fh))
    return fh

  # Create a file.
  def create(self, path, mode):
    if debug == True: appLog('debug', 'Called: create() - Path: ' + path + ' Mode: ' + str(mode))
    fh = self.getFH()
    if debug == True: appLog('debug', 'Returning unique filehandle: ' + str(fh))

    now = datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0000')
    cachedfh = {'bytes':0, 'modified':now, 'path':path, 'is_dir':False}
    self.cache[path] = cachedfh
    return fh

  # Release (close) a filehandle.
  def release(self, path, fh):
    if debug == True: appLog('debug', 'Called: release() - Path: ' + path + ' FH: ' + str(fh))
    self.releaseFH(fh)
    if debug == True: appLog('debug', 'Released filehandle: ' + str(fh)) 
    # Update cache.
    self.cache.pop(os.path.dirname(path))    
    return 0

  # Truncate a file to overwrite it.
  def truncate(self, path, length, fh=None):
    if debug == True: appLog('debug', 'Called: truncate() - Path: ' + path)
    return 0

  # List the content of a directory.
  def readdir(self, path, fh):
    if debug == True: appLog('debug', 'Called: readdir() - Path: ' + path)

    # Fetch folder informations.
    fusefolder = ['.', '..']
    metadata = self.getDropboxMetadata(path)

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
      dircount = 0
      for content in item['contents']:
        if content['is_dir'] == True:
          dircount = dircount + 1
      dircount = dircount + 2
      properties = dict(
        st_mode=S_IFDIR | 0444,
        st_size=0,
        st_ctime=modified,
        st_mtime=modified,
        st_atime=now,
        st_uid=uid,
        st_gid=gid,
        st_nlink=dircount,
      )
      if debug == True: appLog('debug', 'Returning properties for directory: ' + path + ' (' + str(properties) + ')')
      return properties 
    else:
      properties = dict(
        st_mode=S_IFREG | 0444,
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

  ########################################
  # Not supported by transport endpoint. #
  ########################################
  def mknod(self, path, mode, dev):
    if debug_unsupported == True: appLog('debug', 'Called: mknod() - Path: ' + path)
    raise FuseOSError(EOPNOTSUPP)
  def symlink(self, target, source):
    if debug_unsupported == True: appLog('debug', 'Called: symlink() - Path: ' + path)
    raise FuseOSError(EOPNOTSUPP)
  def setxattr(self, path, name, value, options, position=0):
    if debug_unsupported == True: appLog('debug', 'Called: setxattr() - Path: ' + path)
    raise FuseOSError(EOPNOTSUPP)
  def removexattr(self, path, name):
    if debug_unsupported == True: appLog('debug', 'Called: removexattr() - Path: ' + path)
    raise FuseOSError(EOPNOTSUPP)
  def listxattr(self, path):
    if debug_unsupported == True: appLog('debug', 'Called: listxattr() - Path: ' + path)
    raise FuseOSError(EOPNOTSUPP)
  def getxattr(self, path, name, position=0):
    if debug_unsupported == True: appLog('debug', 'Called: getxattr() - Path: ' + path)
    raise FuseOSError(EOPNOTSUPP)
  def destroy(self, path):
    if debug_unsupported == True: appLog('debug', 'Called: destroy() - Path: ' + path)
    raise FuseOSError(EOPNOTSUPP)
  def chown(self, path, uid, gid):
    if debug_unsupported == True: appLog('debug', 'Called: chown() - Path: ' + path)
    raise FuseOSError(EOPNOTSUPP)
  def chmod(self, path, mode):
    if debug_unsupported == True: appLog('debug', 'Called: chmod() - Path: ' + path)
    raise FuseOSError(EOPNOTSUPP)
  def fsync(self, path, fdatasync, fh):
    if debug_unsupported == True: appLog('debug', 'Called: fsync() - Path: ' + path)
    raise FuseOSError(EOPNOTSUPP)

#####################
# Global functions. #
#####################

# Log messages to stdout.
def appLog(mode, text, reason = ""):
  msg = "[" + mode.upper() + "] " + text
  if reason != "":
    msg = msg + " (" + reason + ")" 
  print msg

# Let the user authorize this application.
def getAccessToken():
  print ""
  print "1. Go to: 'http://api.schmidt.ps/authFUSEFilesystem4Dropbox'"
  print "2. Follow the instructions to generate an access token."
  print "   You can choose between full access (Dropbox mode) and"
  print "   jailed access (Sandbox mode)."
  access_token = raw_input("3. Enter the access token: ").strip()

  return access_token

##############
# Main entry #
##############
if __name__ == '__main__':
  print "*****************************"
  print "* FUSE Filesystem 4 Dropbox *"
  print "*****************************"
  print ""

  # Handle arguments.
  if len(sys.argv) < 2 or len(sys.argv) > 3:
    print "Wrong syntax:"
    print "./ff4d <mount point> [access token]"
    sys.exit(-1)

  # Check wether the mountpoint is a valid directory.
  mountpoint = sys.argv[1]
  if not os.path.isdir(mountpoint):
    appLog('error', 'Given mountpoint is not a directory.')
    sys.exit(-1)

  # First of all check for an existing configuration file.
  try:
    scriptpath = os.path.dirname(sys.argv[0])
    f = open(scriptpath + '/ff4d.config', 'r')
    access_token = f.readline()
    if debug == True: appLog('debug', 'Got accesstoken from configuration file: ' + access_token)
  except:
    pass

  # Check wether the user gave an Dropbox access_token as argument.
  if len(sys.argv) == 3:
    access_token = sys.argv[2]
    if debug == True: appLog('debug', 'Got accesstoken from command line: ' + access_token)

  # Check the need to fetch a new access_token.
  if len(sys.argv) == 2 and access_token == False:
    appLog('info', 'No accesstoken available. Fetching a new one.')
    access_token = getAccessToken()
    if debug == True: appLog('debug', 'Got accesstoken from user input: ' + access_token)

  # Check wether an access_token exists.
  if access_token == False:
    appLog('error', 'No valid accesstoken present. Exiting.')
    sys.exit(-1)

  # Validate access_token.
  restclient = dropbox.client.RESTClient()
  client = dropbox.client.DropboxClient(access_token)
  account_info = ''
  try:
    account_info = client.account_info()
  except dropbox.rest.ErrorResponse, e:
    appLog('error', 'Could not talk to Dropbox API.', e.reason)
    sys.exit(-1)

  # Save valid access token to configuration file.
  try:
    scriptpath = os.path.dirname(sys.argv[0])
    f = open(scriptpath + '/ff4d.config', 'w')
    f.write(access_token)
    f.close()
    os.chmod(scriptpath + '/ff4d.config', 0600)
    if debug == True: appLog('debug', 'Wrote accesstoken to configuration file.\n')
  except Exception, e:
    appLog('error', 'Could not write configuration file.', str(e))

  # Everything went fine and we're authed against the Dropbix api.
  print "Welcome " + account_info['display_name']
  print "Space used: " + str(account_info['quota_info']['normal']/1024/1024/1024) + " GB"
  print "Space available: " + str(account_info['quota_info']['quota']/1024/1024/1024) + " GB"
  print ""
  print "Starting FUSE..."
  FUSE(Dropbox(access_token, client, restclient), mountpoint, foreground=True)


'''FUSE Filesystem 4 Dropbox''' is a FUSE plugin whichs allows a local mount of your
global Dropbox or jailed application folder.

To improve the browsing experience of your Dropbox content this plugin will cache
the structure for a certain amount of time. This python script uses '''libfuse''' to
provide FUSE function to the operating system.

=== Donation ===
Since I'm developing in my free time I'd like to ask you to support my work.
You can do it by contributing 5 EUR via paypal. This will give me motivation
to keep on coding and fixing bugs.

Thanks in advance

[https://www.paypal.com/cgi-bin/webscr?no_note=0&lc=US&business=realriot%40realriot.de&item_name=GitHub+-+ff4d&cmd=_donations&currency_code=USD '''DONATE NOW VIA PAYPAL''']

=== Requirements ===
There are some requirements which have to be fulfilled to make this plugin work.
* FUSE has to be installed (http://fuse.sourceforge.net/). On Debian/Ubuntu you can install FUSE with
 apt-get install libfuse2
* Python pkg-resources must be installed. On Debian/Ubuntu you can install it via
 apt-get install python-pkg-resources
* You need pip to install Python packages. On Debian/Ubuntu just use
 apt-get install python-pip
* You need to install the "dropbox" Python package which is required by FF4D. This can be done via the recently installed pip
 pip install dropbox
* The user must have the permission to mount FUSE filesystems. On Debian/Ubuntu systems the user must belong to the group "fuse".
 adduser <user> fuse

=== Compatible systems ===
I've tested this script running on:

* Linux X86
* Linux X64
* Mac OS X

Other systems may work...

=== Authorize access ===
You can use the dropbox internal process to generate an access_token:
https://blogs.dropbox.com/developers/2014/05/generate-an-access-token-for-your-own-account/

Or you can use the enclosed '''./getDropboxAccessToken.py''' script to fetch a token.

'''Please secure your access token. NOBODY may know it! This token allows full access
to your configured dropbox space.'''

=== Usage ===
Quick start:

 ./ff4d.py <mount folder>

The accesstoken can optionally supplied via commandline. Normaly the plugin will ask you just one time
and saves it to a configuration file.

You can see all the mighty arguments by showing the help:

 ./ff4d.py -h

Greets and have fun with this little goodie...
''Sascha Schmidt''

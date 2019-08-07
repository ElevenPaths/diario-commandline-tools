diario-commandline-client
=========================

* [What is this?](#what-is-this)
* [Assumptions](#assumptions)
* [Installation](#installation)
* [Setup project](#setup-project)
* [Usage](#usage)

What is this?
-------------

A utiliy repository created to ease bulk [diario](https://diario.e-paths.com/) API consumption. Currently these functions are fully implemented:

- Upload a file (PDF or Microsoft Office document)
- Upload a complete directory of files
- Query a singled hash
- Query a list of hashes (from a single file)

How do I get a DIARIO account
-----------------------------

Write an email to labs@11paths.com


Warning & Disclaimer
--------------------

Although DIARIO is supposed to upload just a part of the
document to our servers—so you can be sure that your privacy is preserved
(more information: [https://diario.e.-paths.com](https://diario.e.-paths.com)) — this script uploads the whole
document because it is assumed that it will be used for malware analyses.
If you wish to upload a batch of documents and keep your privacy by uploading
just a part of it, please use our Windows/Linux/Mac client with a user interface.
It is available from [https://diario-.e-paths.com](https://diario-.e-paths.com)


Assumptions
-----------

* You are using Python 3.x
* You have [virtualenv](https://pypi.python.org/pypi/virtualenv) and [virtualenvwrapper](https://pypi.python.org/pypi/virtualenvwrapper) installed and working.


Installation
------------

```
cd diario-commandline-client
mkvirtualenv -p `which python3` diario-commandline-client
pip install -r requirements.txt
```

Setup Project
-------------

Make sure the virtualenv is activated, if it is not, run `workon diario-bulk`.

First you'll need to create an API client from the diario admin portal, doing so will generate an app_id and a secret. We advise that you use enviromental variables to store that information `API_CLIENT_APP_ID` and `API_CLIENT_SECRET` respectively.

You can do so by using virtualenv hooks `postactivate` and `predeactivate` located in 'bin' inside your virtualenv folder. If you have your virtualenv activated you can move to your virtualenv folder using `cdvirtualenv`.

```postactivate
	# This hook is sourced after this virtualenv is activated.
	export API_CLIENT_APP_ID=XXXXXXXX
	export API_CLIENT_SECRET=XXXXXXXX
```

```predeactivate
	# This hook is sourced before this virtualenv is deactivated.
	unset API_CLIENT_APP_ID
	unset API_CLIENT_SECRET
```

If you prefer not to use the recommended environmental variables you can pass both the `app_id` and `secret` as arguments to the script. Arguments to the script will take precedence over any environment variables found.

Usage
-----

- Get help on the usage of the scripts:

Remember: where <host> is indicated, protocol handler is mandatory (https://)

```
upload.py -h
```

```
gethash.py -h
```

- Upload a single document (no need to indicate file type):

```
./upload.py -f <path_to_file>
```

- Upload a directory (again, no need to indicate file type):

```
./upload.py -d <path_to_directory>
```

- Query a single hash:

```
./gethash.py --hash <hash>
```

- Query multiple hashes from an index file (again, no need to indicate file type):

```
./gethash.py -f <file_with_hashes>
```

- Query multiple hashes and store results in a file instead of `stdout`

```
./gethash.py -f <file_with_hashes> -l <logfile>
```

- Providing diario `app_id` and `secret` as arguments (works on any script). Let's see an upload example

```
./upload.py -s <diario_secret> -a <diario_client_id> -d <path_to_directory>
```

_Arguments to files and folders can be relative paths or absolute paths_
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import json
import os
import queue
import sys
import threading

from diario import Diario
from diario.admin import DiarioAdmin, Prediction

__VERSION = "1.2"

__DISCLAIMER = """
Warning & Disclaimer: Although DIARIO is supposed to upload just a part of the
document to our servers—so you can be sure that your privacy is preserved
(more information: https://diario.e.-paths.com)— this script uploads the whole
document because it is assumed that it will be used for malware analyses.
If you wish to upload a batch of documents and keep your privacy by uploading
just a part of it, please use our Windows/Linux/Mac client with a user interface.
It is available from https://diario-.e-paths.com
"""

VALIDATION_VALUES = ["pdf_malware", "pdf_goodware", "office_malware", "office_goodware"]


def _format_validation_values():
    return "{0}".format("\n".join(VALIDATION_VALUES))


class UnknownValidationValue(Exception):
    def __init__(self, message):
        super(UnknownValidationValue, self).__init__(message)


class Counter:
    def __init__(self, total):
        self.counter = 0
        self.total = total
        self.good_ones = []
        self.bad_ones = []

    def add_good(self, good):
        self.counter += 1
        self.good_ones.append(good)

    def add_bad(self, bad):
        self.counter += 1
        self.bad_ones.append(bad)

    def report_bad(self):
        for entry in self.bad_ones:
            print("{0}".format(entry))
        print()

    def report_good(self):
        for entry in self.good_ones:
            print("{0}".format(entry))
        print()


def progress(count, total, status=""):
    bar_length = 60
    filled_length = int(round(bar_length * count / float(total)))
    percents = round(100.0 * count / float(total), 1)
    bar = "=" * filled_length + "-" * (bar_length - filled_length)
    sys.stdout.write("[%s] %s%s ...%s\r" % (bar, percents, "%", status))


def _validate(args, d, hash_list):
    print("Document validation...\n")
    counter = 0
    # DIARIO API v1 need to specify the document type when validating hashes
    resp = None
    validation = (
        Prediction.MALWARE
        if args.validation.endswith("malware")
        else Prediction.GOODWARE
    )

    # Is the hash's document a PDF or OFFICE?
    if args.validation.startswith("pdf"):
        validation_function = d.validate_pdf
    else:
        validation_function = d.validate_office

    # Let's do validation
    for document_hash in hash_list:
        d_hash = document_hash.split('\t')[0]
        resp = validation_function(d_hash, validation)
        counter += 1
        progress(counter, len(hash_list), "Validating")
        # Do we found an error in the validation process?
        if resp and not resp.urllib3_response.status == 200:
            print("Error validating document: {0}".format(resp.json["error"]))

    print("Validated {0} of {1} files".format(counter, len(hash_list)))
    print("\nDone")


def _upload(q, d, lock, counter):
    while True:
        task = q.get()

        if task is None:
            break

        resp = d.upload(task)

        lock.acquire()
        try:
            if not "error" in resp.json.keys():
                # print(json.dumps(resp.json, indent=2, sort_keys=True))
                document_hash = resp.json["data"]["hash"]
                counter.add_good("{1}\t{0}".format(task, document_hash))
                progress(counter.counter, counter.total, "Uploading")

            else:
                error_code = resp.json["error"]["code"]
                error_message = resp.json["error"]["message"]
                print(
                    "{0} -> API Error {1}: {2}".format(task, error_code, error_message)
                )
                counter.add_bad(task)

        except Exception as e:
            print("[!] Error when uploading {0}".format(task))
            print(e)

        finally:
            lock.release()
            q.task_done()


def run(args, app_id, secret):
    """
    main loop
    """

    # Create the main object for dealing with diario
    host = "https://diario-elevenlabs.e-paths.com"
    port = 443

    if args.ip:
        host = args.ip
    if args.port:
        port = args.port

    diario = DiarioAdmin(app_id, secret, host=host, port=port)

    all_files = []
    q = queue.Queue()
    threads = []
    lock = threading.Lock()
    threads_number = args.threads_number

    # Do we have a single file? Add it to all_files
    if args.upload_file:
        all_files.append(args.upload_file)
    # or we have a complete dir? Add directory files to all_files
    elif args.upload_dir:
        for root, dirs, files in os.walk(args.upload_dir, topdown=True):
            #  Filter out hidden folders and files
            files = [f for f in files if not f[0] == "."]
            dirs[:] = [d for d in dirs if not d[0] == "."]
            all_files.extend([os.path.join(root, name) for name in files])

    counter = Counter(len(all_files))

    if args.validation and not args.validation in VALIDATION_VALUES:
        raise UnknownValidationValue(
            "Validation must be one of {0}".format(", ".join(VALIDATION_VALUES))
        )

    print("These files will be uploaded:")
    for entry in all_files:
        print("\t{0}".format(entry))
    print("Total: {0}\n".format(len(all_files)))

    if not args.yes_upload:
        yes_or_not = input("proceed? [y/n] ")
        if not yes_or_not == "y":
            sys.exit()

    # Fill queue
    for file_entry in all_files:
        q.put(file_entry)

    # Start threads
    for _ in range(threads_number):
        t = threading.Thread(target=_upload, args=(q, diario, lock, counter))
        t.start()
        threads.append(t)

    q.join()

    # Wait until all task are done
    for _ in range(threads_number):
        q.put(None)

    # Wait until all threads are done
    for t in threads:
        t.join()

    print("\nUploaded {0} of {1} files\n".format(counter.counter, len(all_files)))

    if args.summary:
        print("{0} files with errors:".format(len(counter.bad_ones)))
        counter.report_bad()
        print("{0} successfully uploaded files:\n".format(counter.counter))
        counter.report_good()

    if args.validation:
        _validate(args, diario, counter.good_ones)


if __name__ == "__main__":
    # Parse command-line arguments.
    parser = argparse.ArgumentParser(
        description="Bulk multithreaded uploader to DIARIO (v: %s). " % __VERSION
    )

    # Cosmetic hack to show optional arguments at the end of the usage message
    optional = parser._action_groups.pop()

    required = parser.add_argument_group("required arguments")
    # remove this line: optional = parser...
    optional.add_argument(
        "-i", "--ip", dest="ip", help="example: https://diario-elevenlabs.e-paths.com"
    )
    optional.add_argument("-p", "--port", dest="port", help="example: 8080")

    mutually_exclusive = parser.add_mutually_exclusive_group(required=True)
    mutually_exclusive.add_argument(
        "-f", "--file", dest="upload_file", help="file to upload"
    )
    mutually_exclusive.add_argument(
        "-d", "--dir", dest="upload_dir", help="folder to upload"
    )

    optional.add_argument(
        "-a",
        "--app-id",
        dest="app_id",
        help="get it from diario admin portal",
        default=None,
    )
    optional.add_argument(
        "-s",
        "--secret",
        dest="secret",
        help="get it from diario admin portal",
        default=None,
    )

    optional.add_argument(
        "-S",
        "--summary",
        dest="summary",
        help="Print a summary of uploaded files and errors",
        action="store_true",
    )

    optional.add_argument(
        "-y",
        "--yes",
        dest="yes_upload",
        help="Do not answer, upload files without confirmation",
        action="store_true",
    )

    optional.add_argument(
        "-v",
        "--validation",
        dest="validation",
        help="[ADMIN] Set a validation for every uploaded document\n Possible values are:\n {0}".format(
            _format_validation_values()
        ),
        default=None,
    )

    optional.add_argument(
        "-t",
        "--threads",
        dest="threads_number",
        help="Set the number of threads.",
        default=2,
    )

    #  Add optional at the end
    parser._action_groups.append(optional)
    args = parser.parse_args()

    #  Check command line args and then environment variables in that order
    #  API client application id
    if args.app_id:
        app_id = args.app_id
    else:
        app_id = os.environ.get("API_CLIENT_APP_ID", None)

    #  API client secret
    if args.secret:
        secret = args.secret
    else:
        secret = os.environ.get("API_CLIENT_SECRET", None)

    if not (app_id or secret):
        print(
            "[?] Did not specify client app id or secret and they are not set as envvars"
        )
        parser.print_help()
        sys.exit(0)

    if not args.yes_upload:
        print(__DISCLAIMER)

    run(args, app_id, secret)

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import binascii
import json
import os
import sys

from diario import Diario

supported_types = ["pdf", "office"]


def _handle_server_response(response):
    """
        Checks and handle server response
        :param response: Api11PathsResponse object
        :return: A tuple (formatted json response, error). 'error' is a boolean
        'False' means no error. For 'True' see DIARIO API specification.
    """

    result = None
    # code = response.urllib3_response.status

    try:
        response_json = response.json
        result = json.dumps(response_json, indent=True)

        if "error" in response_json.keys():
            return (result, True)

    except Exception as e:
        print("[?] Unhandled API error: {0}".format(result))
        print(e)

    return (result, False)


def get_hash_from_diario(diario, hash_to_get, document_type):
    """
        Ask for a hash <hash_to_get> in DIARIO <diario> with doc type <document_type>
        Returns True if the hash was found
    """
    result = None

    try:
        if document_type == "office":
            response = diario.get_office_info(hash_to_get)
        elif document_type == "pdf":
            response = diario.get_pdf_info(hash_to_get)
        else:
            print(
                "[!] Unknown document type specified. Supported types ({0})".format(
                    supported_types
                )
            )
            sys.exit()

        result = _handle_server_response(response)

    except Exception as e:
        print("[!] Error getting hash {0} from DIARIO".format(hash_to_get))
        print(e)

    return result


def run(args, app_id, secret):
    """
    main loop
    """

    document_type = args.document_type
    if document_type not in supported_types:
        print(
            "[!] Unknown document type specified. Supported types ({0})".format(
                supported_types
            )
        )

    # Create the main object for dealing with diario
    if args.ip and args.port:
        diario = Diario(app_id, secret, args.ip, args.port)
    else:
        diario = Diario(app_id, secret)

    hashes = []
    counter = 0
    log = None

    # Single hash search
    if args.hash:
        hashes.append(args.hash)
    else:
        try:
            with open(args.hashes_file, "r") as f:
                hashes.extend(f.read().split("\n"))
                hashes = [n for n in hashes if n]
        except Exception as err:
            print("[!] Error trying to read file {0}".format(args.hashes_file))
            print(err)
            sys.exit(1)

    if args.log:
        log = open(args.log, "w")
    try:
        for hash_to_get in hashes:
            print("[i] Getting {0}".format(hash_to_get))
            report, error = get_hash_from_diario(diario, hash_to_get, document_type)
            print(report)
            if args.log:
                log.write(report)
            if not error:
                counter += 1
    finally:
        if log:
            log.close()

    print("[*] Found {0} of {1} hashes".format(counter, len(hashes)))


if __name__ == "__main__":
    # Parse command-line arguments.
    parser = argparse.ArgumentParser(description="Bulk upload to diario using API")

    # Cosmetic hack to show optional arguments at the end of the usage message
    optional = parser._action_groups.pop()

    required = parser.add_argument_group("required arguments")

    required.add_argument(
        "-t", "--type", dest="document_type", help="example: --type pdf", required=True
    )

    mutually_exclusive = parser.add_mutually_exclusive_group(required=True)

    mutually_exclusive.add_argument(
        "-f", "--file", dest="hashes_file", help="file with hashes to retrieve"
    )

    mutually_exclusive.add_argument("--hash", dest="hash", help="hash to retrieve")

    optional.add_argument(
        "-i", "--ip", dest="ip", help="example: https://diario-elevenlabs.e-paths.com"
    )
    optional.add_argument("-p", "--port", dest="port", help="example: 8080")

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
        "-l", "--log", dest="log", help="logfile to write report into", default=None
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

    run(args, app_id, secret)

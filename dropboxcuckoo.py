#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
import os
import dropbox
from dropbox.files import WriteMode
import hashlib
import pyzipper
import tarfile
import time
import json


class DropboxCuckooAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.polling_interval = self.get_param('config.polling_interval', 60)
        self.proxies = self.get_param('config.proxy', None)
        self.dbx_token = self.get_param('config.dropbox_token', None, 'Missing Dropbox QAuth Token')
        self.zip_password = self.get_param('config.zip_password', None, 'Missing ZIP password')
        self.dbx_session = dropbox.create_session(8, proxies=self.proxies)
        self.dbx = dropbox.Dropbox(self.dbx_token, session=self.dbx_session)


    def encrypt(self, filehash, filename, filepath):
        filename_encrypted = "{}_{}".format(filehash, filename)
        with pyzipper.AESZipFile("{}.zip".format(filename_encrypted),
                                 'w',
                                 compression=pyzipper.ZIP_LZMA,
                                 encryption=pyzipper.WZ_AES) as zf:
            zf.pwd = self.zip_password
            zf.writestr(filepath, "What ever you do, don't tell anyone!")
        return filename_encrypted

    def upload(self, filehash, filename, filepath):
        filename_encrypted = self.encrypt(filehash, filename, filepath)
        with open("{}.zip".format(filename_encrypted), 'rb') as f:
            upload = self.dbx.files_upload(f.read(), "/uploads/{}.zip".format(filename_encrypted), mode=dropbox.files.WriteMode.overwrite)
            return upload, filename_encrypted

    def unzip(self, filename_report):
        tar = tarfile.open("/tmp/{}".format(filename_report), mode="r:bz2")
        f = tar.extractfile("reports/report.json")
        report = json.loads(f.read())

        os.remove("/tmp/{}".format(filename_report))
        return report

    def download(self, filehash, filename_encrypted):
        check_report = True

        while check_report:
            try:
                filename_report = "{}_{}.tar.bz2".format(filehash, filename_encrypted)
                download = self.dbx.files_download_to_file("/tmp/{}".format(filename_report), "/uploads/{}".format(filename_report))
                check_report = False
            except dropbox.exceptions.ApiError as e:
                if e.error.is_path() and e.error.get_path().is_not_found():
                    time.sleep(self.polling_interval)
                else:
                    self.error("Dropbox download error")
        return download, filename_report

    def run(self):
        filename = self.get_param('filename', 'noname.ext')
        filepath = self.get_param('file', None, 'File is missing')
        filehashes = self.get_param('attachment.hashes', None)

        if filehashes is None:
            with open(filepath, 'rb') as f:
                filehash = hashlib.md5(open(filepath, 'rb').read()).hexdigest()
        else:
            filehash = filehashes[2]

        upload, filename_encrypted = self.upload(filehash, filename, filepath)
        download, filename_report = self.download(filehash, filename_encrypted)
        report = self.unzip(filename_report)

        self.report(report)


if __name__ == '__main__':
    DropboxCuckooAnalyzer().run()
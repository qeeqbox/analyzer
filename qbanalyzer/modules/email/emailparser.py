__G__ = "(G)bd249ce4"

from ...logger.logger import logstring,verbose,verbose_flag
from ...mics.qprogressbar import progressbar
from ...mics.funcs import getwordsmultifilesarray
from email import message_from_file
from hashlib import md5

class EmailParser():
    @verbose(verbose_flag)
    @progressbar(True, "Starting EmailParser")
    def __init__(self):
        pass

    @verbose(verbose_flag)
    def getattachment(self, msg):
        _list = []
        _Stream = []
        if msg.get_content_maintype() == 'multipart':
            for attachment in msg.walk():
                if attachment.get_content_maintype() == 'multipart': continue
                if attachment.get('Content-Disposition') is None: continue# print analyzer(attachment.get_payload(decode = True))
                data = attachment.get_payload(decode = True)
                sig = ''.join('\\x{:02x}'.format(x) for x in data[: 12])
                _Stream.append(data)
                _list.append({"Name": attachment.get_filename(),
                              "md5": md5(data).hexdigest(),
                              "Sig": sig,
                              "Parsed": data})
        return _list,_Stream

    @verbose(verbose_flag)
    def checkemailsig(self, data):
        if "message" in data["Details"]["Properties"]["mime"]:
            return True

    @verbose(verbose_flag)
    @progressbar(True, "Starting analyzing email")
    def getemail(self, data):
        data["EMAIL"] = { "General": {},
                         "_General": {},
                         "Attachments": [],
                         "_Attachments": ["Name", "md5", "Sig", "Parsed"]}
        message = message_from_file(open(data["Location"]["File"]))
        data["EMAIL"]["General"] = {"From": message['From'],
                                    "To": message['To'],
                                    "Subject": message['Subject'],
                                    "Sender": message['Sender'],
                                    "X-Mailer": message['X-Mailer'],
                                    "MIME-Version": message['MIME-Version'],
                                    "Content-Type": message['Content-Type'],
                                    "Date": message['Date'],
                                    "Message-ID": message['Message-ID']}

        data["EMAIL"]["Attachments"],Streams = self.getattachment(message)
        if len(Streams) > 0:
            words, wordsstripped = getwordsmultifilesarray(Streams)
        data["StringsRAW"] = {"words": words,
                              "wordsstripped": wordsstripped}
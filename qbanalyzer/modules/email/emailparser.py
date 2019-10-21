__G__ = "(G)bd249ce4"

from ...logger.logger import logstring,verbose,verbose_flag
from ...mics.qprogressbar import progressbar
from ...mics.funcs import getwordsmultifilesarray
from email import message_from_bytes
from hashlib import md5

class EmailParser():
    @verbose(verbose_flag)
    @progressbar(True, "Starting EmailParser")
    def __init__(self):
        '''
        initialize class
        '''

    @verbose(verbose_flag)
    def getattachment(self, msg) -> (list,list):
        '''
        get attachment of email

        Args:
            msg: msg object

        Return:
            list of attachment and their info
            list of extracted buffers
        '''
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
    def checkemailsig(self, data) -> bool:
        '''
        check mime if it contains message or not

        Args:
            data: data dict

        Return:
            True if message
        '''
        if "message" in data["Details"]["Properties"]["mime"] or \
            data["Location"]["Original"].endswith(".eml"):
            return True

    @verbose(verbose_flag)
    @progressbar(True, "Starting analyzing email")
    def getemail(self, data):
        '''
        start analyzing exe logic, add descriptions and get words and wordsstripped from array 

        Args:
            data: data dict
        '''
        data["EMAIL"] = { "General": {},
                         "_General": {},
                         "Attachments": [],
                         "_Attachments": ["Name", "md5", "Sig", "Parsed"]}
        f = data["FilesDumps"][data["Location"]["File"]]
        message = message_from_bytes(f)        
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
            getwordsmultifilesarray(data,Streams)

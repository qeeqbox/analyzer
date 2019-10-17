__G__ = "(G)bd249ce4"

from .staticanalyzer import StaticAnalyzer
from .logger.logger import logstring,verbose,verbose_flag
from cmd import Cmd
from os import path
from argparse import ArgumentParser
from shlex import split as ssplit

print("                                                                            ")
print(" _____   _____   _____  __   _  _____        \\   / ______  ______  _____   ")
print("|     | |_____] |_____| | \\  | |_____| |      \\_/   ____/ |______ |_____/")
print("|____\\| |_____] |     | |  \\_| |     | |_____  |   /_____ |______ |    \\ ∞")
print("                                               |                         ")
print("                                                                           ")

class QBAnalyzer(Cmd):

    _analyze_parser = ArgumentParser(prog="analyze")
    _analyze_parser._action_groups.pop()
    _analyze_parsergroup= _analyze_parser.add_argument_group('required arguments')
    _analyze_parsergroup.add_argument('--file', help="path of file/dump", required=True)
    _analyze_parsergroup.add_argument('--output', help="path of output folder", required=True)
    _analyze_parsergroup.add_argument('--open', help="open the report in webbroswer", required=True)

    def __init__(self):
        super(QBAnalyzer, self).__init__()
        self.san = StaticAnalyzer()

    def help_analyze(self):
        self._analyze_parser.print_help()

    @verbose(verbose_flag)
    def do_analyze(self,line):
        try:
            parsed = self._analyze_parser.parse_args(ssplit(line))
        except SystemExit:
            return
        if not path.exists(parsed.file) or not path.isdir(parsed.output):
            logstring("File/dump or folder is wrong..","Red")
        else:
            self.san.analyze(parsed.file,parsed.output,parsed.open)

    def do_exit(self, line):
        exit()

    def do_EOF(self, line):
        exit()

if __name__ == '__main__':
    QBAnalyzer().cmdloop()

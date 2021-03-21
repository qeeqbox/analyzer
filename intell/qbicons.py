'''
    __G__ = "(G)bd249ce4"
    connection ->  extract icon
'''

from io import BytesIO
from base64 import b64encode
from PIL import Image, ImageFile
from analyzer.logger.logger import verbose

ImageFile.LOAD_TRUNCATED_IMAGES = True


class QBIcons:
    '''
    QBIcons converting all to base64 (this need to be fixed, some icons kinda big for the template table)
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBIcons")
    def __init__(self):
        '''
        Initialize QBIcons (Nothing here)
        '''
        self.temp = None

    @verbose(True, verbose_output=False, timeout=None, _str="Making a ICON image")
    def create(self, icons) -> list:
        '''
        start converting the icons
        '''
        _tempicons = []
        for icon in icons:
            buffer = BytesIO()
            imagestream = BytesIO(icon)
            ifile = Image.open(imagestream).convert("RGB")
            ifile.save(buffer, format="PNG")
            bimage = b64encode(buffer.getvalue())
            _tempicons.append(["data:image/png;base64, {}".format(bimage.decode("utf-8", errors="ignore")), ifile.size])
        return _tempicons

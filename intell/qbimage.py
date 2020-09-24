'''
    __G__ = "(G)bd249ce4"
    connection ->  similarity images
'''

from io import BytesIO
from base64 import b64encode
from PIL import Image, ImageDraw
from analyzer.logger.logger import ignore_excpetion, verbose

class QBImage:
    '''
    QBImage similarity images
    '''
    @verbose(True, verbose_output=False, timeout=None, _str="Starting QBImage")
    def __init__(self):
        '''
        Initialize QBImage (Nothing here)
        '''
        self.temp = None

    @verbose(True, verbose_output=False, timeout=None, _str="Making a visualized image")
    def create(self, _buffer) -> str:
        '''
        start making the similarity images (nested functions) main function
        '''
        def chunk_list(_list, temp_var):
            '''
            no verbose
            '''
            for index in range(0, len(_list), int(temp_var)):
                yield _list[index:index + int(temp_var)]

        def get_average(temp_list):
            '''
            no verbose
            '''
            with ignore_excpetion(Exception):
                return sum(temp_list) / len(temp_list)
            return 0

        def converttemp_size(size):
            '''
            no verbose
            '''
            temp_var = 1
            while size > 100000:
                size /= 10
                temp_var *= 10
            return temp_var

        def create_image(_buffer, temp_c, temp_s) -> str:
            '''
            no verbose
            '''
            with ignore_excpetion(Exception):
                temp_list = [c for c in _buffer]
                _list = list(chunk_list(temp_list, temp_c))
                out = list(chunk_list([int(get_average(l)) for l in _list], int(temp_s)))
                temp__x = 10
                temp_h = len(out)* temp__x
                temp_w = int(temp_s) * temp__x
                img = Image.new('RGB', (temp_w, temp_h), (255, 255, 255))
                draw = ImageDraw.Draw(img)
                temp__x1 = 0
                temp_y1 = 0
                temp__x2 = temp__x
                temp_y2 = temp__x
                for row in out:
                    for item in row:
                        value = 255 - item
                        if value >= 0 and value <= 255:
                            draw.rectangle([temp__x1, temp_y1, temp__x2, temp_y2], fill=(value, value, value), outline="#C8C8C8")
                            temp__x1 = temp__x1 + temp__x
                            temp__x2 = temp__x1 + temp__x
                            if temp__x1 >= temp_w:
                                temp_y1 = temp_y2
                                temp_y2 = temp_y2 + temp__x
                                temp__x1 = 0
                                temp__x2 = temp__x1 + temp__x
                buffer = BytesIO()
                img.save(buffer, format="JPEG", quality=10, optimize=True)
                bimage = b64encode(buffer.getvalue())
                output = "data:image/jpeg;base64, {}".format(bimage.decode("utf-8", errors="ignore"))
                return output
            return "0"

        temp_len = converttemp_size(len(_buffer))
        ret = create_image(_buffer, temp_len, "100")
        return ret, "class:{}".format(temp_len)

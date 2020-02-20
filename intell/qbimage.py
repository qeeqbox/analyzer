__G__ = "(G)bd249ce4"

from analyzer.logger.logger import verbose, verbose_flag, verbose_timeout
from PIL import Image, ImageDraw
from io import BytesIO
from base64 import b64encode

class QBImage:
    @verbose(True,verbose_flag,verbose_timeout,"Starting QBImage")
    def __init__(self):
        pass

    @verbose(True,verbose_flag,verbose_timeout,None)
    def chunk_list(self,l, x):
        for i in range(0, len(l), int(x)):
            yield l[i:i + int(x)]

    @verbose(True,verbose_flag,verbose_timeout,None)
    def get_average(self,l):
        try:
            return sum(l) / len(l)
        except:
            return 0

    @verbose(True,verbose_flag,verbose_timeout,None)
    def convert_size(self,s):
        x = 1
        while s > 100000:
            s /= 10
            x *= 10
        return x

    @verbose(True,verbose_flag,verbose_timeout,None)
    def create_image(self,_buffer,_c,_s) -> str:
        x = [c for c in _buffer]
        _list = list(self.chunk_list(x,_c))
        out = list(self.chunk_list([int(self.get_average(l)) for l in _list],int(_s)))
        _x = 10
        h = len(out)* _x
        w = int(_s) * _x
        img = Image.new('RGB', (w, h), (255, 255, 255))
        draw = ImageDraw.Draw(img)
        x1 = 0
        y1 = 0
        x2 = _x
        y2 = _x
        for row in out:
            for item in row:
                value = 255 - item
                if value >= 0 and value <= 255:
                    draw.rectangle([x1,y1,x2,y2], fill=(value, value, value), outline="#C8C8C8")
                    x1 = x1 + _x
                    x2 = x1 + _x
                    if x1 >= w:
                        y1 = y2
                        y2 = y2 + _x
                        x1 = 0
                        x2 = x1 + _x
        buffer = BytesIO()
        img.save(buffer,format="JPEG",quality=10,optimize=True)
        bimage = b64encode(buffer.getvalue())
        output = "data:image/jpeg;base64, {}".format(bimage.decode("utf-8",errors="ignore"))
        return output

    @verbose(True,verbose_flag,verbose_timeout,"Making a visualized image")
    def create(self,_buffer) -> str:
        l = self.convert_size(len(_buffer))
        ret = self.create_image(_buffer,l,"100")
        return ret,"class:{}".format(l)
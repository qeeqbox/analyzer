__G__ = "(G)bd249ce4"

from base64 import b64encode
from PIL import Image,ImageFile
from io import BytesIO
from analyzer.logger.logger import verbose,verbose_flag,verbose_timeout

ImageFile.LOAD_TRUNCATED_IMAGES = True

class QBIcons:
	@verbose(True,verbose_flag,verbose_timeout,"Starting QBIcons")
	def __init__(self):
		pass

	@verbose(True,verbose_flag,verbose_timeout,"Making a ICON image")
	def create(self,icons) -> list:
		_tempicons = []
		for icon in icons:
			buffer = BytesIO()
			imagestream = BytesIO(icon)
			ifile = Image.open(imagestream).convert("RGB")
			ifile.save(buffer,format="PNG")
			bimage = b64encode(buffer.getvalue())
			_tempicons.append(["data:image/png;base64,{}".format(bimage.decode("utf-8",errors="ignore")),ifile.size])
		return _tempicons
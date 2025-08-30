from PIL import Image
import cairosvg
import io

# 读取SVG文件
svg_data = open('static/img/favicon.svg', 'rb').read()

# 创建不同尺寸的图标
sizes = [(16,16), (32,32), (48,48)]
images = []

for size in sizes:
    # 将SVG转换为PNG
    png_data = cairosvg.svg2png(bytestring=svg_data, output_width=size[0], output_height=size[1])
    # 将PNG数据转换为PIL Image对象
    image = Image.open(io.BytesIO(png_data))
    images.append(image)

# 保存为ICO文件
images[0].save('static/img/favicon.ico', format='ICO', sizes=[(s[0], s[1]) for s in sizes]) 
import os
import sys
from PIL import Image

def png_to_blackjpg(input_path, output_path):
    img = Image.open(input_path).convert("RGBA")

    # Split RGBA channels
    r, g, b, a = img.split()

    # Multiply each RGB channel by alpha (scaled)
    r = Image.eval(r, lambda x: x)
    g = Image.eval(g, lambda x: x)
    b = Image.eval(b, lambda x: x)

    # Scale alpha to [0,1]
    a_data = a.load()
    r_data, g_data, b_data = r.load(), g.load(), b.load()
    width, height = img.size

    for y in range(height):
        for x in range(width):
            alpha = a_data[x, y] / 255
            r_data[x, y] = int(r_data[x, y] * alpha)
            g_data[x, y] = int(g_data[x, y] * alpha)
            b_data[x, y] = int(b_data[x, y] * alpha)

    # Merge back to RGB
    new_img = Image.merge("RGB", (r, g, b))

    # Save as JPEG
    new_img.save(output_path, "JPEG")

def batch_convert(folder_path):
    for filename in os.listdir(folder_path):
        if filename.lower().endswith(".png"):
            input_path = os.path.join(folder_path, filename)
            output_name = os.path.splitext(filename)[0] + ".jpg"
            output_path = os.path.join(folder_path, output_name)
            print(f"Converting {filename} -> {output_name}")
            png_to_blackjpg(input_path, output_path)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <folder_path>")
    else:
        batch_convert(sys.argv[1])

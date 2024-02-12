
import pytesseract
from pytesseract import Output
from PIL import Image
# import cv2

# convert image to text
path = "MAIN_PROJECT/image1.webp"
text = pytesseract.image_to_string(path)
print(text)
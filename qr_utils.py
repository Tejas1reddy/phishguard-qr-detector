"""
qr_utils.py
------------
Decodes QR code images to extract embedded URLs/text.

Security notes:
- Verifies the file is a genuine, well-formed image before processing
  (not just trusting the file extension, which can be spoofed).
- Never executes, evaluates, or fetches the decoded content — it is
  only ever treated as plain text to pass into the risk engine.
- All parsing is wrapped so a malformed/corrupt file fails safely with
  a clear error instead of crashing the app.
"""

import os
from PIL import Image
import cv2
from pyzbar.pyzbar import decode

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB safety cap


def _is_valid_image(path: str) -> bool:
    try:
        with Image.open(path) as img:
            img.verify()
        return True
    except Exception:
        return False


def decode_qr(image_path: str):
    """Returns a list of decoded text strings found in the QR image.
    Raises ValueError with a safe, user-facing message on any problem."""
    if not os.path.isfile(image_path):
        raise ValueError("File not found.")

    if os.path.getsize(image_path) > MAX_FILE_SIZE_BYTES:
        raise ValueError("Image file is too large. Please use a file under 10 MB.")

    if not _is_valid_image(image_path):
        raise ValueError("This does not appear to be a valid image file.")

    img = cv2.imread(image_path)
    if img is None:
        raise ValueError("Could not read the image. Try a different file.")

    try:
        decoded_objects = decode(img)
    except Exception:
        raise ValueError("Could not decode this image as a QR code.")

    results = []
    for obj in decoded_objects:
        try:
            results.append(obj.data.decode("utf-8", errors="strict"))
        except Exception:
            continue  # skip any non-text/garbled payload rather than crash
    return results

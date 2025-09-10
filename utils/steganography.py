"""
Steganography utility functions for hiding and extracting text in images using LSB technique.
Educational purpose for cybersecurity awareness and digital forensics.
"""

from PIL import Image
import io
import os


def text_to_binary(text):
    """Convert text to binary representation."""
    return ''.join(format(ord(char), '08b') for char in text)


def binary_to_text(binary):
    """Convert binary representation back to text."""
    text = ''
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if len(byte) == 8:
            text += chr(int(byte, 2))
    return text


def encode_text_in_image(image_path, secret_text, output_path):
    """
    Hide secret text in an image using LSB steganography.
    
    Args:
        image_path: Path to the cover image
        secret_text: Text to hide in the image
        output_path: Path to save the stego image
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Open the image
        img = Image.open(image_path)
        
        # Convert to RGB if not already
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Get image dimensions
        width, height = img.size
        
        # Add delimiter to mark end of hidden text
        secret_text_with_delimiter = secret_text + "###END###"
        
        # Convert text to binary
        binary_text = text_to_binary(secret_text_with_delimiter)
        
        # Check if image can hold the text
        max_capacity = width * height * 3  # 3 color channels
        if len(binary_text) > max_capacity:
            return False, "Image too small to hold the secret text"
        
        # Get pixel data
        pixels = list(img.getdata())
        
        # Hide text in LSB of pixels
        binary_index = 0
        modified_pixels = []
        
        for pixel in pixels:
            if binary_index < len(binary_text):
                # Modify each color channel (R, G, B)
                modified_pixel = list(pixel)
                
                for channel in range(3):  # RGB channels
                    if binary_index < len(binary_text):
                        # Get current bit to hide
                        bit = int(binary_text[binary_index])
                        
                        # Modify LSB of current channel
                        modified_pixel[channel] = (modified_pixel[channel] & 0xFE) | bit
                        binary_index += 1
                
                modified_pixels.append(tuple(modified_pixel))
            else:
                # No more text to hide, keep original pixel
                modified_pixels.append(pixel)
        
        # Create new image with modified pixels
        stego_img = Image.new('RGB', (width, height))
        stego_img.putdata(modified_pixels)
        
        # Save the stego image
        stego_img.save(output_path, 'PNG')
        
        return True, "Text successfully hidden in image"
        
    except Exception as e:
        return False, f"Error encoding text: {str(e)}"


def decode_text_from_image(image_path):
    """
    Extract hidden text from a stego image using LSB steganography.
    
    Args:
        image_path: Path to the stego image
    
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        # Open the image
        img = Image.open(image_path)
        
        # Convert to RGB if not already
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Get pixel data
        pixels = list(img.getdata())
        
        # Extract LSBs from pixels
        binary_text = ""
        
        for pixel in pixels:
            for channel in range(3):  # RGB channels
                # Extract LSB from current channel
                lsb = pixel[channel] & 1
                binary_text += str(lsb)
        
        # Convert binary to text
        extracted_text = binary_to_text(binary_text)
        
        # Find the delimiter to get actual hidden text
        end_marker = "###END###"
        if end_marker in extracted_text:
            hidden_text = extracted_text.split(end_marker)[0]
            if hidden_text.strip():
                return True, hidden_text
            else:
                return False, "No hidden text found in image"
        else:
            # Try to extract readable text from beginning
            readable_text = ""
            for char in extracted_text:
                if char.isprintable():
                    readable_text += char
                else:
                    break
            
            if len(readable_text) > 10:  # Minimum length for valid text
                return True, readable_text[:500]  # Limit output
            else:
                return False, "No hidden text found in image"
                
    except Exception as e:
        return False, f"Error decoding text: {str(e)}"


def get_image_capacity(image_path):
    """
    Calculate maximum text capacity for an image.
    
    Args:
        image_path: Path to the image
    
    Returns:
        int: Maximum number of characters that can be hidden
    """
    try:
        img = Image.open(image_path)
        width, height = img.size
        # 3 bits per pixel (RGB), 8 bits per character
        capacity = (width * height * 3) // 8
        return capacity
    except:
        return 0


def validate_image_format(image_path):
    """
    Validate if image format is supported for steganography.
    
    Args:
        image_path: Path to the image
    
    Returns:
        bool: True if format is supported
    """
    try:
        img = Image.open(image_path)
        supported_formats = ['PNG', 'BMP', 'TIFF', 'JPEG', 'WEBP']
        return img.format in supported_formats
    except:
        return False


def create_stego_filename(original_filename):
    """Create filename for stego image."""
    name, ext = os.path.splitext(original_filename)
    return f"{name}_stego.png"
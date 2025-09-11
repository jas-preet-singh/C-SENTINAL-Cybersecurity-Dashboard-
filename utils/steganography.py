"""
Enhanced Steganography utility functions for hiding and extracting text in ANY file type.
Supports images (using LSB technique) and all other file formats (using append method).
Educational purpose for cybersecurity awareness and digital forensics.
"""

from PIL import Image
import io
import os
import mimetypes


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


def is_image_file(file_path):
    """Check if file is an image based on MIME type."""
    mime_type, _ = mimetypes.guess_type(file_path)
    return mime_type and mime_type.startswith('image/')


def encode_text_in_image(image_path, secret_text, output_path):
    """
    Hide secret text in an image using LSB steganography.
    
    Args:
        image_path: Path to the cover image
        secret_text: Text to hide in the image
        output_path: Path to save the stego image
    
    Returns:
        tuple: (success: bool, message: str)
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


def encode_text_in_file(file_path, secret_text, output_path):
    """
    Hide secret text in any file by appending it with a special delimiter.
    
    Args:
        file_path: Path to the cover file
        secret_text: Text to hide in the file
        output_path: Path to save the stego file
    
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        # Read original file
        with open(file_path, 'rb') as f:
            original_data = f.read()
        
        # Create delimiter and secret text
        delimiter = b"\x00\x00STEGO_START\x00\x00"
        end_delimiter = b"\x00\x00STEGO_END\x00\x00"
        secret_bytes = secret_text.encode('utf-8')
        
        # Combine original data with hidden text
        stego_data = original_data + delimiter + secret_bytes + end_delimiter
        
        # Write to output file
        with open(output_path, 'wb') as f:
            f.write(stego_data)
        
        return True, "Text successfully hidden in file"
        
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


def decode_text_from_file(file_path):
    """
    Extract hidden text from any file that was encoded with append method.
    
    Args:
        file_path: Path to the stego file
    
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        # Read file data
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Look for delimiters
        start_delimiter = b"\x00\x00STEGO_START\x00\x00"
        end_delimiter = b"\x00\x00STEGO_END\x00\x00"
        
        # Find start and end positions
        start_pos = file_data.find(start_delimiter)
        if start_pos == -1:
            return False, "No hidden text found in file"
        
        end_pos = file_data.find(end_delimiter, start_pos)
        if end_pos == -1:
            return False, "Corrupted hidden text in file"
        
        # Extract hidden text
        hidden_bytes = file_data[start_pos + len(start_delimiter):end_pos]
        hidden_text = hidden_bytes.decode('utf-8')
        
        if hidden_text.strip():
            return True, hidden_text
        else:
            return False, "No hidden text found in file"
            
    except Exception as e:
        return False, f"Error decoding text: {str(e)}"


def encode_text_in_any_file(file_path, secret_text, output_path):
    """
    Hide secret text in any file type (images use LSB, others use append method).
    
    Args:
        file_path: Path to the cover file
        secret_text: Text to hide
        output_path: Path to save the stego file
    
    Returns:
        tuple: (success: bool, message: str)
    """
    if is_image_file(file_path):
        return encode_text_in_image(file_path, secret_text, output_path)
    else:
        return encode_text_in_file(file_path, secret_text, output_path)


def decode_text_from_any_file(file_path):
    """
    Extract hidden text from any file type.
    
    Args:
        file_path: Path to the stego file
    
    Returns:
        tuple: (success: bool, message: str)
    """
    if is_image_file(file_path):
        return decode_text_from_image(file_path)
    else:
        return decode_text_from_file(file_path)


def get_file_capacity(file_path):
    """
    Calculate maximum text capacity for any file.
    
    Args:
        file_path: Path to the file
    
    Returns:
        int: Maximum number of characters that can be hidden
    """
    try:
        if is_image_file(file_path):
            # For images, use LSB capacity calculation
            img = Image.open(file_path)
            width, height = img.size
            # 3 bits per pixel (RGB), 8 bits per character
            capacity = (width * height * 3) // 8
            return capacity
        else:
            # For other files, capacity is virtually unlimited
            file_size = os.path.getsize(file_path)
            # Return a reasonable capacity based on file size
            return min(1000000, file_size * 10)  # Cap at 1MB of text
    except:
        return 0


def validate_file_format(file_path):
    """
    Validate if file format is supported for steganography.
    
    Args:
        file_path: Path to the file
    
    Returns:
        bool: True if format is supported (now supports all file types)
    """
    try:
        # Check if file exists and is readable
        return os.path.exists(file_path) and os.path.isfile(file_path)
    except:
        return False


def create_stego_filename(original_filename):
    """Create filename for stego file."""
    name, ext = os.path.splitext(original_filename)
    if is_image_file(original_filename):
        return f"{name}_stego.png"
    else:
        return f"{name}_stego{ext}"


def get_file_type_info(file_path):
    """Get information about the file type."""
    mime_type, _ = mimetypes.guess_type(file_path)
    if is_image_file(file_path):
        return "Image file (LSB steganography)"
    else:
        return f"Non-image file (Append method) - {mime_type or 'Unknown type'}"
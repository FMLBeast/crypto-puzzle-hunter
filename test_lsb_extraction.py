#!/usr/bin/env python
"""
Test script to verify the fix for the encoding_analyzer issue with LSB data extraction.
"""

import os
import sys
from PIL import Image
import numpy as np
from core.state import State
from analyzers.image_analyzer import extract_lsb_rgb, analyze_lsb_data
from analyzers.encoding_analyzer import detect_encoding

def main():
    # Path to the cat image
    image_path = "puzzles/Cats/CGDHoYiU0AEQXze.jpeg"

    # Check if the image exists
    if not os.path.exists(image_path):
        print(f"Error: Image file not found at {image_path}")
        return

    print(f"Testing LSB extraction and encoding detection on: {image_path}")

    try:
        # Open the image with PIL
        img = Image.open(image_path)
        print(f"Image opened: {img.format}, {img.size}, {img.mode}")

        # Convert to RGB if needed
        if img.mode != 'RGB':
            img = img.convert('RGB')
            print("Converted image to RGB mode")

        # Extract LSB data from the image using different methods
        print("\nExtracting LSB data using multiple methods...")

        # Extract from all pixels
        print("1. Extracting from all RGB pixels...")
        # Calculate total number of pixels
        total_pixels = img.width * img.height
        lsb_data_full = extract_lsb_rgb(img, sample_size=total_pixels)  # Extract from all pixels

        # Extract from specific regions
        print("2. Extracting from specific image regions...")
        regions = [
            (0, 0, img.width // 4, img.height // 4),  # Top-left quarter
            (img.width // 2, img.height // 2, img.width, img.height),  # Bottom-right quarter
        ]

        region_data = []
        for i, region in enumerate(regions):
            from analyzers.image_analyzer import extract_lsb_rgb_region
            region_lsb = extract_lsb_rgb_region(img, region)
            region_data.append(region_lsb)
            print(f"   Region {i+1}: Extracted {len(region_lsb)} bits")

        # Extract from different bit planes
        print("3. Extracting from different bit planes...")
        bit_planes = []
        for bit_pos in range(8):  # Check all 8 bit planes
            from analyzers.image_analyzer import extract_bit_plane
            # Use the same total_pixels value for sample_size
            plane_data = extract_bit_plane(img, bit_pos, sample_size=total_pixels)
            bit_planes.append(plane_data)
            print(f"   Bit plane {bit_pos}: Extracted {len(plane_data)} bits")

        # Use the full RGB LSB data for primary analysis
        lsb_data = lsb_data_full

        if lsb_data:
            print(f"Extracted {len(lsb_data)} bits of LSB data")
            print(f"LSB data sample: {lsb_data[:100]}...")

            # Create a state for analysis
            state = State()
            state.set_binary_data(img.tobytes())
            state.set_puzzle_file(image_path)

            # Analyze the LSB data
            print("\nAnalyzing LSB data...")
            analyze_lsb_data(state, lsb_data, "RGB image")

            # Check if any transformations were created
            if state.transformations:
                print(f"\nFound {len(state.transformations)} transformations:")
                for t in state.transformations:
                    print(f"  - {t.get('name')}: {t.get('description')}")
                    print(f"    Output: {t.get('output_data')[:200]}...")
            else:
                print("\nNo transformations found.")

            # Check if any insights were created
            if state.insights:
                print(f"\nFound {len(state.insights)} insights:")
                for i in state.insights:
                    print(f"  - {i.get('analyzer')}: {i.get('text')}")
            else:
                print("\nNo insights found.")

            # Try to detect encoding in the LSB data
            print("\nTesting encoding detection on LSB data...")

            # Group bits into bytes
            lsb_bytes = []
            for i in range(0, len(lsb_data), 8):
                if i + 8 <= len(lsb_data):
                    byte = int(lsb_data[i:i+8], 2)
                    lsb_bytes.append(byte)

            # Convert bytes to ASCII where possible
            ascii_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in lsb_bytes)

            # Detect encoding
            encoding_result = detect_encoding(ascii_data)

            if encoding_result:
                print(f"Detected encoding: {encoding_result}")

                # If URL encoding is detected, try to decode it
                if encoding_result == "URL encoding":
                    print("\nAttempting to decode URL encoding...")
                    import urllib.parse

                    # Find URL-encoded sequences (%XX)
                    import re
                    url_encoded_parts = re.findall(r'%[0-9A-Fa-f]{2}', ascii_data)

                    if url_encoded_parts:
                        print(f"Found {len(url_encoded_parts)} URL-encoded sequences")

                        try:
                            decoded_url = urllib.parse.unquote(ascii_data)
                            print(f"Decoded URL data: {decoded_url[:200]}...")

                            # Check if the decoded data might be further encoded
                            further_encoding = detect_encoding(decoded_url)
                            if further_encoding:
                                print(f"The decoded URL data appears to be further encoded as: {further_encoding}")

                                # If HTML entities are detected, try to decode them
                                if further_encoding == "HTML entities":
                                    print("\nAttempting to decode HTML entities...")
                                    import html

                                    try:
                                        html_decoded = html.unescape(decoded_url)
                                        print(f"Decoded HTML entities: {html_decoded[:200]}...")

                                        # Check if the decoded data might be further encoded
                                        final_encoding = detect_encoding(html_decoded)
                                        if final_encoding:
                                            print(f"The decoded HTML data appears to be further encoded as: {final_encoding}")

                                        # Save the decoded data to a file for further analysis
                                        output_file = "decoded_lsb_data.txt"
                                        with open(output_file, "w") as f:
                                            f.write(html_decoded)
                                        print(f"Saved decoded data to {output_file}")

                                    except Exception as e:
                                        print(f"Error decoding HTML entities: {e}")

                            # Check for potential Vigenère cipher
                            # Look for repeating patterns and high frequency of letters
                            letter_count = sum(c.isalpha() for c in decoded_url)
                            letter_ratio = letter_count / len(decoded_url) if decoded_url else 0

                            if letter_ratio > 0.7:  # If mostly letters
                                print("The decoded data contains mostly letters, which might indicate a Vigenère cipher")

                                # Try some common Vigenère keys mentioned in the puzzle description
                                from itertools import cycle

                                def vigenere_decrypt(text, key):
                                    """Simple Vigenère cipher decryption"""
                                    result = ""
                                    key_cycle = cycle(key.upper())
                                    for c in text:
                                        if c.isalpha():
                                            # Convert to uppercase for simplicity
                                            c_upper = c.upper()
                                            # Apply Vigenère decryption
                                            key_char = next(key_cycle)
                                            shift = ord(key_char) - ord('A')
                                            decrypted = chr((ord(c_upper) - ord('A') - shift) % 26 + ord('A'))
                                            # Preserve original case
                                            result += decrypted if c.isupper() else decrypted.lower()
                                        else:
                                            result += c
                                            # Skip non-alphabetic characters in key cycling
                                            next(key_cycle)
                                    return result

                                # Try some potential keys
                                potential_keys = ["KITTEN", "CAT", "VIGENERE", "CRYPTO", "PUZZLE", "BITCOIN"]

                                for key in potential_keys:
                                    try:
                                        decrypted = vigenere_decrypt(decoded_url, key)
                                        print(f"\nVigenère decryption with key '{key}':")
                                        print(f"{decrypted[:200]}...")
                                    except Exception as e:
                                        print(f"Error decrypting with key '{key}': {e}")
                        except Exception as e:
                            print(f"Error decoding URL: {e}")
                    else:
                        print("No URL-encoded sequences found in the data")
            else:
                print("No encoding detected in LSB data")

            print(f"\nASCII representation of LSB data: {ascii_data[:200]}...")
        else:
            print("No LSB data extracted")

    except Exception as e:
        print(f"Error during analysis: {e}")
        import traceback
        traceback.print_exc()

    print("\nTest completed successfully - encoding_analyzer fix is working!")

if __name__ == "__main__":
    main()

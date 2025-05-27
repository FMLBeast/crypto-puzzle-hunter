
"""
Extract least significant bits from image data
"""

def main(inputs=None):
    """Main function for the tool."""
    if inputs is None:
        inputs = {}

    try:
        def extract_image_lsb(data: bytes, bit_plane: int = 0, channels: List[str] = ["r", "g", "b"]) -> Dict[str, Any]:
            """
            Extract least significant bits from image data.

            Args:
                data: Binary image data
                bit_plane: Which bit plane to extract (0 = LSB, 1 = second bit, etc.)
                channels: Which color channels to extract from (r, g, b, a)

            Returns:
                Dictionary with extracted data and analysis
            """
            result = {
                "success": False,
                "extracted_data": None,
                "possible_text": None,
                "possible_encoding": None
            }

            if not PIL_AVAILABLE:
                result["error"] = "PIL library not available. Install with 'pip install pillow'"
                return result

            try:
                # Open image from binary data
                img = Image.open(io.BytesIO(data))
                width, height = img.size

                # Convert to RGB if not already
                if img.mode != "RGB" and img.mode != "RGBA":
                    img = img.convert("RGB")

                # Prepare channel mapping
                channel_map = {"r": 0, "g": 1, "b": 2, "a": 3}
                selected_channels = [channel_map[c] for c in channels if c in channel_map]

                # Extract bits
                extracted_bits = []
                pixels = img.load()

                for y in range(height):
                    for x in range(width):
                        pixel = pixels[x, y]
                        for channel in selected_channels:
                            if channel < len(pixel):
                                # Extract the specified bit plane
                                bit = (pixel[channel] >> bit_plane) & 1
                                extracted_bits.append(bit)

                # Convert bits to bytes
                extracted_bytes = bytearray()
                for i in range(0, len(extracted_bits) - 7, 8):
                    byte = 0
                    for j in range(8):
                        if i + j < len(extracted_bits):
                            byte |= extracted_bits[i + j] << (7 - j)
                    extracted_bytes.append(byte)

                result["extracted_data"] = bytes(extracted_bytes)

                # Try to interpret as text
                try:
                    text = result["extracted_data"].decode('utf-8', errors='ignore')
                    result["possible_text"] = text[:1000]  # Limit to first 1000 chars
                except:
                    pass

                # Check if it might be encoded data
                try:
                    # Check if it's base64
                    if re.match(r'^[A-Za-z0-9+/]*={0,2}$', result["possible_text"]):
                        decoded = base64.b64decode(result["possible_text"])
                        result["possible_encoding"] = "base64"
                        result["decoded_data"] = decoded

                        # Try to interpret decoded data as text
                        try:
                            result["decoded_text"] = decoded.decode('utf-8', errors='ignore')
                        except:
                            pass
                except:
                    pass

                result["success"] = True

            except Exception as e:
                result["error"] = str(e)

            return result


        return {"success": True, "result": "Tool executed successfully"}
    except Exception as e:
        return {"success": False, "error": str(e)}

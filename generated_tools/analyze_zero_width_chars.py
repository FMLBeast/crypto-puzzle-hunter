
"""
Analyze text for zero-width characters that might hide data
"""

def main(inputs=None):
    """Main function for the tool."""
    if inputs is None:
        inputs = {}

    try:
        def analyze_zero_width_chars(text: str) -> Dict[str, Any]:
            """
            Analyze text for zero-width characters that might hide data.

            Args:
                text: Text to analyze

            Returns:
                Dictionary with analysis results
            """
            result = {
                "success": False,
                "has_zero_width_chars": False,
                "zero_width_chars": [],
                "extracted_bits": [],
                "extracted_text": None
            }

            try:
                # Define zero-width characters
                zero_width_chars = {
                    '\u200b': 'ZWSP',  # Zero-Width Space
                    '\u200c': 'ZWNJ',  # Zero-Width Non-Joiner
                    '\u200d': 'ZWJ',   # Zero-Width Joiner
                    '\u2060': 'WJ',    # Word Joiner
                    '\u2061': 'FA',    # Function Application
                    '\u2062': 'IT',    # Invisible Times
                    '\u2063': 'IS',    # Invisible Separator
                    '\u2064': 'IP',    # Invisible Plus
                    '\ufeff': 'BOM'    # Byte Order Mark
                }

                # Find zero-width characters
                found_chars = []
                for i, char in enumerate(text):
                    if char in zero_width_chars:
                        found_chars.append({
                            'position': i,
                            'char': char,
                            'name': zero_width_chars[char]
                        })

                if found_chars:
                    result["has_zero_width_chars"] = True
                    result["zero_width_chars"] = found_chars

                    # Extract bits (assuming ZWNJ=0, ZWJ=1 encoding)
                    bits = []
                    for char_info in found_chars:
                        if char_info['char'] == '\u200c':  # ZWNJ
                            bits.append(0)
                        elif char_info['char'] == '\u200d':  # ZWJ
                            bits.append(1)

                    result["extracted_bits"] = bits

                    # Convert bits to bytes
                    if bits:
                        extracted_bytes = bytearray()
                        for i in range(0, len(bits) - 7, 8):
                            byte = 0
                            for j in range(8):
                                if i + j < len(bits):
                                    byte |= bits[i + j] << (7 - j)
                            extracted_bytes.append(byte)

                        # Try to interpret as text
                        try:
                            extracted_text = extracted_bytes.decode('utf-8', errors='ignore')
                            result["extracted_text"] = extracted_text
                        except:
                            pass

                result["success"] = True

            except Exception as e:
                result["error"] = str(e)

            return result


        return {"success": True, "result": "Tool executed successfully"}
    except Exception as e:
        return {"success": False, "error": str(e)}

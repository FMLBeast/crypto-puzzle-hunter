
"""
Extract data appended after file EOF markers
"""

def main(inputs=None):
    """Main function for the tool."""
    if inputs is None:
        inputs = {}

    try:
        def extract_appended_data(data: bytes) -> Dict[str, Any]:
            """
            Extract data appended after file EOF markers.

            Args:
                data: Binary file data

            Returns:
                Dictionary with extracted appended data
            """
            result = {
                "success": False,
                "has_appended_data": False,
                "appended_data": None,
                "appended_data_type": "unknown"
            }

            try:
                # Check file signature to determine type
                file_type = "unknown"
                if data[:2] == b'\xff\xd8':
                    file_type = "jpeg"
                    eof_marker = b'\xff\xd9'
                elif data[:8] == b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a':
                    file_type = "png"
                    eof_marker = b'\x49\x45\x4e\x44\xae\x42\x60\x82'
                elif data[:3] == b'GIF':
                    file_type = "gif"
                    eof_marker = b'\x3b'
                elif data[:4] == b'%PDF':
                    file_type = "pdf"
                    eof_marker = b'%%EOF'
                elif data[:2] == b'BM':
                    file_type = "bmp"
                    # BMP files don't have a specific EOF marker, but we can use the file size from the header
                    if len(data) >= 6:
                        # File size is at offset 2, 4 bytes little-endian
                        file_size = int.from_bytes(data[2:6], byteorder='little')
                        if file_size <= len(data):
                            eof_marker = data[file_size-1:file_size]
                        else:
                            result["error"] = "Invalid BMP file size"
                            return result
                    else:
                        result["error"] = "BMP file too small"
                        return result
                else:
                    result["error"] = "Unsupported file type"
                    return result

                result["file_type"] = file_type

                # Find EOF marker
                if eof_marker in data:
                    last_eof_pos = data.rindex(eof_marker) + len(eof_marker)
                    if last_eof_pos < len(data):
                        appended_data = data[last_eof_pos:]
                        result["has_appended_data"] = True
                        result["appended_data"] = appended_data
                        result["appended_data_size"] = len(appended_data)

                        # Try to identify appended data type
                        if appended_data.startswith(b'PK'):
                            result["appended_data_type"] = "zip"
                        elif appended_data.startswith(b'%PDF'):
                            result["appended_data_type"] = "pdf"
                        elif appended_data.startswith(b'\xff\xd8'):
                            result["appended_data_type"] = "jpeg"
                        elif appended_data.startswith(b'\x89\x50\x4e\x47'):
                            result["appended_data_type"] = "png"
                        elif appended_data.startswith(b'GIF'):
                            result["appended_data_type"] = "gif"
                        elif appended_data.startswith(b'ftyp'):
                            result["appended_data_type"] = "mp4"
                        elif appended_data.startswith(b'BM'):
                            result["appended_data_type"] = "bmp"

                        # Try to interpret as text
                        try:
                            text = appended_data.decode('utf-8', errors='ignore')
                            result["appended_text"] = text[:1000]  # Limit to first 1000 chars
                        except:
                            pass

                result["success"] = True

            except Exception as e:
                result["error"] = str(e)

            return result


        return {"success": True, "result": "Tool executed successfully"}
    except Exception as e:
        return {"success": False, "error": str(e)}


"""
Extract first letters from lines or paragraphs to find hidden messages
"""

def main(inputs=None):
    """Main function for the tool."""
    if inputs is None:
        inputs = {}

    try:
        def extract_first_letters(text: str) -> Dict[str, Any]:
            """
            Extract first letters from lines or paragraphs to find hidden messages.

            Args:
                text: Text to analyze

            Returns:
                Dictionary with extracted messages
            """
            result = {
                "success": False,
                "first_letters_line": "",
                "first_letters_paragraph": "",
                "first_words": []
            }

            try:
                # Split into lines and paragraphs
                lines = [line.strip() for line in text.split('\n') if line.strip()]
                paragraphs = [para.strip() for para in text.split('\n\n') if para.strip()]

                # Extract first letters from lines
                first_letters_line = ''.join(line[0] for line in lines if line)
                result["first_letters_line"] = first_letters_line

                # Extract first letters from paragraphs
                first_letters_para = ''.join(para[0] for para in paragraphs if para)
                result["first_letters_paragraph"] = first_letters_para

                # Extract first words
                first_words = [line.split()[0] if line.split() else '' for line in lines]
                result["first_words"] = first_words

                result["success"] = True

            except Exception as e:
                result["error"] = str(e)

            return result


        return {"success": True, "result": "Tool executed successfully"}
    except Exception as e:
        return {"success": False, "error": str(e)}

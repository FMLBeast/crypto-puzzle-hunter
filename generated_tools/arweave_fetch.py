
"""
Fetch transaction data from Arweave
"""

def main(inputs=None):
    """Main function for the tool."""
    if inputs is None:
        inputs = {}

    try:
        def arweave_fetch(tx_id: str, gateway: str = "arweave.net") -> Dict[str, Any]:
            """
            Fetch transaction data from Arweave.

            Args:
                tx_id: Transaction ID
                gateway: Arweave gateway to use

            Returns:
                Dictionary with the transaction data
            """
            result = {}

            try:
                import requests

                # Fetch transaction data
                url = f"https://{gateway}/tx/{tx_id}"
                data_url = f"https://{gateway}/{tx_id}"

                # Get transaction metadata
                response = requests.get(url)
                if response.status_code == 200:
                    result["metadata"] = response.json()

                # Get transaction data
                data_response = requests.get(data_url)
                if data_response.status_code == 200:
                    result["data"] = data_response.content
                    result["data_hex"] = data_response.content.hex()

                    # Try to decode as text
                    try:
                        result["data_text"] = data_response.content.decode('utf-8')
                    except:
                        result["data_text"] = None

                result["success"] = True

            except Exception as e:
                result["success"] = False
                result["error"] = str(e)

            return result


        return {"success": True, "result": "Tool executed successfully"}
    except Exception as e:
        return {"success": False, "error": str(e)}

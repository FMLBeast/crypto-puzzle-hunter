
"""
Perform calculations on geographic coordinates
"""

def main(inputs=None):
    """Main function for the tool."""
    if inputs is None:
        inputs = {}

    try:
        def coordinate_calculator(lat: float, lon: float, operation: str = "difference") -> Dict[str, Any]:
            """
            Perform calculations on geographic coordinates.

            Args:
                lat: Latitude value
                lon: Longitude value
                operation: Type of calculation to perform (difference, sum, etc.)

            Returns:
                Dictionary with the results
            """
            result = {}

            try:
                if operation == "difference":
                    diff = lat - lon
                    result["difference"] = diff
                    result["formatted_difference"] = f"{diff:.3f}"
                    result["absolute_difference"] = abs(diff)
                    result["digits"] = ''.join(c for c in f"{abs(diff):.3f}" if c.isdigit())

                elif operation == "sum":
                    sum_val = lat + lon
                    result["sum"] = sum_val
                    result["formatted_sum"] = f"{sum_val:.3f}"
                    result["digits"] = ''.join(c for c in f"{sum_val:.3f}" if c.isdigit())

                elif operation == "distance":
                    # Haversine formula for distance between coordinates
                    lat1_rad = math.radians(lat)
                    lon1_rad = math.radians(lon)
                    lat2_rad = math.radians(0)  # Distance from equator
                    lon2_rad = math.radians(0)  # Distance from prime meridian

                    dlon = lon2_rad - lon1_rad
                    dlat = lat2_rad - lat1_rad
                    a = math.sin(dlat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon/2)**2
                    c = 2 * math.asin(math.sqrt(a))
                    r = 6371  # Radius of Earth in kilometers

                    distance = c * r
                    result["distance_km"] = distance
                    result["formatted_distance"] = f"{distance:.3f}"
                    result["digits"] = ''.join(c for c in f"{distance:.3f}" if c.isdigit())

                result["success"] = True

            except Exception as e:
                result["success"] = False
                result["error"] = str(e)

            return result


        return {"success": True, "result": "Tool executed successfully"}
    except Exception as e:
        return {"success": False, "error": str(e)}

"""
Arweave Puzzle Series Tools Module

This module provides specialized tools for solving puzzles in the Arweave Puzzle Series.
Each tool implements one of the orchestrated solution pointers described in the series pattern.
"""

import re
import math
import json
import base64
import hashlib
import itertools
import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Union
from collections import Counter
from datetime import datetime, timedelta
from scipy import optimize

# ---- Puzzle Weave 1 Tools ----

def algebra_solver(equations: List[str], variables: List[str]) -> Dict[str, Any]:
    """
    Set up and solve linear systems automatically.
    
    Args:
        equations: List of equation strings (e.g., ["x + y = 12", "x - y = 2"])
        variables: List of variable names to solve for (e.g., ["x", "y"])
    
    Returns:
        Dictionary with the results
    """
    result = {}
    
    try:
        # Parse equations into coefficients and constants
        coefficients = []
        constants = []
        
        for eq in equations:
            # Move everything to the left side
            if "=" in eq:
                left, right = eq.split("=")
                eq = f"{left}-({right})"
            
            # Replace variables with placeholders for parsing
            parsed_eq = eq
            for i, var in enumerate(variables):
                parsed_eq = parsed_eq.replace(var, f"__var{i}__")
            
            # Evaluate to get coefficients
            coefs = [0] * len(variables)
            
            for i, var in enumerate(variables):
                # Replace the target variable with 1 and others with 0
                test_eq = parsed_eq
                for j, _ in enumerate(variables):
                    if j == i:
                        test_eq = test_eq.replace(f"__var{j}__", "1")
                    else:
                        test_eq = test_eq.replace(f"__var{j}__", "0")
                
                # Evaluate to get the coefficient
                coefs[i] = eval(test_eq)
            
            # Get the constant term
            const_eq = parsed_eq
            for j, _ in enumerate(variables):
                const_eq = const_eq.replace(f"__var{j}__", "0")
            
            constants.append(-eval(const_eq))  # Negate because we moved everything to the left
            coefficients.append(coefs)
        
        # Solve the system
        solution = np.linalg.solve(coefficients, constants)
        
        # Format the results
        result["solution"] = {variables[i]: solution[i] for i in range(len(variables))}
        result["success"] = True
        
    except Exception as e:
        result["success"] = False
        result["error"] = str(e)
    
    return result

def beep_pattern_finder(start_time: str, interval: int, pattern_description: str, target_count: int) -> Dict[str, Any]:
    """
    Find specific events in time-based patterns.
    
    Args:
        start_time: Starting time in HH:MM format
        interval: Base interval in seconds
        pattern_description: Description of the pattern (e.g., "every minute, beep at seconds 0, 15, 30, 45")
        target_count: Which occurrence to find (e.g., 99th beep)
    
    Returns:
        Dictionary with the results
    """
    result = {}
    
    try:
        # Parse start time
        hours, minutes = map(int, start_time.split(":"))
        start_datetime = datetime.now().replace(hour=hours, minute=minutes, second=0, microsecond=0)
        
        # Set up pattern detection
        beep_times = []
        current_time = start_datetime
        count = 0
        
        # Simple pattern: regular interval
        if "every" in pattern_description.lower() and "second" in pattern_description.lower():
            # Extract seconds from pattern description
            seconds_pattern = re.findall(r'(\d+)\s*second', pattern_description)
            if seconds_pattern:
                seconds_interval = int(seconds_pattern[0])
            else:
                seconds_interval = interval
            
            while count < target_count:
                count += 1
                beep_times.append(current_time)
                current_time += timedelta(seconds=seconds_interval)
        
        # Pattern with multiple beeps per minute
        elif "every minute" in pattern_description.lower() and "beep at seconds" in pattern_description.lower():
            # Extract seconds from pattern description
            seconds_list = re.findall(r'(\d+)', pattern_description.split("beep at seconds")[1])
            seconds_list = [int(s) for s in seconds_list]
            
            minute = 0
            while count < target_count:
                for sec in seconds_list:
                    count += 1
                    beep_time = start_datetime + timedelta(minutes=minute, seconds=sec)
                    beep_times.append(beep_time)
                    
                    if count >= target_count:
                        break
                
                minute += 1
        
        # Default: simple interval
        else:
            while count < target_count:
                count += 1
                beep_times.append(current_time)
                current_time += timedelta(seconds=interval)
        
        # Get the target beep
        target_beep = beep_times[target_count - 1]
        
        result["target_beep_time"] = target_beep.strftime("%H:%M:%S")
        result["target_beep_count"] = target_count
        result["total_minutes"] = (target_beep - start_datetime).total_seconds() / 60
        result["success"] = True
        
    except Exception as e:
        result["success"] = False
        result["error"] = str(e)
    
    return result

def riddle_lookup(riddle_text: str) -> Dict[str, Any]:
    """
    Look up common riddles in a database.
    
    Args:
        riddle_text: The riddle to look up
    
    Returns:
        Dictionary with possible answers
    """
    result = {}
    
    # Common riddle database
    riddle_db = {
        "what has keys but no locks": "piano",
        "what has a head and a tail but no body": "coin",
        "what gets wetter as it dries": "towel",
        "what has an eye but cannot see": "needle",
        "what has teeth but cannot eat": "comb",
        "what has a face and two hands but no arms or legs": "clock",
        "what can travel around the world while staying in a corner": "stamp",
        "what has a neck but no head": "bottle",
        "what is full of holes but still holds water": "sponge",
        "what is always in front of you but can't be seen": "future",
        "what can you catch but not throw": "cold",
        "what has many keys but can't open a single lock": "keyboard",
        "what gets broken without being held": "promise",
        "what can run but never walks": "river",
        "what has legs but doesn't walk": "table",
        "what is so fragile that saying its name breaks it": "silence",
        "what goes up but never comes down": "age",
        "what has hands but cannot clap": "clock",
        "what can you serve but never eat": "tennis ball",
        "what has cities but no houses": "map",
        "what has words but never speaks": "book",
        "what can fly without wings": "time",
        "what has a ring but no finger": "telephone",
        "what has banks but no money": "river",
        "what has a bed but never sleeps": "river",
        "what has a head but never weeps": "pin",
        "what has a bottom at the top": "leg",
        "what has four legs in the morning, two at noon, and three in the evening": "human",
        "what is black when you buy it, red when you use it, and gray when you throw it away": "charcoal",
        "what can fill a room but takes up no space": "light",
        "what is always coming but never arrives": "tomorrow",
        "what can be cracked, made, told, and played": "joke",
        "what has 13 hearts but no other organs": "deck of cards",
        "what has a thumb and four fingers but is not alive": "glove",
        "what has many needles but doesn't sew": "pine tree",
        "what has branches but no fruit, trunk or leaves": "bank",
        "what is cut on a table, but is never eaten": "deck of cards",
        "what has a head, a tail, is brown, and has no legs": "penny",
        "what building has the most stories": "library",
        "what has roots that nobody sees, is taller than trees, up up it goes, and yet never grows": "mountain",
        "what is odette's mother": "odette",
        "what is dead but was never alive": "battery",
    }
    
    try:
        # Clean up the riddle text
        clean_riddle = riddle_text.lower().strip().rstrip("?")
        
        # Direct lookup
        if clean_riddle in riddle_db:
            result["answer"] = riddle_db[clean_riddle]
            result["confidence"] = "high"
            result["success"] = True
            return result
        
        # Fuzzy matching
        best_match = None
        best_score = 0
        
        for known_riddle, answer in riddle_db.items():
            # Simple word overlap score
            riddle_words = set(clean_riddle.split())
            known_words = set(known_riddle.split())
            overlap = len(riddle_words.intersection(known_words))
            total = len(riddle_words.union(known_words))
            score = overlap / total if total > 0 else 0
            
            if score > best_score and score > 0.5:  # Threshold for matching
                best_score = score
                best_match = (known_riddle, answer)
        
        if best_match:
            result["answer"] = best_match[1]
            result["matched_riddle"] = best_match[0]
            result["confidence"] = f"medium ({best_score:.2f})"
            result["success"] = True
        else:
            result["success"] = False
            result["error"] = "No matching riddle found in database"
        
    except Exception as e:
        result["success"] = False
        result["error"] = str(e)
    
    return result

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
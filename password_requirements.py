import re
import random
import string
from typing import Dict, Tuple

class PasswordRequirements:
    @staticmethod
    def analyze_password(password: str) -> Dict[str, int]:
        """Analyze password and return counts of each character type"""
        return {
            'uppercase': sum(1 for c in password if c.isupper()),
            'lowercase': sum(1 for c in password if c.islower()),
            'numbers': sum(1 for c in password if c.isdigit()),
            'special': sum(1 for c in password if c in "!@#$%^&*(),.?\":{}|<>"),
            'length': len(password)
        }

    @staticmethod
    def modify_password(password: str, requirement_type: str, target_count: int) -> str:
        """Modify password to meet the target count for a specific requirement"""
        if not password:
            return password

        special_chars = "!@#$%^&*(),.?\":{}|<>"
        current_counts = PasswordRequirements.analyze_password(password)
        
        if requirement_type == 'uppercase':
            current_count = current_counts['uppercase']
            if target_count > current_count:
                # Add more uppercase letters by converting lowercase to uppercase
                for _ in range(target_count - current_count):
                    lower_indices = [i for i, c in enumerate(password) if c.islower()]
                    if lower_indices:
                        idx = random.choice(lower_indices)
                        password = password[:idx] + password[idx].upper() + password[idx+1:]
            elif target_count < current_count:
                # Convert uppercase to lowercase
                upper_indices = [i for i, c in enumerate(password) if c.isupper()]
                for _ in range(current_count - target_count):
                    if upper_indices:
                        idx = random.choice(upper_indices)
                        password = password[:idx] + password[idx].lower() + password[idx+1:]
                        upper_indices.remove(idx)

        elif requirement_type == 'numbers':
            current_count = current_counts['numbers']
            if target_count > current_count:
                # Add more numbers by replacing non-numbers
                for _ in range(target_count - current_count):
                    non_num_indices = [i for i, c in enumerate(password) if not c.isdigit()]
                    if non_num_indices:
                        idx = random.choice(non_num_indices)
                        password = password[:idx] + str(random.randint(0, 9)) + password[idx+1:]
            elif target_count < current_count:
                # Replace numbers with lowercase letters
                num_indices = [i for i, c in enumerate(password) if c.isdigit()]
                for _ in range(current_count - target_count):
                    if num_indices:
                        idx = random.choice(num_indices)
                        password = password[:idx] + random.choice(string.ascii_lowercase) + password[idx+1:]
                        num_indices.remove(idx)

        elif requirement_type == 'special':
            current_count = current_counts['special']
            if target_count > current_count:
                # Add more special characters
                for _ in range(target_count - current_count):
                    non_special_indices = [i for i, c in enumerate(password) if c not in special_chars]
                    if non_special_indices:
                        idx = random.choice(non_special_indices)
                        password = password[:idx] + random.choice(special_chars) + password[idx+1:]
            elif target_count < current_count:
                # Replace special characters with lowercase letters
                special_indices = [i for i, c in enumerate(password) if c in special_chars]
                for _ in range(current_count - target_count):
                    if special_indices:
                        idx = random.choice(special_indices)
                        password = password[:idx] + random.choice(string.ascii_lowercase) + password[idx+1:]
                        special_indices.remove(idx)

        elif requirement_type == 'length':
            current_length = len(password)
            if target_count > current_length:
                # Add more characters
                chars = string.ascii_letters + string.digits + special_chars
                password += ''.join(random.choice(chars) for _ in range(target_count - current_length))
            elif target_count < current_length:
                # Truncate password
                password = password[:target_count]

        return password

    @staticmethod
    def assess_strength(password: str) -> Tuple[str, int]:
        """Assess password strength and return (strength_label, score)"""
        score = 0
        counts = PasswordRequirements.analyze_password(password)
        
        # Length score (up to 40 points)
        length = counts['length']
        if length >= 12:
            score += 40
        elif length >= 8:
            score += 25
        elif length >= 6:
            score += 10
            
        # Character type diversity (up to 60 points)
        if counts['uppercase'] > 0:
            score += 15
        if counts['lowercase'] > 0:
            score += 15
        if counts['numbers'] > 0:
            score += 15
        if counts['special'] > 0:
            score += 15
            
        # Determine strength label
        if score >= 80:
            return "Very Strong", score
        elif score >= 60:
            return "Strong", score
        elif score >= 40:
            return "Moderate", score
        else:
            return "Weak", score

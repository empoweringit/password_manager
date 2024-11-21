import string
import re
import math
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

@dataclass
class PasswordRequirement:
    min_length: int
    max_length: Optional[int]
    require_uppercase: bool
    require_lowercase: bool
    require_numbers: bool
    require_special: bool
    allowed_special: str
    disallowed_chars: str
    max_sequential: Optional[int]
    max_repeated: Optional[int]
    min_unique: Optional[int]
    description: str
    reference_url: str

class PasswordStandards:
    """Collection of password standards from various organizations"""
    
    STANDARDS = {
        "NIST SP 800-63B": PasswordRequirement(
            min_length=8,
            max_length=64,
            require_uppercase=False,  # NIST doesn't require complexity
            require_lowercase=False,
            require_numbers=False,
            require_special=False,
            allowed_special=string.punctuation,
            disallowed_chars="",  # NIST recommends accepting all printable ASCII
            max_sequential=None,   # No specific requirement
            max_repeated=None,     # No specific requirement
            min_unique=None,       # No specific requirement
            description="NIST guidelines focus on length over complexity. Emphasizes user-friendly yet secure practices.",
            reference_url="https://pages.nist.gov/800-63-3/sp800-63b.html"
        ),
        
        "PCI DSS 4.0": PasswordRequirement(
            min_length=12,         # Increased from 8 in PCI DSS 4.0
            max_length=None,
            require_uppercase=True,
            require_lowercase=True,
            require_numbers=True,
            require_special=True,
            allowed_special=string.punctuation,
            disallowed_chars="",
            max_sequential=3,      # No more than 3 consecutive identical characters
            max_repeated=4,        # No more than 4 repeated characters
            min_unique=6,          # At least 6 unique characters
            description="Payment Card Industry Data Security Standard version 4.0, focused on protecting payment systems.",
            reference_url="https://www.pcisecuritystandards.org/"
        ),
        
        "HIPAA": PasswordRequirement(
            min_length=8,
            max_length=None,
            require_uppercase=True,
            require_lowercase=True,
            require_numbers=True,
            require_special=True,
            allowed_special=string.punctuation,
            disallowed_chars="",
            max_sequential=None,
            max_repeated=None,
            min_unique=None,
            description="Healthcare Information Protection standards for medical data security.",
            reference_url="https://www.hhs.gov/hipaa/"
        ),
        
        "Microsoft AD": PasswordRequirement(
            min_length=8,
            max_length=256,
            require_uppercase=True,
            require_lowercase=True,
            require_numbers=True,
            require_special=True,
            allowed_special="~!@#$%^&*_-+=`|\\(){}[]:;\"'<>,.?/",
            disallowed_chars="",
            max_sequential=None,
            max_repeated=None,
            min_unique=None,
            description="Microsoft Active Directory default password policy.",
            reference_url="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy"
        ),
        
        "CIS Level 1": PasswordRequirement(
            min_length=14,
            max_length=None,
            require_uppercase=True,
            require_lowercase=True,
            require_numbers=True,
            require_special=True,
            allowed_special=string.punctuation,
            disallowed_chars="",
            max_sequential=3,
            max_repeated=3,
            min_unique=8,
            description="Center for Internet Security Level 1 benchmark for essential cybersecurity.",
            reference_url="https://www.cisecurity.org/"
        ),
        
        "CIS Level 2": PasswordRequirement(
            min_length=16,
            max_length=None,
            require_uppercase=True,
            require_lowercase=True,
            require_numbers=True,
            require_special=True,
            allowed_special=string.punctuation,
            disallowed_chars="",
            max_sequential=2,
            max_repeated=2,
            min_unique=10,
            description="Center for Internet Security Level 2 benchmark for enhanced cybersecurity.",
            reference_url="https://www.cisecurity.org/"
        ),
        
        "SOC 2": PasswordRequirement(
            min_length=10,
            max_length=None,
            require_uppercase=True,
            require_lowercase=True,
            require_numbers=True,
            require_special=True,
            allowed_special=string.punctuation,
            disallowed_chars="",
            max_sequential=None,
            max_repeated=None,
            min_unique=None,
            description="System and Organization Controls 2 compliance for service organizations.",
            reference_url="https://www.aicpa.org/soc"
        ),
    }

    @staticmethod
    def analyze_password(password: str, standard_name: str = None) -> Dict:
        """
        Analyzes a password against one or all standards.
        
        Args:
            password: The password to analyze
            standard_name: Optional specific standard to check against
        
        Returns:
            Dictionary containing analysis results
        """
        standards_to_check = (
            {standard_name: PasswordStandards.STANDARDS[standard_name]}
            if standard_name
            else PasswordStandards.STANDARDS
        )
        
        # Basic password characteristics
        chars = list(password)
        unique_chars = len(set(chars))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(f'[{re.escape(string.punctuation)}]', password))
        
        # Advanced patterns
        # Check for sequential patterns (e.g., abc, 123)
        sequential_alpha = 'abcdefghijklmnopqrstuvwxyz'
        sequential_num = '0123456789'
        max_sequential = 1
        
        # Check both forward and backward sequences
        for seq in [sequential_alpha, sequential_num]:
            seq_fwd = seq.lower()
            seq_rev = seq_fwd[::-1]
            
            for test_seq in [seq_fwd, seq_rev]:
                for i in range(len(password)-2):
                    window = password[i:i+3].lower()
                    if window in test_seq:
                        max_sequential = max(max_sequential, len(window))
        
        # Check for repeated characters
        repeated_chars = {c: password.count(c) for c in set(password)}
        max_repeated = max(repeated_chars.values()) if repeated_chars else 0
        
        # Calculate entropy more accurately based on the standard
        if standard_name:
            req = standards_to_check[standard_name]
            # Adjust character pool based on standard requirements
            char_pool_size = sum([
                26 if req.require_lowercase else (26 if has_lower else 0),  # lowercase
                26 if req.require_uppercase else (26 if has_upper else 0),  # uppercase
                10 if req.require_numbers else (10 if has_digit else 0),    # digits
                len(req.allowed_special) if req.require_special            # special chars
                    else (sum(1 for c in password if c in string.punctuation))
            ])
        else:
            # Default entropy calculation
            char_pool_size = sum([
                26 if has_lower else 0,    # lowercase
                26 if has_upper else 0,    # uppercase
                10 if has_digit else 0,    # digits
                sum(1 for c in password if c in string.punctuation)  # actual special chars
            ])
        
        entropy = len(password) * math.log2(char_pool_size) if char_pool_size > 0 else 0
        
        # Time to crack estimates (based on different attack scenarios)
        # Adjust cracking speeds based on standard requirements
        if standard_name:
            req = standards_to_check[standard_name]
            # More conservative estimates for high-security standards
            if standard_name in ["CIS Level 2", "PCI DSS 4.0"]:
                offline_fast_per_second = 1e11  # Faster GPU attacks
            elif standard_name in ["HIPAA", "SOC 2"]:
                offline_fast_per_second = 1e10  # Standard GPU attacks
            else:
                offline_fast_per_second = 1e9   # Basic GPU attacks
        else:
            offline_fast_per_second = 1e10  # Default GPU attack speed
        
        online_attempts_per_second = 100    # Rate-limited online attacks
        offline_slow_per_second = 1e4       # Slow hash offline attacks
        
        possible_combinations = char_pool_size ** len(password)
        time_to_crack = {
            "online_attack": possible_combinations / online_attempts_per_second,
            "offline_slow": possible_combinations / offline_slow_per_second,
            "offline_fast": possible_combinations / offline_fast_per_second
        }
        
        # Check compliance with each standard
        compliance = {}
        for name, req in standards_to_check.items():
            issues = []
            
            if len(password) < req.min_length:
                issues.append(f"Length below minimum ({len(password)} < {req.min_length})")
            if req.max_length and len(password) > req.max_length:
                issues.append(f"Length above maximum ({len(password)} > {req.max_length})")
            if req.require_uppercase and not has_upper:
                issues.append("Missing uppercase letter")
            if req.require_lowercase and not has_lower:
                issues.append("Missing lowercase letter")
            if req.require_numbers and not has_digit:
                issues.append("Missing number")
            if req.require_special and not has_special:
                issues.append("Missing special character")
            if req.max_sequential and max_sequential > req.max_sequential:
                issues.append(f"Contains sequential pattern (e.g., abc, 123)")
            if req.max_repeated and max_repeated > req.max_repeated:
                issues.append(f"Character repeated too many times ({max_repeated} times)")
            if req.min_unique and unique_chars < req.min_unique:
                issues.append(f"Too few unique characters ({unique_chars} < {req.min_unique})")
            
            # Standard-specific checks
            if name == "PCI DSS 4.0":
                if any(c not in req.allowed_special and c in string.punctuation for c in password):
                    issues.append("Contains disallowed special characters")
            elif name == "HIPAA":
                # HIPAA specific - check for common medical terms
                medical_terms = ['doctor', 'nurse', 'patient', 'hospital', 'clinic']
                if any(term in password.lower() for term in medical_terms):
                    issues.append("Contains common medical terms (security risk)")
            elif name == "CIS Level 2":
                # Additional CIS Level 2 checks
                if len(set(password)) < len(password) * 0.75:  # At least 75% unique chars
                    issues.append("Insufficient character variety")
            
            compliance[name] = {
                "compliant": len(issues) == 0,
                "issues": issues,
                "description": req.description,
                "reference": req.reference_url,
                "min_length": req.min_length,
                "max_length": req.max_length,
                "require_special": req.require_special,
                "allowed_special": req.allowed_special
            }
        
        return {
            "length": len(password),
            "entropy": entropy,
            "character_sets": {
                "uppercase": has_upper,
                "lowercase": has_lower,
                "numbers": has_digit,
                "special": has_special,
                "unique_count": unique_chars
            },
            "patterns": {
                "max_sequential": max_sequential,
                "max_repeated": max_repeated,
                "character_frequency": repeated_chars
            },
            "time_to_crack": time_to_crack,
            "compliance": compliance,
            "selected_standard": standard_name
        }

    @staticmethod
    def get_recommendations(analysis: Dict, target_standard: str = None) -> List[str]:
        """
        Generates recommendations based on the analysis results.
        
        Args:
            analysis: Password analysis results
            target_standard: Optional specific standard to target recommendations for
        
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # If targeting a specific standard, focus on its requirements
        if target_standard and target_standard in PasswordStandards.STANDARDS:
            req = PasswordStandards.STANDARDS[target_standard]
            compliance = analysis["compliance"][target_standard]
            
            if not compliance["compliant"]:
                recommendations.append(f"\nTo comply with {target_standard}:")
                for issue in compliance["issues"]:
                    recommendations.append(f"• {issue}")
                recommendations.append(f"\nReference: {req.reference_url}")
            return recommendations
        
        # General recommendations based on best practices
        if analysis["entropy"] < 70:
            recommendations.append("• Increase password strength by making it longer or more complex")
        
        char_sets = analysis["character_sets"]
        if not all([char_sets["uppercase"], char_sets["lowercase"], 
                   char_sets["numbers"], char_sets["special"]]):
            recommendations.append("• Use a mix of uppercase, lowercase, numbers, and special characters")
        
        if analysis["length"] < 14:  # Conservative minimum length
            recommendations.append("• Consider using a longer password (14+ characters recommended)")
        
        patterns = analysis["patterns"]
        if patterns["max_sequential"] > 2:
            recommendations.append("• Avoid sequential characters (e.g., '123', 'abc')")
        if patterns["max_repeated"] > 2:
            recommendations.append("• Avoid repeating characters too many times")
        
        # Add recommendations for standards that are close to being met
        almost_compliant = []
        for standard, result in analysis["compliance"].items():
            if not result["compliant"] and len(result["issues"]) <= 2:
                almost_compliant.append(f"• With small changes, could comply with {standard}")
        
        if almost_compliant:
            recommendations.append("\nNearby Standards Compliance:")
            recommendations.extend(almost_compliant)
        
        return recommendations

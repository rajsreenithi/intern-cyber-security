import string
import secrets
import sqlite3

# ==========================================
# 1. DATABASE SETUP (Optional Feature)
# ==========================================
def init_db():
    """Creates a local database to store old passwords and prevent reuse."""
    conn = sqlite3.connect("password_history.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT NOT NULL UNIQUE
        )
    ''')
    conn.commit()
    conn.close()

def is_password_reused(password):
    """Checks if the password already exists in the history database."""
    conn = sqlite3.connect("password_history.db")
    cursor = conn.cursor()
    # Note: In a production app, you would hash this (e.g., using bcrypt or hashlib)
    cursor.execute("SELECT 1 FROM password_history WHERE password_hash = ?", (password,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def save_password(password):
    """Saves a newly accepted password to the history database."""
    conn = sqlite3.connect("password_history.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO password_history (password_hash) VALUES (?)", (password,))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Already exists
    conn.close()


# ==========================================
# 2. PASSWORD STRENGTH ANALYZER CORE
# ==========================================
def evaluate_password(password):
    """Evaluates password length, complexity, and unique characters."""
    score = 0
    feedback = []

    # Check Length
    length = len(password)
    if length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        feedback.append("• Increase length to at least 8 characters (12+ preferred).")

    # Check Complexity
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    if has_lower: score += 1
    else: feedback.append("• Add lowercase letters.")
    
    if has_upper: score += 1
    else: feedback.append("• Add uppercase letters.")
    
    if has_digit: score += 1
    else: feedback.append("• Add numbers.")
    
    if has_special: score += 1
    else: feedback.append("• Add special characters (e.g., !, @, #, $).")

    # Check Uniqueness / Entropy (Ratio of unique characters)
    if length > 0:
        unique_ratio = len(set(password)) / length
        if unique_ratio < 0.5:
            score -= 1
            feedback.append("• Reduce character repetition; make it more unique.")

    # Determine Rating
    if score >= 5:
        rating = "STRONG"
    elif 3 <= score < 5:
        rating = "MEDIUM"
    else:
        rating = "WEAK"

    return rating, feedback


# ==========================================
# 3. SUGGEST ALTERNATIVES
# ==========================================
def generate_strong_alternative(length=14):
    """Generates a secure, cryptographically random alternative password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        # Ensure it meets the strict strength requirements
        if (any(c.islower() for c in password) and 
            any(c.isupper() for c in password) and 
            any(c.isdigit() for c in password) and 
            any(c in string.punctuation for c in password)):
            return password


# ==========================================
# 4. MAIN USER INTERFACE
# ==========================================
def main():
    init_db()
    print("=" * 45)
    print("       PASSWORD STRENGTH ANALYZER       ")
    print("=" * 45)

    while True:
        user_pwd = input("\nEnter a password to evaluate (or type 'exit' to quit): ").strip()
        
        if user_pwd.lower() == 'exit':
            print("\nExiting tool. Stay secure!")
            break
        
        if not user_pwd:
            print("Password cannot be empty!")
            continue

        # Step 1: Database Reuse Check
        if is_password_reused(user_pwd):
            print("\n❌ SECURITY RISK: You have used this password before!")
            print("👉 Recommendation: Please generate or choose a brand new password.")
            print(f"💡 Suggested Secure Alternative: {generate_strong_alternative()}")
            continue

        # Step 2: Strength Evaluation
        rating, feedback = evaluate_password(user_pwd)

        # Step 3: Print Results
        print(f"\nAnalysis Result:")
        print(f"----------------")
        if rating == "STRONG":
            print(f"Strength Rating: ✅ {rating}")
            print("Great job! Your password meets basic cryptographic strength rules.")
            # Save accepted strong password to history
            save_password(user_pwd)
        elif rating == "MEDIUM":
            print(f"Strength Rating: ⚠️ {rating}")
        else:
            print(f"Strength Rating: ❌ {rating}")

        # Provide Improvement Tips
        if feedback:
            print("\nHow to improve your password:")
            for tip in feedback:
                print(tip)

        # Step 4: Offer Alternative Suggestion if it's not already Strong
        if rating != "STRONG":
            print(f"\n💡 Suggested Secure Alternative: {generate_strong_alternative()}")
            
        print("-" * 45)

if __name__ == "__main__":
    main()

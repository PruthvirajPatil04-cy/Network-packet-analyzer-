"""
One-time seed generator: Hashes student passwords using bcrypt and saves to students.json.
Plaintext source reference lives only in docs/DEMO_CREDENTIALS.md.
Usage:
    python -m demo_server.seed.hash_passwords
"""

import json
import os
from pathlib import Path
import bcrypt

SEED_DIR = Path(__file__).resolve().parent
STUDENTS_JSON_PATH = SEED_DIR / "students.json"

RAW_SEED_ROSTER = [
    {
        "roll": "CS22B001",
        "name": "Aarav Sharma",
        "program": "B.Tech CSE",
        "year": 3,
        "email": "aarav.sharma@college.edu",
        "password": "Aarav@2024",
        "section": "A",
        "ip": "10.20.1.101",
        "enrolled": ["CS301 DBMS", "CS302 OS", "CS303 Networks", "CS304 DSA"],
        "cgpa": 8.6,
        "fee_status": "Paid",
        "fee_due": 0,
    },
    {
        "roll": "CS22B002",
        "name": "Priya Nair",
        "program": "B.Tech CSE",
        "year": 3,
        "email": "priya.nair@college.edu",
        "password": "Priya@2024",
        "section": "A",
        "ip": "10.20.1.102",
        "enrolled": ["CS301 DBMS", "CS302 OS", "CS303 Networks", "HS301 Ethics"],
        "cgpa": 9.1,
        "fee_status": "Paid",
        "fee_due": 0,
    },
    {
        "roll": "CS22B003",
        "name": "Rohan Mehta",
        "program": "B.Tech CSE",
        "year": 3,
        "email": "rohan.mehta@college.edu",
        "password": "Rohan@2024",
        "section": "B",
        "ip": "10.20.1.103",
        "enrolled": ["CS301 DBMS", "CS303 Networks", "CS305 AI", "CS306 Cloud"],
        "cgpa": 7.8,
        "fee_status": "Partial",
        "fee_due": 15000,
    },
    {
        "roll": "EC22B004",
        "name": "Ananya Iyer",
        "program": "B.Tech ECE",
        "year": 3,
        "email": "ananya.iyer@college.edu",
        "password": "Ananya@2024",
        "section": "A",
        "ip": "10.20.2.104",
        "enrolled": ["EC301 DSP", "EC302 VLSI", "EC303 Signals", "MA301 Prob"],
        "cgpa": 8.9,
        "fee_status": "Paid",
        "fee_due": 0,
    },
    {
        "roll": "EC22B005",
        "name": "Vikram Reddy",
        "program": "B.Tech ECE",
        "year": 3,
        "email": "vikram.reddy@college.edu",
        "password": "Vikram@2024",
        "section": "A",
        "ip": "10.20.2.105",
        "enrolled": ["EC301 DSP", "EC302 VLSI", "EC304 Embedded", "MA301 Prob"],
        "cgpa": 8.2,
        "fee_status": "Paid",
        "fee_due": 0,
    },
    {
        "roll": "ME22B006",
        "name": "Sneha Kulkarni",
        "program": "B.Tech Mech",
        "year": 3,
        "email": "sneha.kulkarni@college.edu",
        "password": "Sneha@2024",
        "section": "A",
        "ip": "10.20.3.106",
        "enrolled": ["ME301 Thermo", "ME302 FM", "ME303 Machine Design", "MA302 Num"],
        "cgpa": 8.4,
        "fee_status": "Paid",
        "fee_due": 0,
    },
    {
        "roll": "ME22B007",
        "name": "Karthik Rao",
        "program": "B.Tech Mech",
        "year": 3,
        "email": "karthik.rao@college.edu",
        "password": "Karthik@2024",
        "section": "B",
        "ip": "10.20.3.107",
        "enrolled": ["ME301 Thermo", "ME302 FM", "ME304 CAD", "MA302 Num"],
        "cgpa": 7.5,
        "fee_status": "Partial",
        "fee_due": 22000,
    },
    {
        "roll": "CS21B008",
        "name": "Isha Patel",
        "program": "B.Tech CSE",
        "year": 4,
        "email": "isha.patel@college.edu",
        "password": "Isha@2024",
        "section": "A",
        "ip": "10.20.1.108",
        "enrolled": ["CS401 ML", "CS402 Compilers", "CS403 Security", "CS404 Capstone"],
        "cgpa": 9.3,
        "fee_status": "Paid",
        "fee_due": 0,
    },
    {
        "roll": "CS21B009",
        "name": "Aditya Verma",
        "program": "B.Tech CSE",
        "year": 4,
        "email": "aditya.verma@college.edu",
        "password": "Aditya@2024",
        "section": "A",
        "ip": "10.20.1.109",
        "enrolled": ["CS401 ML", "CS402 Compilers", "CS403 Security", "CS405 Blockchain"],
        "cgpa": 8.7,
        "fee_status": "Unpaid",
        "fee_due": 45000,
    },
    {
        "roll": "EE22B010",
        "name": "Meera Joshi",
        "program": "B.Tech EEE",
        "year": 3,
        "email": "meera.joshi@college.edu",
        "password": "Meera@2024",
        "section": "A",
        "ip": "10.20.4.110",
        "enrolled": ["EE301 Power Sys", "EE302 Control", "EE303 Machines", "MA301 Prob"],
        "cgpa": 8.1,
        "fee_status": "Paid",
        "fee_due": 0,
    },
]


def generate_hashed_seed():
    """Generates bcrypt password hashes and outputs students.json."""
    hashed_students = []
    for item in RAW_SEED_ROSTER:
        plain_pw = item["password"]
        # Generate bcrypt hash (12 rounds)
        salt = bcrypt.gensalt(rounds=12)
        pw_hash = bcrypt.hashpw(plain_pw.encode("utf-8"), salt).decode("utf-8")

        student_record = {
            "roll": item["roll"],
            "name": item["name"],
            "program": item["program"],
            "year": item["year"],
            "email": item["email"],
            "password_hash": pw_hash,
            "section": item["section"],
            "ip": item["ip"],
            "enrolled": item["enrolled"],
            "cgpa": item["cgpa"],
            "fee_status": item["fee_status"],
            "fee_due": item["fee_due"],
        }
        hashed_students.append(student_record)

    SEED_DIR.mkdir(parents=True, exist_ok=True)
    with open(STUDENTS_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(hashed_students, f, indent=2)

    print(f"Successfully generated {len(hashed_students)} hashed student records at {STUDENTS_JSON_PATH}")


if __name__ == "__main__":
    generate_hashed_seed()

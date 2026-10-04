import sqlite3
from database import get_db


def add_student(student_id, name):

    db = get_db()
    cursor = db.cursor()

    try:

        cursor.execute("""
            INSERT INTO students (id, name)
            VALUES (?, ?)
        """, (student_id, name))

        db.commit()

        result = {
            "success": True,
            "message": "Student registered successfully"
        }

    except sqlite3.IntegrityError:

        result = {
            "success": False,
            "message": "Student already exists"
        }

    db.close()

    return result
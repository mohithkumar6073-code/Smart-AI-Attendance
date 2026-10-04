from datetime import date
from database import get_db


def mark_attendance(student_id, status="Present"):

    db = get_db()
    cursor = db.cursor()

    today = str(date.today())

    # Check whether attendance already exists
    cursor.execute("""
        SELECT * FROM attendance
        WHERE student_id = ? AND date = ?
    """, (student_id, today))

    existing = cursor.fetchone()

    if existing:
        db.close()

        return {
            "success": False,
            "message": "Attendance already marked today"
        }

    cursor.execute("""
        INSERT INTO attendance
        (student_id, date, status)
        VALUES (?, ?, ?)
    """, (student_id, today, status))

    db.commit()
    db.close()

    return {
        "success": True,
        "student_id": student_id,
        "date": today,
        "status": status,
        "message": "Attendance marked successfully"
    }
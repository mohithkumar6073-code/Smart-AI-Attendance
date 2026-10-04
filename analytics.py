from database import get_db


def get_attendance(student_id):

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT COUNT(*) FROM attendance
        WHERE student_id = ?
    """, (student_id,))

    total = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM attendance
        WHERE student_id = ?
        AND status = 'Present'
    """, (student_id,))

    present = cursor.fetchone()[0]

    db.close()

    if total == 0:
        percentage = 0
    else:
        percentage = (present / total) * 100

    return {
        "student_id": student_id,
        "total_classes": total,
        "present": present,
        "attendance_percentage": round(percentage, 2)
    }
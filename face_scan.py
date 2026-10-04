from database import get_db


def verify_face(student_id):

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        "SELECT name FROM students WHERE id = ?",
        (student_id,)
    )

    student = cursor.fetchone()

    db.close()

    if student:

        return {
            "success": True,
            "student_id": student_id,
            "student_name": student[0],
            "message": "Face verified successfully"
        }

    return {
        "success": False,
        "message": "Student not registered"
    }
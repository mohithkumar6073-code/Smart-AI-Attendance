from database import get_db


def get_alerts():

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT
            students.id,
            students.name,
            COUNT(attendance.id) AS total,
            SUM(
                CASE
                    WHEN attendance.status = 'Present'
                    THEN 1
                    ELSE 0
                END
            ) AS present
        FROM students
        LEFT JOIN attendance
        ON students.id = attendance.student_id
        GROUP BY students.id
    """)

    students = cursor.fetchall()

    alerts = []

    for student in students:

        student_id = student[0]
        name = student[1]
        total = student[2]
        present = student[3] or 0

        if total > 0:
            percentage = (present / total) * 100

            if percentage < 75:

                alerts.append({
                    "student_id": student_id,
                    "name": name,
                    "attendance": round(percentage, 2),
                    "alert": "Attendance below 75%"
                })

    db.close()

    return alerts
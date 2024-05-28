from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request, jsonify, send_file, Response, \
    make_response
from io import StringIO
import csv
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor, CKEditorField
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_manager, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey, Date, Boolean, update, func
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
Bootstrap5(app)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///facial_recognition_attendance.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# CONFIGURE TABLE
class Courses(db.Model):
    __tablename__ = "courses"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    course_name: Mapped[str] = mapped_column(String(100))
    course_code: Mapped[str] = mapped_column(String(100), unique=True)
    qrcode: Mapped[str] = mapped_column(String(100))
    course_description: Mapped[str] = mapped_column(String(500))
    condition: Mapped[Boolean] = mapped_column(Boolean)

    # Foreign key to User
    instructor_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('users.id'))

    # Relationship to User
    creator = relationship('User', back_populates='courses')

    relation_to_enrolled_courses = relationship('EnrolledCourses', back_populates='relation_to_courses')
    attendance = relationship('Attendance', back_populates='course')


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fullname: Mapped[str] = mapped_column(String(100))
    user_id: Mapped[str] = mapped_column(String(100), unique=True)
    email: Mapped[str] = mapped_column(String(100))
    password: Mapped[str] = mapped_column(String(100))
    role: Mapped[str] = mapped_column(String(100))
    facial_data: Mapped[str] = mapped_column(String(1000))
    courses = relationship('Courses', back_populates='creator')
    attendance = relationship('Attendance', back_populates='student')


class EnrolledCourses(db.Model):
    __tablename__ = "enrolledcourses"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    student_id: Mapped[str] = mapped_column(String(100))
    fullname: Mapped[str] = mapped_column(String(100))

    course_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('courses.id'))
    relation_to_courses = relationship('Courses', back_populates='relation_to_enrolled_courses')


class Attendance(db.Model):
    __tablename__ = "attendance"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    course_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('courses.id'))
    student_id: Mapped[int] = mapped_column(Integer, db.ForeignKey('users.user_id'))
    attendance_date: Mapped[Date] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(100))

    course = relationship('Courses', back_populates='attendance')
    student = relationship('User', back_populates='attendance')


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        result = db.session.execute(db.select(User).where(User.user_id == username))
        user = result.scalar()

        if not user:
            flash("This ID does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            user_role = user.role
            if user_role == 'student':
                return redirect(url_for('student_home', student_id=user.id))
            else:
                return redirect(url_for('instructor_home', instructor_id=user.id))

    return render_template("login.html")


@app.route("/role")
def role_selector():
    return render_template("role_selector.html")


@app.route("/signup/<role>", methods=["GET", "POST"])
def signup(role):
    if request.method == "POST":
        if role == 'student':
            # Check if the entered student ID exists or not
            result_id = db.session.execute(db.select(User).where(User.user_id == request.form.get("student_id")))
            user = result_id.scalar()
            user_id = request.form.get("student_id")
            if user:
                # StudentID already exists
                flash("This student ID already exists, try again")
                return redirect(url_for('signup', role=role))
        elif role == 'instructor':
            result_id = db.session.execute(db.select(User).where(User.user_id == request.form.get("instructor_id")))
            user = result_id.scalar()
            user_id = request.form.get("instructor_id")
            if user:
                # StudentID already exists
                flash("This instructor ID already exists, try again")
                return redirect(url_for('signup', role=role))

        # Check if the email address is used for another account or not
        result_emailAddress = db.session.execute(db.select(User).where(User.email == request.form.get("email")))
        user2 = result_emailAddress.scalar()
        if user2:
            # Email address already exists
            flash("This email ID already exists, try again")
            return redirect(url_for('signup', role=role))

        hash_and_salted_password = generate_password_hash(
            request.form.get("password"),
            method='pbkdf2:sha256',
            salt_length=8
        )

        new_user = User(
            fullname=request.form.get("full_name"),
            user_id=user_id,
            email=request.form.get("email"),
            password=hash_and_salted_password,
            role=role,
            facial_data='nothing'
        )
        db.session.add(new_user)
        db.session.commit()

        # This line will authenticate users with flask login
        login_user(new_user)
        if role == 'student':
            return redirect(url_for("student_home", student_id=new_user.id))
        else:
            return redirect(url_for("instructor_home", instructor_id=new_user.id))

    return render_template("signup.html", role=role)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/HomePage/<student_id>")
@login_required
def student_home(student_id):
    result = db.session.execute(db.select(User).where(User.id == student_id))
    student_list = result.scalars().all()

    if not student_list:
        return "No student found with the given ID."

    student = student_list[0]

    result2 = db.session.execute(db.select(EnrolledCourses).where(EnrolledCourses.student_id == student.user_id))
    enrolled_courses = result2.scalars().all()
    courses = []

    for enrolled_course in enrolled_courses:
        result3 = db.session.execute(db.select(Courses).where(Courses.id == enrolled_course.course_id))
        course_list = result3.scalars().all()

        if course_list:
            course = course_list[0]
            result4 = db.session.execute(db.select(User).where(User.id == course.instructor_id))
            instructor_list = result4.scalars().all()

            if instructor_list:
                instructor = instructor_list[0]
                courses.append({
                    'course_name': course.course_name,
                    'course_code': course.course_code,
                    'instructor_name': instructor.fullname,
                    'course_id': enrolled_course.course_id
                })

    return render_template("student_home.html", student_id=current_user.id, courses=courses)


@app.route("/CourseS/<student_id>/<course_id>")
@login_required
def student_course(course_id, student_id):
    result = db.session.execute(db.select(Courses).where(Courses.id == course_id))
    course = result.scalar()
    return render_template("student_course.html", course=course, student_id=student_id, course_id=course_id)


@app.route("/Student/Settings/<student_id>")
@login_required
def student_settings(student_id):
    return render_template("student_settings.html", student_id=student_id)


@app.route("/Instructor/Settings/<instructor_id>")
@login_required
def instructor_settings(instructor_id):
    return render_template("instructor_settings.html", instructor_id=instructor_id)


@app.route("/HomePageII/<instructor_id>")
@login_required
def instructor_home(instructor_id):
    courses = current_user.courses
    return render_template("instructor_home.html", role='instructor', instructor_id=instructor_id, courses=courses)


@app.route("/AddCourse/<instructor_id>", methods=["GET", "POST"])
@login_required
def instructor_add_course(instructor_id):
    if request.method == "POST":
        result = db.session.execute(db.select(Courses).where(Courses.course_code == request.form.get("course_code")))
        course = result.scalar()

        if course:
            # This course already exists
            flash("This course already exists, try again")
            return redirect(url_for('instructor_add_course', instructor_id=instructor_id))

        new_course = Courses(
            course_name=request.form.get("course_name"),
            course_code=request.form.get("course_code"),
            qrcode='nothing',
            course_description=request.form.get("course_description"),
            instructor_id=instructor_id,
            condition=False
        )
        db.session.add(new_course)
        db.session.commit()
        return redirect(url_for("instructor_home", instructor_id=instructor_id))

    return render_template("instructor_addcourse.html", instructor_id=instructor_id, role='instructor')


@app.route("/Course/<instructor_id>/<course_id>")
@login_required
def instructor_course(course_id, instructor_id):
    result = db.session.execute(db.select(Courses).where(Courses.id == course_id))
    course = result.scalar()

    return render_template("instructor_course.html", role='instructor', course=course, instructor_id=instructor_id)


@app.route("/add_students/<instructor_id>/<course_id>", methods=["POST"])
@login_required
def add_students(course_id, instructor_id):
    data = request.json
    students = data.get('students', [])

    # Lists to track newly added and already existing students
    added_students = []
    existing_students = []

    for student in students:
        fullname = student['fullname']
        student_id = student['student_id']

        # Check if the student already exists in the EnrolledCourses table
        exists = db.session.query(EnrolledCourses).filter_by(student_id=student_id, course_id=course_id).first()

        if exists:
            existing_students.append(student)
        else:
            new_student = EnrolledCourses(
                student_id=student_id,
                fullname=fullname,
                course_id=course_id
            )
            db.session.add(new_student)
            added_students.append(student)

    db.session.commit()

    return jsonify({
        "message": "Changes saved successfully!",
        "added_students": added_students,
        "existing_students": existing_students
    })


@app.route('/load-student-list', methods=['GET'])
def load_student_list():
    course_id = request.args.get('course_id')
    # Fetch the student list for the given course_id from your database
    result = db.session.execute(db.select(EnrolledCourses).where(EnrolledCourses.course_id == course_id))
    enrolled_courses = result.scalars().all()

    students = []
    for enrolled_course in enrolled_courses:
        students.append({
            "full_name": enrolled_course.fullname,
            "student_id": enrolled_course.student_id
        })

    return jsonify({'students': students})


@app.route('/remove-student', methods=['DELETE'])
def remove_student():
    student_id = request.args.get('student_id')
    course_id = request.args.get('course_id')

    # Find and delete the student from the database
    student = db.session.execute(
        db.select(EnrolledCourses).where(
            (EnrolledCourses.student_id == student_id) &
            (EnrolledCourses.course_id == course_id)
        )
    ).scalar_one_or_none()

    if student:
        db.session.delete(student)
        db.session.commit()
        return jsonify({'success': True}), 200
    else:
        return jsonify({'error': 'Student not found'}), 404


@app.route('/start_attendance', methods=['POST'])
@login_required
def start_attendance():
    data = request.get_json()
    course_id = data.get('course_id')

    # Get all enrolled students for the given course_id
    enrolled_students = db.session.execute(
        db.select(EnrolledCourses).where(EnrolledCourses.course_id == course_id)
    ).scalars().all()

    # Add entries to the Attendance table
    today = date.today()
    for enrolled in enrolled_students:
        attendance_entry = Attendance(
            course_id=course_id,
            student_id=enrolled.student_id,
            attendance_date=today,
            status='Absent',
        )
        db.session.add(attendance_entry)

    # Update condition column in Courses table
    db.session.execute(
        update(Courses).where(Courses.id == course_id).values(condition=True)
    )

    db.session.commit()
    return jsonify({'message': 'Attendance session started successfully'}), 200


@app.route('/end_attendance', methods=['POST'])
@login_required
def end_attendance():
    data = request.get_json()
    course_id = data.get('course_id')

    # Update condition column in Courses table
    db.session.execute(
        update(Courses).where(Courses.id == course_id).values(condition=False)
    )

    db.session.commit()
    return jsonify({'message': 'Attendance session ended successfully'}), 200


@app.route('/delete_course', methods=['POST'])
@login_required
def delete_course():
    data = request.get_json()
    course_id = data.get('course_id')
    print(course_id)
    # Your logic to delete the course using course_id
    return jsonify({'message': 'Course deleted successfully'}), 200


@app.route('/give_attendance_page/<course_id>')
@login_required
def give_attendance_page(course_id):
    return render_template('student_give_attendance.html', course_id=course_id)


@app.route('/give_attendance/<course_id>', methods=['POST'])
@login_required
def give_attendance(course_id):
    student_id = current_user.user_id

    # Check if the student is enrolled in the course
    enrolled = db.session.execute(
        db.select(EnrolledCourses).where(
            EnrolledCourses.course_id == course_id,
            EnrolledCourses.student_id == student_id
        )
    ).scalars().first()

    if not enrolled:
        return jsonify({'message': 'Student not enrolled in the course'}), 400

    # Check the condition column in Courses table for the course
    course = db.session.execute(
        db.select(Courses).where(Courses.id == course_id)
    ).scalars().first()

    if not course or not course.condition:
        return jsonify({'message': 'Attendance session is off, the instructor needs to turn it on'}), 400

    # Check the existing attendance record
    today = date.today()
    attendance = db.session.execute(
        db.select(Attendance).where(
            Attendance.course_id == course_id,
            Attendance.student_id == student_id,
            Attendance.attendance_date == today
        )
    ).scalars().first()

    if attendance:
        attendance.status = 'Present'
        db.session.commit()
        return jsonify({'message': 'Attendance given successfully'}), 200
    else:
        return jsonify({'message': 'Attendance record not found'}), 400


@app.route('/get_attendance_data', methods=['GET'])
def get_attendance_data():
    course_id = request.args.get('course_id')
    # Get enrolled students for the course
    enrolled_students = EnrolledCourses.query.filter_by(course_id=course_id).all()
    attendance_report = []

    for student in enrolled_students:
        student_id = student.student_id
        fullname = student.fullname

        # Count days present and absent
        days_present = db.session.query(func.count(Attendance.id)).filter_by(student_id=student_id,
                                                                             status='Present').scalar()
        days_absent = db.session.query(func.count(Attendance.id)).filter_by(student_id=student_id,
                                                                            status='Absent').scalar()

        attendance_report.append({
            'full_name': fullname,
            'student_id': student_id,
            'days_present': days_present,
            'days_absent': days_absent
        })

    return jsonify({'attendance': attendance_report})


@app.route('/download_attendance_report', methods=['GET'])
def download_attendance_report():
    course_id = request.args.get('course_id')
    if not course_id:
        return jsonify({'error': 'Missing course_id parameter'}), 400

    # Get enrolled students for the course
    enrolled_students = EnrolledCourses.query.filter_by(course_id=course_id).all()

    attendance_report = []

    for student in enrolled_students:
        student_id = student.student_id
        fullname = student.fullname

        # Count days present and absent
        days_present = db.session.query(func.count(Attendance.id)).filter_by(student_id=student_id,
                                                                             status='present').scalar()
        days_absent = db.session.query(func.count(Attendance.id)).filter_by(student_id=student_id,
                                                                            status='absent').scalar()

        attendance_report.append({
            'full_name': fullname,
            'student_id': student_id,
            'days_present': days_present,
            'days_absent': days_absent
        })

    # Create CSV
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Full Name', 'Student ID', 'Days Present', 'Days Absent'])
    for record in attendance_report:
        writer.writerow([record['full_name'], record['student_id'], record['days_present'], record['days_absent']])

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=attendance_report.csv"
    output.headers["Content-type"] = "text/csv"
    return output


@app.route('/upload_enrolled_courses', methods=['POST'])
def upload_enrolled_courses():
    course_id = request.form.get('course_id')

    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and file.filename.endswith('.csv'):
        try:
            # Parse the CSV file
            file_str = StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_data = csv.reader(file_str)

            # Skip the header row if it exists
            next(csv_data, None)

            # Store the data from the CSV file
            student_data = []
            for row in csv_data:
                student_data.append({'full_name': row[0], 'student_id': row[1]})

            # # Insert data into the database
            # db.session.bulk_insert_mappings(EnrolledCourses, student_data)
            # db.session.commit()
            return jsonify({'success': 'File uploaded and data inserted successfully', 'data': student_data}), 200

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    else:
        return jsonify({'error': 'Invalid file type. Please upload a CSV file'}), 400


if __name__ == "__main__":
    app.run(debug=True)

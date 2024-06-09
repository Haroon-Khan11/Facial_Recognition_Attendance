import os
import cv2
import csv
import json
import smtplib
import numpy as np
from io import StringIO
from datetime import date
from email.mime.text import MIMEText
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from email.mime.multipart import MIMEMultipart
from itsdangerous import URLSafeTimedSerializer
from sklearn.neighbors import KNeighborsClassifier
from sqlalchemy import Integer, String, Date, Boolean, update, func, and_
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, Response, make_response

app = Flask(__name__)
Bootstrap5(app)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
# app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


# video = cv2.VideoCapture(0)
# facedetect = cv2.CascadeClassifier('haarcascade/haarcascade_frontalface_default.xml')

global_data = {}
user_id_global = None
video_capture_active = None

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///facial_recognition_attendance.db'
# app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///facial_recognition_attendance.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


def generate_frames():
    video = cv2.VideoCapture(0)
    facedetect = cv2.CascadeClassifier('haarcascade/haarcascade_frontalface_default.xml')

    faces_data = []
    i = 0

    while True:
        ret, frame = video.read()
        if not ret:
            break
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = facedetect.detectMultiScale(gray, 1.3, 5)
        for (x, y, w, h) in faces:
            crop_img = frame[y:y + h, x:x + w, :]
            resized_img = cv2.resize(crop_img, (50, 50))
            if len(faces_data) < 50 and i % 10 == 0:
                faces_data.append(resized_img)
            i += 1
            cv2.putText(frame, str(len(faces_data)), (50, 50), cv2.FONT_HERSHEY_COMPLEX, 1, (50, 50, 255), 1)
            cv2.rectangle(frame, (x, y), (x + w, y + h), (50, 50, 255), 1)

        ret, buffer = cv2.imencode('.jpg', frame)
        frame = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

        if len(faces_data) >= 50:
            # Save faces_data to the global dictionary instead of session
            global_data['faces_data'] = np.array(faces_data).tolist()
            video.release()
            cv2.destroyAllWindows()
            with app.app_context():
                # Set a flag to indicate completion
                global_data['capture_complete'] = True
                break


def generate_frames_login():
    global video_capture_active
    with app.app_context():
        # Load data from the database
        users = db.session.query(User).all()
        FACES = []
        LABELS = []

        for user in users:
            faces_data_json = user.facial_data
            if faces_data_json:  # Check if JSON string is not empty
                try:
                    faces_data = json.loads(faces_data_json.encode('utf-8', 'replace').decode('utf-8', 'replace'))
                    flattened_faces = [np.array(face).flatten() for face in faces_data]  # Flatten each face data
                    FACES.extend(flattened_faces)  # Extend FACES with flattened faces
                    LABELS.extend([user.user_id] * len(flattened_faces))  # Extend LABELS with user_id for each face
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    print(f"Error decoding JSON for user {user.id}: {e}")

        FACES = np.array(FACES)
        LABELS = np.array(LABELS)

        print('Shape of Faces matrix --> ', FACES.shape)

        knn = KNeighborsClassifier(n_neighbors=5)
        knn.fit(FACES, LABELS)

        # Video capture loop
        video = cv2.VideoCapture(0)
        facedetect = cv2.CascadeClassifier('haarcascade/haarcascade_frontalface_default.xml')
        video_capture_active = True

        while video_capture_active:
            ret, frame = video.read()
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = facedetect.detectMultiScale(gray, 1.3, 5)
            for (x, y, w, h) in faces:
                crop_img = frame[y:y + h, x:x + w, :]
                resized_img = cv2.resize(crop_img, (50, 50)).flatten().reshape(1, -1)
                output = knn.predict(resized_img)

                # Store the detected user_id in the global variable
                global_data["detected_userID"] = output[0]

                cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 0, 255), 1)
                cv2.rectangle(frame, (x, y), (x + w, y + h), (50, 50, 255), 2)
                cv2.rectangle(frame, (x, y - 40), (x + w, y), (50, 50, 255), -1)
                cv2.putText(frame, str(output[0]), (x, y - 15), cv2.FONT_HERSHEY_COMPLEX, 1, (255, 255, 255), 1)
                cv2.rectangle(frame, (x, y), (x + w, y + h), (50, 50, 255), 1)
                ret, buffer = cv2.imencode('.jpg', frame)
                frame = buffer.tobytes()
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')


def generate_frames_attendance(user_id):
    global video_capture_active
    with app.app_context():
        # Load data from the database
        result = db.session.execute(db.select(User).where(User.role == 'student'))
        users = result.scalars().all()

        FACES = []
        LABELS = []

        for user in users:
            faces_data_json = user.facial_data
            if faces_data_json:  # Check if JSON string is not empty
                try:
                    faces_data = json.loads(faces_data_json.encode('utf-8', 'replace').decode('utf-8', 'replace'))
                    flattened_faces = [np.array(face).flatten() for face in faces_data]  # Flatten each face data
                    FACES.extend(flattened_faces)  # Extend FACES with flattened faces
                    LABELS.extend([user.user_id] * len(flattened_faces))  # Extend LABELS with user_id for each face
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    print(f"Error decoding JSON for user {user.id}: {e}")

        FACES = np.array(FACES)
        LABELS = np.array(LABELS)

        print('Shape of Faces matrix --> ', FACES.shape)

        knn = KNeighborsClassifier(n_neighbors=5)
        knn.fit(FACES, LABELS)

        # Video capture loop
        video = cv2.VideoCapture(0)
        facedetect = cv2.CascadeClassifier('haarcascade/haarcascade_frontalface_default.xml')
        video_capture_active = True

        while video_capture_active:
            ret, frame = video.read()
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = facedetect.detectMultiScale(gray, 1.3, 5)
            for (x, y, w, h) in faces:
                crop_img = frame[y:y + h, x:x + w, :]
                resized_img = cv2.resize(crop_img, (50, 50)).flatten().reshape(1, -1)
                output = knn.predict(resized_img)

                # Store the detected user_id in the global variable
                global_data["detected_userID"] = output[0]

                cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 0, 255), 1)
                cv2.rectangle(frame, (x, y), (x + w, y + h), (50, 50, 255), 2)
                cv2.rectangle(frame, (x, y - 40), (x + w, y), (50, 50, 255), -1)
                cv2.putText(frame, str(output[0]), (x, y - 15), cv2.FONT_HERSHEY_COMPLEX, 1, (255, 255, 255), 1)
                cv2.rectangle(frame, (x, y), (x + w, y + h), (50, 50, 255), 1)
                ret, buffer = cv2.imencode('.jpg', frame)
                frame = buffer.tobytes()
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')


def send_email(to_email, subject, body):
    message = MIMEMultipart()
    message['From'] = 'test.11122211111@outlook.com'
    message['To'] = to_email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))

    try:
        session = smtplib.SMTP('smtp.office365.com', 587)
        session.starttls()
        session.login('test.11122211111@outlook.com', '12345678Haha')
        text = message.as_string()
        session.sendmail('test.11122211111@outlook.com', to_email, text)
        session.quit()
        print("Mail Sent Successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")


# CONFIGURE TABLES
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
    facial_data: Mapped[str] = mapped_column(String(200000))
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


@app.route("/", methods=["POST", "GET"])
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


@app.route("/login1/FaceID", methods=["GET", "POST"])
def login_faceID():
    return render_template("login_faceID.html")  # Add a template for displaying the webcam feed


@app.route('/stop_video_capture', methods=['POST'])
def stop_video_capture():
    video_capture_active = False
    return jsonify({'status': 'success', 'message': 'Login Successful!'}), 200


@app.route('/login_success')
def login_success():
    detected_user_id = global_data.get("detected_userID")
    print(detected_user_id)

    result = db.session.execute(db.select(User).where(User.user_id == detected_user_id))
    user = result.scalars().first()

    login_user(user)
    user_role = user.role
    if user_role == 'student':
        return redirect(url_for('student_home', student_id=user.id))
    else:
        return redirect(url_for('instructor_home', instructor_id=user.id))


@app.route("/video_feed_login")
def video_feed_login():
    mimetype = 'multipart/x-mixed-replace; boundary=frame'
    return Response(generate_frames_login(), mimetype=mimetype)


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

        # Redirect to capture facial data page
        return redirect(url_for("capture_facial_data", user_id=new_user.id, role=role))

        # # This line will authenticate users with flask login
        # login_user(new_user)
        # if role == 'student':
        #     return redirect(url_for("student_home", student_id=new_user.id))
        # else:
        #     return redirect(url_for("instructor_home", instructor_id=new_user.id))

    return render_template("signup.html", role=role)


@app.route("/captureFacialData/<int:user_id>/<role>")
def capture_facial_data(user_id, role):
    user = User.query.get(user_id)
    if not user:
        flash("User not found")
        return redirect(url_for('signup', role=role))

    global_data["role"] = role
    return render_template("signup_facialData.html", user_id=user.id, role=role)


@app.route("/video_feed/<int:user_id>")
def video_feed(user_id):
    global user_id_global
    user_id_global = user_id
    mimetype = 'multipart/x-mixed-replace; boundary=frame'
    return Response(generate_frames(), mimetype=mimetype)


@app.route('/capture_completion_redirect')
def capture_completion_redirect():
    if global_data.get('capture_complete'):
        faces_data = global_data.get('faces_data')
        global user_id_global
        role = global_data.get('role')

        if user_id_global is None or faces_data is None:
            print("SSSSSSSSSSSS")  # Handle error appropriately

        faces_data = np.asarray(faces_data)
        faces_data = faces_data.reshape(50, -1)

        # Convert faces_data to JSON string before storing in the database
        faces_data_json = json.dumps(faces_data.tolist())

        result = db.session.execute(db.select(User).where(User.id == user_id_global))
        user = result.scalars().first()

        if user:
            # Assuming User model has a facial_data attribute
            user.facial_data = faces_data_json  # Save the new facial data
            db.session.commit()

            login_user(user)
            if role == 'student':
                return redirect(url_for("student_home", student_id=user.id))
            else:
                return redirect(url_for("instructor_home", instructor_id=user.id))


@app.route('/check_capture_completion')
def check_capture_completion():
    faces_data = global_data.get('faces_data')
    if faces_data is not None and len(faces_data) >= 50:
        return jsonify(completed=True)
    return jsonify(completed=False)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/forgot_password', methods=["POST", "GET"])
def forgot_password():
    if request.method == "POST":
        email_address = request.form.get("emailID")
        result = db.session.execute(db.select(User).where(User.email == email_address))
        user = result.scalar()

        if not user:
            flash("There is no user account associated with this email address, please try again.")
            return redirect(url_for('forgot_password'))

        token = s.dumps(email_address, salt='password-reset-salt')
        reset_url = url_for('reset_password', token=token, _external=True)
        body = f'User ID : {user.id}' \
               f'Please use the following link to reset your password: {reset_url}'
        send_email(email_address, 'Password Reset Request', body)
        flash('A password reset link has been sent to your email.')
        return redirect(url_for('login'))

    return render_template("forgot_password.html")


@app.route('/reset_password/<token>', methods=["GET", "POST"])
def reset_password(token):
    try:
        email_address = s.loads(token, salt='password-reset-salt', max_age=3600)  # Token valid for 1 hour
    except Exception as e:
        flash('The reset link is invalid or has expired.')
        return redirect(url_for('forgot_password'))

    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if new_password != confirm_password:
            flash('The new password and confirm password do not match. Please try again.')
            return redirect(url_for('reset_password', token=token))

        hash_and_salted_password = generate_password_hash(
            new_password,
            method='pbkdf2:sha256',
            salt_length=8
        )

        user = db.session.execute(db.select(User).where(User.email == email_address)).scalar()
        user.password = hash_and_salted_password
        db.session.commit()

        flash('Your password has been reset successfully. Please login with your new password.')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


@app.route("/HomePage/<student_id>")
@login_required
def student_home(student_id):
    result = db.session.execute(db.select(User).where(User.id == student_id))
    student_list = result.scalars().all()

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

    student_number = current_user.user_id

    result2 = db.session.execute(
        db.select(Attendance).where(and_(Attendance.course_id == course_id, Attendance.student_id == student_number))
    )
    attendance_data = result2.scalars()

    return render_template("student_course.html", course=course, student_id=student_id, course_id=course_id,
                           attendance_data=attendance_data)


@app.route("/Student/Settings/<student_id>")
@login_required
def student_settings(student_id):
    result = db.session.execute(db.select(User).where(User.id == student_id))
    student = result.scalars().all()
    return render_template("student_settings.html", student=student[0], role='student', student_id=student_id)


@app.route('/update_email', methods=['POST', 'GET'])
@login_required
def update_email():
    if request.method == "POST":
        new_email = request.form.get('new_email')

        if not new_email:
            return jsonify({'status': 'error', 'message': 'Please provide a new email address'}), 400

        current_user.email = new_email
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Email updated successfully'}), 200


@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    if request.method == "POST":
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not current_password or not new_password or not confirm_password:
            return jsonify({'status': 'error', 'message': 'Please fill in all password fields'}), 400

        elif not check_password_hash(current_user.password, current_password):
            return jsonify({'status': 'error', 'message': 'Current password is incorrect'}), 400

        elif new_password != confirm_password:
            return jsonify({'status': 'error', 'message': 'New password and confirm password do not match'}), 400

        current_user.password = generate_password_hash(new_password)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Password updated successfully'}), 200


@app.route("/Instructor/Settings/<instructor_id>")
@login_required
def instructor_settings(instructor_id):
    result = db.session.execute(db.select(User).where(User.id == instructor_id))
    instructor = result.scalars().all()
    return render_template("instructor_settings.html", instructor=instructor[0], role='instructor',
                           instructor_id=instructor_id)


@app.route('/update_email_instructor', methods=['POST', 'GET'])
@login_required
def update_email_instructor():
    if request.method == "POST":
        new_email = request.form.get('new_email')

        if not new_email:
            return jsonify({'status': 'error', 'message': 'Please provide a new email address'}), 400

        current_user.email = new_email
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Email updated successfully'}), 200


@app.route('/update_password_instructor', methods=['POST'])
@login_required
def update_password_instructor():
    if request.method == "POST":
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not current_password or not new_password or not confirm_password:
            return jsonify({'status': 'error', 'message': 'Please fill in all password fields'}), 400

        elif not check_password_hash(current_user.password, current_password):
            return jsonify({'status': 'error', 'message': 'Current password is incorrect'}), 400

        elif new_password != confirm_password:
            return jsonify({'status': 'error', 'message': 'New password and confirm password do not match'}), 400

        current_user.password = generate_password_hash(new_password)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Password updated successfully'}), 200


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

    attendance = course.condition

    return render_template("instructor_course.html", role='instructor', course=course, instructor_id=instructor_id,
                           attendance_started=attendance)


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

    print("LOAD STUDENT LIST")
    print(course_id)
    print(students)

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


@app.route('/give_attendance_page/<course_id>')
@login_required
def give_attendance_page(course_id):
    student_number = current_user.user_id
    global_data["courseID"] = course_id
    result = db.session.execute(db.select(Courses).where(Courses.id == course_id))
    course = result.scalar()

    if course.condition:
        # Get today's date
        today_date = date.today()

        # Modify the query to include the conditions for course ID, student ID, and attendance date
        result = db.session.execute(
            db.select(Attendance).where(
                and_(
                    Attendance.course_id == course_id,
                    Attendance.student_id == student_number,
                    Attendance.attendance_date == today_date
                )
            )
        )
        attendance_data = result.scalars()

    return render_template('student_give_attendance.html', course_id=course_id, student_id=current_user.id)


@app.route('/video_feed_attendance')
@login_required
def video_feed_attendance():
    mimetype = 'multipart/x-mixed-replace; boundary=frame'
    return Response(generate_frames_attendance(current_user.id), mimetype=mimetype)


@app.route('/stop_video_capture_attendance', methods=['POST'])
def stop_video_capture_attendance():
    video_capture_active = False
    return jsonify({'status': 'success', 'message': 'Attendance Successful!'}), 200


@app.route('/attendance_success', methods=["POST"])
def attendance_success():
    video_capture_active = False
    student_id = current_user.user_id
    detected_id = global_data.get("detected_userID")
    course_id = global_data.get("courseID")

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

    if detected_id == student_id:
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
            # return redirect(url_for('student_course', course_id=course_id, student_id=current_user.id))
            return jsonify({'message': 'Attendance given successfully!'})
        else:
            return jsonify({'message': 'Attendance record not found'}), 400
    else:
        return jsonify({'message': 'Another person detected!'})


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

    # Get the course name
    course = Courses.query.filter_by(id=course_id).first()
    if not course:
        return jsonify({'error': 'Course not found'}), 404
    course_name = course.course_name

    # Get today's date
    today_date = date.today()

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
            'student_id': f"'{student_id}'",  # Prevent scientific notation
            'days_present': days_present,
            'days_absent': days_absent
        })

        # Create CSV
        si = StringIO()
        writer = csv.writer(si)
        # Write header with empty columns between each actual column
        writer.writerow(['Full Name', '', 'Student ID', '', 'Days Present', '', 'Days Absent', ''])
        for record in attendance_report:
            writer.writerow(
                [record['full_name'], '', record['student_id'], '', record['days_present'], '', record['days_absent'],
                 ''])

    # Construct filename
    filename = f"{course_name}_attendance_report_{today_date}.csv"

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename={filename}"
    output.headers["Content-type"] = "text/csv"
    return output


@app.route('/upload_enrolled_courses', methods=['POST'])
def upload_enrolled_courses():
    course_id = request.form.get('course_id')

    # Validate course_id
    if not course_id:
        return jsonify({'error': 'Missing course_id parameter'}), 400

    # Check if file part is in the request
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    # Check if a file was selected
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Check if the file is a CSV
    if file and file.filename.endswith('.csv'):
        try:
            # Parse the CSV file
            file_str = StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_data = csv.reader(file_str)

            # Check the header row
            header = next(csv_data, None)
            if header is None or header[0].strip().lower() != 'full name' or header[1].strip().lower() != 'student id':
                return jsonify({'error': 'Invalid CSV format. Must contain "Full name" and "Student ID" columns.'}), 400

            # Store the data from the CSV file and check for duplicates
            student_data = []
            student_ids = set()
            for row in csv_data:
                if len(row) < 2:
                    continue  # Skip rows that don't have enough columns
                full_name = row[0].strip()
                student_id = row[1].strip()

                if student_id in student_ids:
                    return jsonify({'error': f'Duplicate student ID found: {student_id}'}), 400

                student_ids.add(student_id)
                student_data.append({'full_name': full_name, 'student_id': student_id})

            return jsonify({'success': 'File uploaded successfully', 'data': student_data}), 200

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    else:
        return jsonify({'error': 'Invalid file type. Please upload a CSV file'}), 400


@app.route('/delete_course', methods=['POST'])
def delete_course():
    data = request.get_json()
    course_id = data.get('course_id')
    print(course_id)

    # Perform deletion logic here
    try:
        # Delete rows from EnrolledCourses table
        enrolled_courses = db.session.query(EnrolledCourses).filter_by(course_id=course_id).all()
        for enrolled_course in enrolled_courses:
            db.session.delete(enrolled_course)

        # Delete rows from Attendance table
        attendance_records = db.session.query(Attendance).filter_by(course_id=course_id).all()
        for attendance in attendance_records:
            db.session.delete(attendance)

        # Delete row from Courses table
        course = db.session.query(Courses).filter_by(id=course_id).first()
        if course:
            db.session.delete(course)

        # Commit the changes
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()  # Rollback the session in case of error
        return jsonify({'success': False, 'error': str(e)})


if __name__ == "__main__":
    app.run(debug=True)

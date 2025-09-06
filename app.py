from operator import or_
from flask import Flask, flash, render_template, request, redirect, session, jsonify, send_file, url_for, make_response, abort
from sqlalchemy.orm import joinedload
from werkzeug.utils import secure_filename
import os
import io
import csv
import base64
from datetime import date, datetime, timedelta, time
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import numpy as np
import face_recognition
from password_validator import PasswordValidator
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import BYTEA
from collections import defaultdict

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['MAX_CONTENT_LENGTH'] = 3 * 1024 * 1024  # 3 MB upload cap

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('POSTGRES_URL', 'postgresql://postgres:postgres@localhost:5432/project')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Setup limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)


# Password schema
password_schema = PasswordValidator()
password_schema \
    .min(8) \
    .max(100) \
    .has().uppercase() \
    .has().lowercase() \
    .has().digits() \
    .has().no().spaces()

class User(db.Model):
    __tablename__ = 'users'
    email = db.Column(db.String(255), primary_key=True)
    fname = db.Column(db.String(100), nullable=False)
    lname = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    photo = db.Column(BYTEA, nullable=False)
    embedding = db.Column(db.LargeBinary, nullable=True)
    present = db.Column(db.Boolean, default=False)
    faculty = db.Column(db.String(100), nullable=True)
    role = db.Column(db.String(50), nullable=False)

    organized_meetings = db.relationship(
        'Meeting',
        back_populates='organizer',
        foreign_keys='Meeting.organizer_email'
    )
    meeting_participations = db.relationship('MeetingParticipant', backref='user')

class Room(db.Model):
    __tablename__ = 'rooms'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)


class Meeting(db.Model):
    __tablename__ = 'meetings'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    organizer_email = db.Column(db.String(255), db.ForeignKey('users.email'), nullable=False)

    room = db.relationship('Room', backref='meetings')
    organizer = db.relationship(
        'User',
        foreign_keys=[organizer_email],
        back_populates='organized_meetings',
        overlaps="organizer_user"
    )

    participants = db.relationship(
        'MeetingParticipant',
        backref='meeting',
        cascade='all, delete-orphan',
        passive_deletes=True
    )

    attendances = db.relationship(
        'Attendance',
        back_populates='meeting',
        cascade='all, delete-orphan',
        passive_deletes=True
    )

class MeetingParticipant(db.Model):
    __tablename__ = 'meeting_participants'
    id = db.Column(db.Integer, primary_key=True)

    meeting_id = db.Column(
        db.Integer,
        db.ForeignKey('meetings.id', ondelete='CASCADE'),
        nullable=False
    )

    user_email = db.Column(
        db.String(255),
        db.ForeignKey('users.email'),
        nullable=False
    )

class Attendance(db.Model):
    __tablename__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), db.ForeignKey('users.email'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    date = db.Column(db.Date, index=True, nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'), nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=True)

    # Add ondelete='CASCADE'
    meeting_id = db.Column(
        db.Integer,
        db.ForeignKey('meetings.id', ondelete='CASCADE'),
        nullable=True
    )
    
    room = db.relationship('Room', backref='attendances')
    meeting = db.relationship('Meeting', back_populates='attendances')

def normalize_email(email):
    return email.strip().lower()

@app.template_filter('b64encode')
def b64encode_filter(data):
    if data:
        return base64.b64encode(data).decode('utf-8')
    return ''

@app.route('/')
def home():
    return redirect('/login')

@app.errorhandler(429)
def ratelimit_handler(e):
    retry_after = getattr(e, 'retry_after', None)
    retry_after = int(retry_after) if retry_after is not None else 60
    path = request.path

    if path == '/login':
        response = make_response(
            render_template('login.html', error_message=f"Too many login attempts. Please try again in {retry_after} seconds.", retry_after=retry_after)
        )
        return response, 429
    elif path == '/register':
        response = make_response(
            render_template('register.html', error_message=f"Too many registration attempts. Please try again in {retry_after} seconds.", retry_after=retry_after)
        )
        return response, 429
    else:
        return jsonify(error="Too many requests. Please try again later."), 429

def login_required(f):
    """Decorator to check if user is logged in."""
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        email_input = request.form['email'].strip()
        password = request.form['password']
        mode = request.form.get('mode', '').strip().lower()

        normalized_email = normalize_email(email_input)
        user = User.query.filter_by(email=normalized_email).first()

        if not user:
            flash('User not found. Please check your email.', 'error')
            return redirect('/login')

        if not check_password_hash(user.password, password):
            flash('Incorrect password. Please try again.', 'error')
            return redirect('/login')

        # Set session
        session['user'] = user.email
        session['role'] = user.role
        session['is_teacher'] = (user.role == 'teacher')

        # Redirect based on mode
        if mode == 'admin':
            if user.role == 'teacher':
                return redirect('/student_records')
            else:
                flash('Only teachers can access the admin panel.', 'error')
                return redirect('/login')

        elif mode == 'attendance':
            if user.role in ['teacher', 'student']:
                return redirect('/attendance')
            else:
                flash('Invalid role for attendance panel.', 'error')
                return redirect('/login')

        else:
            flash('Invalid mode selected.', 'error')
            return redirect('/login')

    else:
        # GET request
        return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/check_face', methods=['POST'])
def check_face():
    data = request.get_json() or {}
    email = normalize_email(data.get('email', ''))
    img_b64 = data.get('image', '').split(',', 1)[-1]

    try:
        img_bytes = base64.b64decode(img_b64)
        pil_img = Image.open(io.BytesIO(img_bytes)).convert('RGB')
    except Exception:
        return jsonify({"message": "Invalid image data"}), 400

    unk_encs = face_recognition.face_encodings(np.array(pil_img))
    if not unk_encs:
        return jsonify({"message": "⚠️ No face detected."}), 400
    unk_enc = unk_encs[0]

    # check faces in db, skip the email user
    users = User.query.filter(User.email != email).all()
    for u in users:
        try:
            known_img_pil = Image.open(io.BytesIO(u.photo)).convert('RGB')
            known_img_np = np.array(known_img_pil)
            known_encs = face_recognition.face_encodings(known_img_np)
            if not known_encs:
                continue
            dist = face_recognition.face_distance([known_encs[0]], unk_enc)[0]
            if dist < 0.5:
                return jsonify({"exists": True})
        except Exception:
            continue

    return jsonify({"exists": False})

@app.route('/delete_user', methods=['POST'])
def delete_user():
    if 'user' not in session or not session.get('is_teacher'):
        return jsonify({'status': 'error', 'message': 'Unauthorized: Admin access required.'}), 401

    current_user_email = session['user']

    data = request.get_json(silent=True)
    email = normalize_email(data.get('email', '')) if data else normalize_email(request.form.get('email', ''))

    if not email:
        return jsonify({'status': 'error', 'message': 'Please provide an email.'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404

    if user.role == 'teacher' and email != current_user_email:
        return jsonify({'status': 'error', 'message': 'You can only delete your own teacher account.'}), 403

    try:
        Attendance.query.filter_by(email=email).delete()

        if user.role == 'teacher':
            meetings = Meeting.query.filter_by(organizer_email=email).all()
            for meeting in meetings:
                db.session.delete(meeting)
            MeetingParticipant.query.filter_by(user_email=email).delete()

        db.session.delete(user)
        db.session.commit()

        # If the deleted user is the logged-in user, log them out
        if email == current_user_email:
            session.clear()
            return jsonify({
                'status': 'success',
                'message': f'User {email} deleted successfully.',
                'logout': True
            })

        return jsonify({'status': 'success', 'message': f'User {email} deleted successfully.'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Error deleting user: {str(e)}'}), 500


@app.route('/add_room', methods=['GET', 'POST'])
def add_room():
    if request.method == 'POST':
        name = request.form['name'].strip()

        # Check if room already exists
        existing_room = Room.query.filter_by(name=name).first()
        if existing_room:
            flash('Room already exists.', 'warning')
            return redirect(url_for('teacher_records'))

        new_room = Room(name=name)
        db.session.add(new_room)
        db.session.commit()

        flash('Room added successfully!', 'success')
        return redirect(url_for('teacher_records'))

    return redirect(url_for('teacher_records'))  # No GET form here; it's on the dashboard already

@app.route('/edit_room/<int:room_id>', methods=['POST'])
def edit_room(room_id):
    room = Room.query.get_or_404(room_id)
    new_name = request.form.get('name')
    if new_name:
        room.name = new_name
        db.session.commit()
        flash('Room updated successfully!', 'success')
    else:
        flash('Room name cannot be empty.', 'danger')
    return redirect(url_for('teacher_records'))  # Adjust this to your dashboard route

@app.route('/delete_room/<int:room_id>', methods=['POST'])
def delete_room(room_id):
    room = Room.query.get_or_404(room_id)

    # Check if any meetings are scheduled in this room
    meetings_in_room = Meeting.query.filter_by(room_id=room_id).first()
    if meetings_in_room:
        flash("You can't delete this room because there are meetings scheduled here.", "danger")
        return redirect(url_for('teacher_records'))  # or the appropriate page

    try:
        db.session.delete(room)
        db.session.commit()
        flash("Room deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting room: {str(e)}", "danger")

    return redirect(url_for('teacher_records'))


@app.route('/add_meeting', methods=['POST'])
def add_meeting():
    if 'user' not in session or not session.get('is_teacher'):
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))

    title = request.form['title']
    room_id = int(request.form['room_id'])
    date_str = request.form['date']
    start_time_str = request.form['start_time']
    end_time_str = request.form['end_time']
    invited_user_emails = request.form.getlist('invited_users')

    organizer_email = session['user']  # Automatically use logged-in user's email

    # Parse date/time
    try:
        meeting_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        meeting_start = datetime.strptime(f"{date_str} {start_time_str}", '%Y-%m-%d %H:%M').time()
        meeting_end = datetime.strptime(f"{date_str} {end_time_str}", '%Y-%m-%d %H:%M').time()
    except ValueError:
        flash("Invalid date or time format.", "error")
        return redirect(url_for('teacher_records'))

    if meeting_start >= meeting_end:
        flash("End time must be after start time.", "error")
        return redirect(url_for('teacher_records'))

    # Check for time conflicts in the same room
    conflict = Meeting.query.filter(
        Meeting.room_id == room_id,
        Meeting.date == meeting_date,
        Meeting.start_time < meeting_end,
        Meeting.end_time > meeting_start
    ).first()

    if conflict:
        flash(f"Time conflict with another meeting from {conflict.start_time.strftime('%H:%M')} to {conflict.end_time.strftime('%H:%M')}.", "error")
        return redirect(url_for('teacher_records'))

    # Create meeting
    meeting = Meeting(
        title=title,
        room_id=room_id,
        date=meeting_date,
        start_time=meeting_start,
        end_time=meeting_end,
        organizer_email=organizer_email
    )
    db.session.add(meeting)
    db.session.commit()

    # Add participants (including organizer)
    participants_emails = set(invited_user_emails)
    participants_emails.add(organizer_email)

    for email in participants_emails:
        db.session.add(MeetingParticipant(meeting_id=meeting.id, user_email=email))

    db.session.commit()

    flash("✅ Meeting scheduled successfully!", "success")
    return redirect(url_for('teacher_records'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register():
    if request.method == 'POST':
        fname = request.form['fname'].strip()
        lname = request.form['lname'].strip()
        email = normalize_email(request.form['email'])
        password = request.form['password']
        faculty = request.form.get('faculty', '').strip()
        role = request.form.get('role', '').strip().lower()  # teacher/student/admin

        # Validate role
        if role not in ['teacher', 'student', 'admin']:
            return jsonify({"message": "❌ Role must be either 'teacher', 'student', or 'admin'."}), 400

        # Teacher verification
        if role == 'teacher':
            submitted_code = request.form.get('teacher_code', '').strip()
            REQUIRED_TEACHER_CODE = 'SCHOOL2024'
            if submitted_code != REQUIRED_TEACHER_CODE:
                return jsonify({"message": "❌ Invalid or missing teacher verification code."}), 403

        # Validate password
        if not password_schema.validate(password):
            return jsonify({"message": "❌ Password must be 8+ chars, with uppercase, lowercase, digits, and no spaces."}), 400

        # Check if user exists
        if User.query.filter_by(email=email).first():
            return jsonify({"message": "❌ User with this email already exists."}), 400

        # Load photo
        file = request.files.get('photo_file')
        if file and file.filename:
            img_bytes = file.read()
        else:
            b64 = request.form.get('photoData', '')
            if ',' in b64:
                b64 = b64.split(',', 1)[1]
            try:
                img_bytes = base64.b64decode(b64)
            except Exception:
                return jsonify({"message": "❌ Invalid photo data."}), 400

        # Face recognition: detect face and save embedding
        try:
            img = Image.open(io.BytesIO(img_bytes)).convert('RGB')
            encs = face_recognition.face_encodings(np.array(img))
            if not encs:
                return jsonify({"message": "❌ No face detected in photo."}), 400

            embedding_vector = encs[0]  # 128D numpy array
            embedding_bytes = embedding_vector.tobytes()  # store as binary
        except Exception:
            return jsonify({"message": "❌ Error processing face data."}), 400

        pw_hash = generate_password_hash(password)

        new_user = User(
            email=email,
            fname=fname,
            lname=lname,
            password=pw_hash,
            embedding=embedding_bytes,
            photo=img_bytes,
            present=False,
            faculty=faculty if faculty else None,
            role=role
        )
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "✅ Registered successfully! You can now log in."})

    return render_template('register.html')

@app.route('/attendance')
@login_required
def attendance():
    if 'user' not in session or session.get('is_admin'):
        return redirect('/login')

    user_email = session['user'].strip().lower()

    today = date.today()

    # Fetch meetings for today and future where user is a participant
    meetings = (
        db.session.query(Meeting)
        .join(MeetingParticipant, Meeting.id == MeetingParticipant.meeting_id)
        .filter(
            MeetingParticipant.user_email == user_email,
            Meeting.date >= today
        )
        .order_by(Meeting.date, Meeting.start_time)
        .all()
    )

    for m in meetings:
        print(f"- {m.date}: {m.title} at {m.start_time} in room {m.room_id}")

    rooms = Room.query.order_by(Room.name).all()

    return render_template(
        'attendance.html',
        user=user_email,
        rooms=rooms,
        meetings=meetings,
        selected_meeting_id=None,
        selected_room_id=None
    )

def get_current_hour_interval(t: time):
    start_hour = t.replace(minute=0, second=0, microsecond=0)
    end_hour = time((start_hour.hour + 1) % 24, 0, 0)
    return start_hour, end_hour

def format_embedding(embedding):
    return [round(float(x), 3) for x in embedding]

@app.route('/mark_attendance', methods=['POST'])
@login_required
def mark_attendance():
    if 'user' not in session:
        return jsonify({"message": "Unauthorized"}), 401

    user_email = normalize_email(session['user'])
    data = request.get_json()
    if not data or 'image' not in data or 'room' not in data:
        return jsonify({"message": "Missing required data"}), 400

    room_id = data.get('room')
    meeting_id = data.get('meeting')  # optional
    now = datetime.now()
    today_date = now.date()
    current_time = now.time()

    # Validate room
    try:
        room = Room.query.get(int(room_id))
        if not room:
            return jsonify({"message": "Invalid room selected"}), 400
    except Exception:
        return jsonify({"message": "Invalid room data"}), 400

    # Validate user
    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({"message": "❌ You are not registered, please register first!"}), 404
    if not user.embedding:
        return jsonify({"message": "❌ No face embedding found for user.", "status": "failed"}), 400

    # Decode and process current image
    try:
        img_bytes = base64.b64decode(data['image'].split(',')[1])
        pil_img = Image.open(io.BytesIO(img_bytes)).convert('RGB')
        np_img = np.array(pil_img)
    except Exception:
        return jsonify({"message": "Invalid image data"}), 400

    encodings = face_recognition.face_encodings(np_img)
    if not encodings:
        return jsonify({"message": "⚠️ Face not detected. Make sure your face is clearly visible."}), 400

    user_enc = encodings[0]

    # Use saved embedding
    registered_embedding = np.frombuffer(user.embedding, dtype=np.float64)
    dist = face_recognition.face_distance([registered_embedding], user_enc)[0]

    if dist >= 0.5:
        return jsonify({
            "message": f"❌ Face not recognized. You’re logged in as {user.fname} {user.lname} but your face does not match.",
            "distance": float(dist),
            "registered_embedding": format_embedding(registered_embedding.tolist()),
            "captured_embedding":format_embedding(user_enc.tolist()),
            "status": "failed"
        }), 403

    # --- MEETING MODE ---
    if meeting_id:
        meeting = Meeting.query.get(int(meeting_id))
        if not meeting:
            return jsonify({"message": "Invalid meeting selected", "distance": float(dist), "status": "failed"}), 400

        if meeting.date != today_date:
            return jsonify({"message": "⚠️ You can only mark attendance on the meeting date.", "distance": float(dist), "status": "failed"}), 400

        if current_time < meeting.start_time:
            return jsonify({
                "message": f"⚠️ Attendance not open yet. Meeting starts at {meeting.start_time.strftime('%H:%M')}.",
                "distance": float(dist),
                "status": "failed"
            }), 400

        if current_time > meeting.end_time:
            return jsonify({
                "message": f"⚠️ Meeting already ended at {meeting.end_time.strftime('%H:%M')}.",
                "distance": float(dist),
                "status": "failed"
            }), 400

        existing = Attendance.query.filter_by(
            email=user_email,
            date=today_date,
            meeting_id=meeting.id
        ).first()

        if existing:
            return jsonify({
                "message": "✅ You are already marked present!",
                "distance": float(dist),
                "registered_embedding": format_embedding(registered_embedding.tolist()),
                "captured_embedding":format_embedding(user_enc.tolist()),
                "status": "success"
            })

        new_attendance = Attendance(
            email=user_email,
            timestamp=now,
            date=today_date,
            room_id=meeting.room_id,
            meeting_id=meeting.id,
            start_time=meeting.start_time,
            end_time=meeting.end_time
        )
        room_name = meeting.room.name

    # --- ROOM-ONLY MODE ---
    else:
        start_hour, end_hour = get_current_hour_interval(current_time)

        existing_user_attendance = Attendance.query.filter_by(
            email=user_email,
            date=today_date,
            room_id=room.id,
            meeting_id=None,
            start_time=start_hour,
            end_time=end_hour
        ).first()

        if existing_user_attendance:
            return jsonify({
                "message": "✅ You are already marked present in this time slot!",
                "distance": float(dist),
                "registered_embedding": format_embedding(registered_embedding.tolist()),
                "captured_embedding":format_embedding(user_enc.tolist()),
                "status": "success"
            })

        new_attendance = Attendance(
            email=user_email,
            timestamp=now,
            date=today_date,
            room_id=room.id,
            meeting_id=None,
            start_time=start_hour,
            end_time=end_hour
        )
        room_name = room.name

    # Finalize
    user.present = True
    db.session.add(new_attendance)
    db.session.commit()

    return jsonify({
        "message": f"✅ Attendance marked successfully in {room_name}!",
        "distance": float(dist),
        "registered_embedding": format_embedding(registered_embedding.tolist()),
        "captured_embedding":format_embedding(user_enc.tolist()),
        "status": "success"
    })



@app.route('/teacher_records', methods=['GET'])
@login_required  # Add if required
def teacher_records():
    selected_faculty = request.args.get('faculty', '')
    selected_date = request.args.get('date', '')

    rooms = Room.query.all()
    users = User.query.all()

    # Extract distinct faculties from users (skip None or empty)
    faculties = sorted(set(user.faculty for user in users if user.faculty))

    query = Meeting.query.join(Meeting.organizer)

    if selected_faculty:
        query = query.filter(User.faculty == selected_faculty)

    if selected_date:
        try:
            filter_date = datetime.strptime(selected_date, '%Y-%m-%d').date()
            query = query.filter(Meeting.date == filter_date)
        except ValueError:
            flash("Invalid date format.", "warning")

    meetings = query.order_by(Meeting.date.desc(), Meeting.start_time).all()

    return render_template(
        'teacher_records.html',
        meetings=meetings,
        rooms=rooms,
        users=users,
        faculties=faculties,
        selected_faculty=selected_faculty,
        selected_date=selected_date
    )

@app.route('/edit_meeting/<int:meeting_id>', methods=['POST'])
@login_required
def edit_meeting(meeting_id):
    meeting = Meeting.query.get_or_404(meeting_id)

    title = request.form.get('title')
    room_id = request.form.get('room_id')
    date_str = request.form.get('date')
    start_time_str = request.form.get('start_time')
    end_time_str = request.form.get('end_time')
    organizer_email = request.form.get('organizer_email')
    invited_users = request.form.getlist('invited_users')

    try:
        # Validate mandatory fields presence
        if not all([title, room_id, date_str, start_time_str, end_time_str, organizer_email]):
            flash("Missing required form fields.", "error")
            return redirect(url_for('teacher_records'))

        # Parse date and times
        meeting_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        meeting_start = datetime.strptime(start_time_str, '%H:%M').time()
        meeting_end = datetime.strptime(end_time_str, '%H:%M').time()

        if meeting_start >= meeting_end:
            flash("End time must be after start time.", "error")
            return redirect(url_for('teacher_records'))

        # Check for conflicts excluding current meeting
        conflict = Meeting.query.filter(
            Meeting.room_id == int(room_id),
            Meeting.date == meeting_date,
            Meeting.id != meeting.id,
            Meeting.start_time < meeting_end,
            Meeting.end_time > meeting_start
        ).first()

        if conflict:
            flash(f"Time conflict with meeting from {conflict.start_time} to {conflict.end_time}", "error")
            return redirect(url_for('teacher_records'))

        # Update meeting fields
        meeting.title = title
        meeting.room_id = int(room_id)
        meeting.date = meeting_date
        meeting.start_time = meeting_start
        meeting.end_time = meeting_end
        meeting.organizer_email = organizer_email

        # Delete old participants
        for participant in meeting.participants[:]:
            db.session.delete(participant)

        # Add new participants (ensure uniqueness)
        participants_emails = set(invited_users)
        participants_emails.add(organizer_email)

        for email in participants_emails:
            # Optional: Validate user exists before adding participant
            user = User.query.filter_by(email=email).first()
            if user:
                participant = MeetingParticipant(meeting_id=meeting.id, user_email=email)
                db.session.add(participant)
            else:
                flash(f"User with email {email} does not exist.", "warning")

        db.session.commit()
        flash('Meeting updated successfully.', 'success')

    except Exception as e:
        db.session.rollback()
        # Log error for debugging (print to console or use logging)
        print(f"Exception in edit_meeting: {e}")
        flash(f'Failed to update meeting: {str(e)}', 'danger')

    return redirect(url_for('teacher_records'))

@app.route('/delete_meeting/<int:meeting_id>', methods=['POST'])
@login_required
def delete_meeting(meeting_id):
    meeting = Meeting.query.get_or_404(meeting_id)
    try:
        db.session.delete(meeting)
        db.session.commit()
        flash('Meeting deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Failed to delete meeting: {str(e)}', 'danger')
    return redirect(url_for('teacher_records'))

@app.route('/student_records')
def student_reg():
    if 'user' not in session or not session.get('is_teacher'):
        return redirect('/login')

    selected_date_str = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))
    try:
        selected_date = datetime.strptime(selected_date_str, '%Y-%m-%d').date()
    except Exception:
        selected_date = datetime.now().date()

    selected_faculty = request.args.get('faculty', '').strip()
    selected_room_id = request.args.get('room_id', '').strip()
    selected_meeting_id = request.args.get('meeting_id', '').strip()

    # Base query for attendance by date
    attendance_query = Attendance.query.filter_by(date=selected_date)

    if selected_room_id:
        attendance_query = attendance_query.filter(Attendance.room_id == int(selected_room_id))
    if selected_meeting_id:
        attendance_query = attendance_query.filter(Attendance.meeting_id == int(selected_meeting_id))

    attendance_records = attendance_query.all()
    present_emails = {rec.email for rec in attendance_records}

    # Query users filtered by faculty if selected
    if selected_faculty:
        users = User.query.filter(User.faculty == selected_faculty).all()
    else:
        users = User.query.all()

    attendance_by_faculty = defaultdict(lambda: {'present': [], 'absent': []})

    for user in users:
        if user.email in present_emails:
            attendance_by_faculty[user.faculty]['present'].append(user)
        else:
            attendance_by_faculty[user.faculty]['absent'].append(user)

    # Get unique faculties for dropdown
    faculties = (
        db.session.query(User.faculty)
        .distinct()
        .order_by(User.faculty)
        .all()
    )
    faculties = [f[0] for f in faculties if f[0]]

    # Get rooms and meetings for dropdowns
    rooms = Room.query.order_by(Room.name).all()
    meetings = Meeting.query.order_by(Meeting.title).all()

    return render_template(
        'student_records.html',
        attendance_by_faculty=attendance_by_faculty,
        selected_date=selected_date.strftime('%Y-%m-%d'),
        selected_faculty=selected_faculty,
        selected_room_id=selected_room_id,
        selected_meeting_id=selected_meeting_id,
        faculties=faculties,
        rooms=rooms,
        meetings=meetings,
        datetime=datetime,
    )

@app.route('/download_csv')
def download_csv():
    if 'user' not in session or not session.get('is_teacher'):
        return redirect('/login')

    # Get filters from query params
    date_str = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))
    selected_faculty = request.args.get('faculty', '').strip()
    meeting_id = request.args.get('meeting_id', type=int)
    room_id = request.args.get('room_id', type=int)
    start_time_str = request.args.get('start_time')
    end_time_str = request.args.get('end_time')

    # Parse date
    try:
        date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except Exception:
        return jsonify({"message": "Invalid date format"}), 400

    # Query attendance for given date
    attendance_query = Attendance.query.filter_by(date=date)

    # Apply filters
    if meeting_id:
        attendance_query = attendance_query.filter(Attendance.meeting_id == meeting_id)

    if room_id:
        attendance_query = attendance_query.filter(Attendance.room_id == room_id)

    if start_time_str and end_time_str:
        try:
            start_time = datetime.strptime(start_time_str, '%H:%M').time()
            end_time = datetime.strptime(end_time_str, '%H:%M').time()
            attendance_query = attendance_query.filter(
                Attendance.start_time >= start_time,
                Attendance.end_time <= end_time
            )
        except Exception:
            return jsonify({"message": "Invalid time format"}), 400

    attendance_records = attendance_query.all()
    present_emails = {rec.email for rec in attendance_records}
    attendance_map = {rec.email: rec for rec in attendance_records}

    # Filter users optionally by faculty
    user_query = User.query
    if selected_faculty:
        user_query = user_query.filter(User.faculty == selected_faculty)

    users = user_query.all()

    # Generate CSV
    sio = io.StringIO()
    writer = csv.writer(sio)
    writer.writerow([
        'First Name', 'Last Name', 'Email', 'Faculty', 'Role', 'Status',
        'Meeting Topic', 'Room Name', 'Start Time', 'End Time', 'Timestamp'
    ])

    for u in users:
        status = 'Present' if u.email in present_emails else 'Absent'
        att = attendance_map.get(u.email)

        meeting_title = att.meeting.title if att and att.meeting else ''
        room_name = att.room.name if att and att.room else ''
        start_time_val = att.start_time.strftime('%H:%M') if att and att.start_time else ''
        end_time_val = att.end_time.strftime('%H:%M') if att and att.end_time else ''
        timestamp = att.timestamp.strftime('%H:%M:%S') if att and att.timestamp else ''

        writer.writerow([
            u.fname, u.lname, u.email, u.faculty or '', u.role, status,
            meeting_title, room_name, start_time_val, end_time_val, timestamp
        ])

    # Return CSV as attachment
    sio.seek(0)
    return send_file(
        io.BytesIO(sio.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'attendance_{date.strftime("%Y_%m_%d")}.csv'
    )

@app.route('/student_records/edit_user/<email>', methods=['POST'])
def edit_user(email):
    if 'user' not in session or not session.get('is_teacher'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    email = email.lower()
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'status': 'error', 'message': 'Student not found.'})

    fname = request.form.get('fname', '').strip()
    lname = request.form.get('lname', '').strip()
    new_password = request.form.get('password', '').strip()

    if not fname or not lname:
        return jsonify({'status': 'error', 'message': 'First and last name cannot be empty.'})

    if new_password:
        user.password = generate_password_hash(new_password)

    user.fname = fname
    user.lname = lname

    file = request.files.get('photo_file')
    if file and file.filename:
        try:
            img_bytes = file.read()
            img = Image.open(io.BytesIO(img_bytes)).convert('RGB')
            encs = face_recognition.face_encodings(np.array(img))
            if not encs:
                return jsonify({'status': 'error', 'message': 'No face detected in the uploaded photo.'})

            new_enc = encs[0]

            if user.photo:
                try:
                    existing_img = face_recognition.load_image_file(io.BytesIO(user.photo))
                    existing_encs = face_recognition.face_encodings(existing_img)
                    if existing_encs:
                        existing_enc = existing_encs[0]
                        dist = face_recognition.face_distance([existing_enc], new_enc)[0]
                        if dist > 0.5:
                            return jsonify({'status': 'error', 'message': 'Uploaded photo does not match your current photo.'})
                    else:
                        return jsonify({'status': 'error', 'message': 'No face found in existing photo.'})
                except Exception:
                    return jsonify({'status': 'error', 'message': 'Error processing existing photo.'})

            user.photo = img_bytes
        except Exception:
            return jsonify({'status': 'error', 'message': 'Invalid image uploaded.'})

    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Updated successfully.'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)

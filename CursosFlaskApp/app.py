from flask import Flask, render_template, redirect, url_for, request, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'clave_secreta_para_sesiones'

def get_db_connection():
    conn = sqlite3.connect('CursosFlask.sqlite')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def inicio():
    return render_template('inicio.html')


@app.route('/login_alumno', methods=['GET', 'POST'])
def login_alumno():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        contraseña = request.form.get('contraseña', '').strip()

        # Validación de campos vacíos
        if not email or not contraseña:
            error = 'Todos los campos son obligatorios.'
            return render_template('login_alumno.html', error=error)

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM Alumnos WHERE email = ?', (email,))
                alumno = cursor.fetchone()

                # Verificar credenciales
                if alumno and check_password_hash(alumno['contraseña'], contraseña):
                    # Guardar información en la sesión
                    session['alumno_id'] = alumno['id']
                    session['alumno_nombre'] = alumno['nombre']
                    return redirect(url_for('ver_cursos'))
                else:
                    error = 'Email o contraseña incorrectos.'
                    return render_template('login_alumno.html', error=error)

        except sqlite3.Error as e:
            # Registrar el error en la consola o en un archivo de logs
            print(f"Error de base de datos: {e}")
            error = 'Ocurrió un error al iniciar sesión. Inténtalo de nuevo más tarde.'
            return render_template('login_alumno.html', error=error)

    return render_template('login_alumno.html')


@app.route('/registro_alumno', methods=['GET', 'POST'])
def registro_alumno():
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        email = request.form.get('email', '').strip()
        contraseña = request.form.get('contraseña', '').strip()

        # Validación de datos
        if not nombre or not email or not contraseña:
            error = 'Todos los campos son obligatorios.'
            return render_template('registro_alumno.html', error=error)

        if len(contraseña) < 8:
            error = 'La contraseña debe tener al menos 8 caracteres.'
            return render_template('registro_alumno.html', error=error)

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()

                # Verificamos si el email ya está registrado
                cursor.execute('SELECT * FROM Alumnos WHERE email = ?', (email,))
                alumno = cursor.fetchone()

                if alumno:
                    error = 'Ya existe un alumno registrado con este email.'
                    return render_template('registro_alumno.html', error=error)

                # Guardamos el alumno
                hash_pw = generate_password_hash(contraseña)
                cursor.execute('INSERT INTO Alumnos (nombre, email, contraseña) VALUES (?, ?, ?)',
                               (nombre, email, hash_pw))
                conn.commit()

            return redirect(url_for('login_alumno'))

        except sqlite3.Error as e:
            # Registrar el error en la consola
            print(f"Error de base de datos: {e}")
            error = 'Ocurrió un error al registrar al alumno. Inténtalo de nuevo más tarde.'
            return render_template('registro_alumno.html', error=error)

    return render_template('registro_alumno.html')


@app.route('/login_admin', methods=['GET', 'POST'])
def login_admin():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        contraseña = request.form.get('contraseña', '').strip()

        # Validación de campos vacíos
        if not email or not contraseña:
            error = 'Todos los campos son obligatorios.'
            return render_template('login_admin.html', error=error)

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM Administradores WHERE email = ?', (email,))
                admin = cursor.fetchone()

                # Verificar credenciales
                if admin and check_password_hash(admin['contraseña'], contraseña):
                    session['admin_id'] = admin['id']
                    session['admin_nombre'] = admin['nombre']
                    return redirect(url_for('admin_dashboard'))
                else:
                    error = 'Email o contraseña incorrectos.'
                    return render_template('login_admin.html', error=error)

        except sqlite3.Error as e:
            print(f"Error de base de datos: {e}")
            error = 'Ocurrió un error al iniciar sesión. Inténtalo de nuevo más tarde.'
            return render_template('login_admin.html', error=error)

    return render_template('login_admin.html')


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        return redirect(url_for('login_admin'))

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Obtener todos los alumnos inscritos
            cursor.execute('SELECT * FROM Alumnos')
            alumnos = cursor.fetchall()

            # Obtener todos los cursos
            cursor.execute('SELECT * FROM Cursos')
            cursos = cursor.fetchall()

            # Obtener todos los profesores
            cursor.execute('SELECT * FROM Profesores')
            profesores = cursor.fetchall()

            # Obtener los cursos a los que los alumnos están inscritos
            cursor.execute('''
                SELECT Alumnos.nombre AS alumno_nombre, Cursos.nombre AS curso_nombre
                FROM Inscripciones
                INNER JOIN Alumnos ON Inscripciones.alumno_id = Alumnos.id
                INNER JOIN Cursos ON Inscripciones.curso_id = Cursos.id
            ''')
            inscripciones = cursor.fetchall()

        return render_template('admin_dashboard.html', alumnos=alumnos, cursos=cursos, profesores=profesores, inscripciones=inscripciones)

    except sqlite3.Error as e:
        print(f"Error de base de datos: {e}")
        return "Ocurrió un error al cargar el panel de administrador."


@app.route('/cursos')
def ver_cursos():
    if 'alumno_id' not in session:
        return redirect(url_for('login_alumno'))

    alumno_id = session['alumno_id']

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Consulta para obtener los cursos disponibles
            cursor.execute('''
                SELECT Cursos.id, Cursos.nombre AS curso_nombre, Profesores.nombre AS profesor_nombre
                FROM Cursos
                LEFT JOIN Profesores ON Cursos.profesor = Profesores.id
            ''')
            cursos = cursor.fetchall()
            print("Cursos disponibles:", cursos)

            # Consulta para obtener los cursos inscritos del alumno
            cursor.execute('''
                SELECT Cursos.id, Cursos.nombre AS curso_nombre
                FROM Cursos
                INNER JOIN Inscripciones ON Cursos.id = Inscripciones.curso_id
                WHERE Inscripciones.alumno_id = ?
            ''', (alumno_id,))
            cursos_inscritos = cursor.fetchall()

        return render_template('cursos.html', cursos=cursos, cursos_inscritos=cursos_inscritos)

    except sqlite3.Error as e:
        print(f"Error de base de datos: {e}")
        error = 'Ocurrió un error al cargar los cursos. Inténtalo de nuevo más tarde.'
        return render_template('cursos.html', error=error)
    

@app.route('/inscribirse/<int:curso_id>', methods=['POST'])
def inscribirse(curso_id):
    if 'alumno_id' not in session:
        return redirect(url_for('login_alumno'))

    alumno_id = session['alumno_id']

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Verificar si el alumno ya está inscrito en el curso
            cursor.execute('SELECT * FROM Inscripciones WHERE alumno_id = ? AND curso_id = ?', (alumno_id, curso_id))
            inscripcion = cursor.fetchone()

            if inscripcion:
                error = 'Ya estás inscrito en este curso.'
                return redirect(url_for('ver_cursos', error=error))

            # Inscribir al alumno en el curso
            cursor.execute('INSERT INTO Inscripciones (alumno_id, curso_id) VALUES (?, ?)', (alumno_id, curso_id))
            conn.commit()

        return redirect(url_for('ver_cursos'))

    except sqlite3.Error as e:
        print(f"Error de base de datos: {e}")
        error = 'Ocurrió un error al inscribirse en el curso. Inténtalo de nuevo más tarde.'
        return redirect(url_for('ver_cursos', error=error))


@app.route('/eliminar_curso/<int:curso_id>', methods=['POST'])
def eliminar_curso(curso_id):
    if 'admin_id' not in session:
        return redirect(url_for('login_admin'))

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM Cursos WHERE id = ?', (curso_id,))
            conn.commit()

        return redirect(url_for('admin_dashboard'))

    except sqlite3.Error as e:
        print(f"Error de base de datos: {e}")
        return "Ocurrió un error al eliminar el curso."


@app.route('/editar_curso/<int:curso_id>', methods=['GET', 'POST'])
def editar_curso(curso_id):
    if 'admin_id' not in session:
        return redirect(url_for('login_admin'))

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            if request.method == 'POST':
                nombre = request.form.get('nombre', '').strip()
                profesor_id = request.form.get('profesor_id', '').strip()
                cursor.execute('UPDATE Cursos SET nombre = ?, profesor_id = ? WHERE id = ?', (nombre, profesor_id, curso_id))
                conn.commit()
                return redirect(url_for('admin_dashboard'))

            cursor.execute('SELECT * FROM Cursos WHERE id = ?', (curso_id,))
            curso = cursor.fetchone()

        return render_template('editar_curso.html', curso=curso)

    except sqlite3.Error as e:
        print(f"Error de base de datos: {e}")
        return "Ocurrió un error al editar el curso."


@app.route('/editar_profesor/<int:profesor_id>', methods=['GET', 'POST'])
def editar_profesor(profesor_id):
    if 'admin_id' not in session:
        return redirect(url_for('login_admin'))

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            if request.method == 'POST':
                nombre = request.form.get('nombre', '').strip()
                cursor.execute('UPDATE Profesores SET nombre = ? WHERE id = ?', (nombre, profesor_id))
                conn.commit()
                return redirect(url_for('admin_dashboard'))

            cursor.execute('SELECT * FROM Profesores WHERE id = ?', (profesor_id,))
            profesor = cursor.fetchone()

        return render_template('editar_profesor.html', profesor=profesor)

    except sqlite3.Error as e:
        print(f"Error de base de datos: {e}")
        return "Ocurrió un error al editar el profesor."


@app.route('/agregar_curso', methods=['GET', 'POST'])
def agregar_curso():
    if 'admin_id' not in session:
        return redirect(url_for('login_admin'))

    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        profesor_nombre = request.form.get('profesor_nombre', '').strip()
        profesor_correo = request.form.get('profesor_correo', '').strip()

        # Validación de campos vacíos
        if not nombre or not profesor_nombre or not profesor_correo:
            error = 'Todos los campos son obligatorios.'
            return render_template('agregar_curso.html', error=error)

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()

                # Verificar si el profesor ya existe
                cursor.execute('SELECT id FROM Profesores WHERE nombre = ? AND correo = ?', (profesor_nombre, profesor_correo))
                profesor = cursor.fetchone()

                if profesor:
                    profesor = profesor['id']
                else:
                    # Insertar el nuevo profesor
                    cursor.execute('INSERT INTO Profesores (nombre, correo) VALUES (?, ?)', (profesor_nombre, profesor_correo))
                    profesor = cursor.lastrowid

                # Insertar el nuevo curso
                cursor.execute('INSERT INTO Cursos (nombre, profesor) VALUES (?, ?)', (nombre, profesor))
                conn.commit()

            return redirect(url_for('admin_dashboard'))

        except sqlite3.Error as e:
            print(f"Error de base de datos: {e}")
            error = 'Ocurrió un error al agregar el curso. Inténtalo de nuevo más tarde.'
            return render_template('agregar_curso.html', error=error)

    return render_template('agregar_curso.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('inicio'))

# Generar hash de contraseña para el administrador
hash_pw = generate_password_hash('admin123')  
# print(hash_pw)  # Comenta esta línea después de copiar el hash

# Importamos las bibliotecas necesarias
from flask import Flask, render_template, redirect, url_for, request
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta

# Creamos la aplicación Flask
app = Flask(__name__)
# Establecemos una clave secreta para manejar sesiones de usuario de forma segura
app.secret_key = 'clave_secreta_para_sesiones'

# Clave secreta para firmar los tokens JWT
JWT_SECRET = 'clave_secreta_para_jwt'
JWT_ALGORITHM = 'HS256'

# Función para conectar a la base de datos SQLite
def get_db_connection():
    # Creamos una conexión a la base de datos
    conn = sqlite3.connect('CursosFlask.sqlite')
    # Configuramos para que las filas se devuelvan como diccionarios
    conn.row_factory = sqlite3.Row
    return conn

# Función para generar un token JWT
def generar_token(datos):
    payload = {
        'exp': datetime.utcnow() + timedelta(hours=1),  # Expiración en 1 hora
        'iat': datetime.utcnow(),  # Fecha de emisión
        'sub': datos  # Datos del usuario
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

# Función para verificar un token JWT
def verificar_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return None  # Token expirado
    except jwt.InvalidTokenError:
        return None  # Token inválido

# Ruta principal de la aplicación
@app.route('/')
def inicio():
    return render_template('inicio.html')

# Modificar la ruta de login para alumnos
@app.route('/login_alumno', methods=['GET', 'POST'])
def login_alumno():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        contraseña = request.form.get('contraseña', '').strip()

        if not email or not contraseña:
            error = 'Todos los campos son obligatorios.'
            return render_template('login_alumno.html', error=error)

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM Alumnos WHERE email = ?', (email,))
                alumno = cursor.fetchone()

                if alumno and check_password_hash(alumno['contraseña'], contraseña):
                    # Generar token JWT
                    token = generar_token({'id': alumno['id'], 'nombre': alumno['nombre']})
                    return redirect(url_for('ver_cursos', token=token))
                else:
                    error = 'Email o contraseña incorrectos.'
                    return render_template('login_alumno.html', error=error)

        except sqlite3.Error as e:
            print(f"Error de base de datos: {e}")
            error = 'Ocurrió un error al iniciar sesión. Inténtalo de nuevo más tarde.'
            return render_template('login_alumno.html', error=error)

    return render_template('login_alumno.html')

# Ruta para registro de nuevos alumnos
@app.route('/registro_alumno', methods=['GET', 'POST'])
def registro_alumno():
    if request.method == 'POST':
        # Obtenemos los datos del formulario
        nombre = request.form.get('nombre', '').strip()
        email = request.form.get('email', '').strip()
        contraseña = request.form.get('contraseña', '').strip()

        # Validaciones básicas
        if not nombre or not email or not contraseña:
            error = 'Todos los campos son obligatorios.'
            return render_template('registro_alumno.html', error=error)

        # Verificamos longitud mínima de contraseña
        if len(contraseña) < 8:
            error = 'La contraseña debe tener al menos 8 caracteres.'
            return render_template('registro_alumno.html', error=error)

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()

                # Verificamos si el email ya existe
                cursor.execute('SELECT * FROM Alumnos WHERE email = ?', (email,))
                alumno = cursor.fetchone()

                if alumno:
                    error = 'Ya existe un alumno registrado con este email.'
                    return render_template('registro_alumno.html', error=error)

                # Hasheamos la contraseña antes de guardarla
                hash_pw = generate_password_hash(contraseña)
                # Insertamos el nuevo alumno
                cursor.execute('INSERT INTO Alumnos (nombre, email, contraseña) VALUES (?, ?, ?)',
                             (nombre, email, hash_pw))
                conn.commit()

            return redirect(url_for('login_alumno'))

        except sqlite3.Error as e:
            print(f"Error de base de datos: {e}")
            error = 'Ocurrió un error al registrar al alumno. Inténtalo de nuevo más tarde.'
            return render_template('registro_alumno.html', error=error)

    return render_template('registro_alumno.html')


# Ruta para el login del administrador
@app.route('/login_admin', methods=['GET', 'POST'])
def login_admin():
    # Comprobamos si la petición es POST (envío del formulario)
    if request.method == 'POST':
        # Obtenemos y limpiamos los datos del formulario
        email = request.form.get('email', '').strip()
        contraseña = request.form.get('contraseña', '').strip()

        # Validamos que los campos no estén vacíos
        if not email or not contraseña:
            error = 'Todos los campos son obligatorios.'
            return render_template('login_admin.html', error=error)

        try:
            # Conectamos con la base de datos
            with get_db_connection() as conn:
                cursor = conn.cursor()
                # Buscamos al administrador por su email
                cursor.execute('SELECT * FROM Administradores WHERE email = ?', (email,))
                admin = cursor.fetchone()

                # Verificamos las credenciales del administrador
                if admin and check_password_hash(admin['contraseña'], contraseña):
                    # Generar token JWT
                    token = generar_token({'id': admin['id'], 'nombre': admin['nombre']})
                    return redirect(url_for('admin_dashboard', token=token))
                else:
                    # Si las credenciales son incorrectas, mostramos error
                    error = 'Email o contraseña incorrectos.'
                    return render_template('login_admin.html', error=error)

        except sqlite3.Error as e:
            # Manejamos cualquier error de base de datos
            print(f"Error de base de datos: {e}")
            error = 'Ocurrió un error al iniciar sesión. Inténtalo de nuevo más tarde.'
            return render_template('login_admin.html', error=error)

    # Si la petición es GET, mostramos el formulario de login
    return render_template('login_admin.html')


# Modificar la ruta de admin_dashboard para pasar los datos del token al template
@app.route('/admin_dashboard')
def admin_dashboard():
    token = request.args.get('token')
    datos_usuario = verificar_token(token)

    if not datos_usuario:
        return redirect(url_for('login_admin'))

    try:
        # Establecemos conexión con la base de datos usando nuestro helper
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # SECCIÓN 1: OBTENCIÓN DE DATOS BÁSICOS
            # Recuperamos todos los alumnos de la base de datos
            cursor.execute('SELECT * FROM Alumnos')
            alumnos = cursor.fetchall()

            # Recuperamos todos los cursos disponibles
            cursor.execute('SELECT * FROM Cursos')
            cursos = cursor.fetchall()

            # Recuperamos la lista de profesores
            cursor.execute('SELECT * FROM Profesores')
            profesores = cursor.fetchall()

            # SECCIÓN 2: CONSULTA COMPLEJA DE INSCRIPCIONES
            # Hacemos un JOIN múltiple para obtener nombres de alumnos y cursos
            cursor.execute('''
                SELECT Alumnos.nombre AS alumno_nombre, Cursos.nombre AS curso_nombre
                FROM Inscripciones
                INNER JOIN Alumnos ON Inscripciones.alumno_id = Alumnos.id
                INNER JOIN Cursos ON Inscripciones.curso_id = Cursos.id
            ''')
            inscripciones = cursor.fetchall()

            # SECCIÓN 3: PROCESAMIENTO DE DATOS
            # Creamos un diccionario para organizar los cursos por alumno
            inscripciones_por_alumno = {}
            for inscripcion in inscripciones:
                alumno_nombre = inscripcion['alumno_nombre']
                curso_nombre = inscripcion['curso_nombre']
                # Si es la primera vez que vemos este alumno, inicializamos su lista
                if alumno_nombre not in inscripciones_por_alumno:
                    inscripciones_por_alumno[alumno_nombre] = []
                # Añadimos el curso a la lista de cursos del alumno
                inscripciones_por_alumno[alumno_nombre].append(curso_nombre)

        # SECCIÓN 4: RENDERIZADO
        # Enviamos todos los datos recopilados a la plantilla
        return render_template('admin_dashboard.html', 
                            alumnos=alumnos,           # Lista de todos los alumnos
                            cursos=cursos,            # Lista de todos los cursos
                            profesores=profesores,    # Lista de todos los profesores
                            inscripciones_por_alumno=inscripciones_por_alumno,  # Diccionario de inscripciones
                            jwt_payload=datos_usuario)  # Pasar datos del token al template

    except sqlite3.Error as e:
        # Manejo de errores de base de datos
        # Registramos el error para debugging
        print(f"Error de base de datos: {e}")
        # Mostramos un mensaje de error amigable al usuario
        return "Ocurrió un error al cargar el panel de administrador."

# SECCIÓN: VISUALIZACIÓN DE CURSOS
# Modificar la ruta de ver_cursos para pasar los datos del token al template
@app.route('/cursos')
def ver_cursos():
    token = request.args.get('token')
    datos_usuario = verificar_token(token)

    if not datos_usuario:
        return redirect(url_for('login_alumno'))

    alumno_id = datos_usuario['id']

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # CONSULTA 1: Obtener detalles de todos los cursos y sus profesores
            cursor.execute('''
                SELECT Cursos.id, Cursos.nombre AS curso_nombre, 
                       Cursos.descripcion, Profesores.nombre AS profesor_nombre
                FROM Cursos
                LEFT JOIN Profesores ON Cursos.profesor = Profesores.id
            ''')
            cursos = cursor.fetchall()

            # CONSULTA 2: Obtener los cursos en los que está inscrito el alumno
            cursor.execute('''
                SELECT Cursos.id
                FROM Cursos
                INNER JOIN Inscripciones ON Cursos.id = Inscripciones.curso_id
                WHERE Inscripciones.alumno_id = ?
            ''', (alumno_id,))
            cursos_inscritos = cursor.fetchall()

            # Creamos un conjunto para fácil verificación de inscripciones
            cursos_inscritos_ids = {curso['id'] for curso in cursos_inscritos}

        # Renderizamos la plantilla con todos los datos necesarios
        return render_template('cursos.html', 
                             cursos=cursos,  # Lista de todos los cursos
                             cursos_inscritos=cursos_inscritos,  # Lista de cursos inscritos
                             cursos_inscritos_ids=cursos_inscritos_ids,  # Conjunto de IDs para verificación rápida
                             jwt=datos_usuario)  # Pasar datos del token al template

    except sqlite3.Error as e:
        # Manejo de errores de base de datos
        print(f"Error de base de datos: {e}")
        error = 'Ocurrió un error al cargar los cursos. Inténtalo de nuevo más tarde.'
        return render_template('cursos.html', error=error)


    

@app.route('/inscribirse/<int:curso_id>', methods=['POST'])
def inscribirse(curso_id):
    token = request.form.get('token')
    datos_usuario = verificar_token(token)

    if not datos_usuario:
        return redirect(url_for('login_alumno'))

    alumno_id = datos_usuario['id']

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Verificar si el alumno ya está inscrito en el curso
            cursor.execute('SELECT * FROM Inscripciones WHERE alumno_id = ? AND curso_id = ?', (alumno_id, curso_id))
            inscripcion = cursor.fetchone()

            if inscripcion:
                error = 'Ya estás inscrito en este curso.'
                return redirect(url_for('ver_cursos', token=token, error=error))

            # Inscribir al alumno en el curso
            cursor.execute('INSERT INTO Inscripciones (alumno_id, curso_id) VALUES (?, ?)', (alumno_id, curso_id))
            conn.commit()

        return redirect(url_for('ver_cursos', token=token))

    except sqlite3.Error as e:
        print(f"Error de base de datos: {e}")
        error = 'Ocurrió un error al inscribirse en el curso. Inténtalo de nuevo más tarde.'
        return redirect(url_for('ver_cursos', token=token, error=error))


@app.route('/eliminar_curso/<int:curso_id>', methods=['POST'])
def eliminar_curso(curso_id):
    token = request.form.get('token')
    datos_usuario = verificar_token(token)

    if not datos_usuario:
        return redirect(url_for('login_admin'))

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM Cursos WHERE id = ?', (curso_id,))
            conn.commit()

        return redirect(url_for('admin_dashboard', token=token))

    except sqlite3.Error as e:
        print(f"Error de base de datos: {e}")
        return redirect(url_for('admin_dashboard', token=token, error="Ocurrió un error al eliminar el curso."))


# Modificar la ruta de editar_curso para manejar correctamente el token JWT
@app.route('/editar_curso/<int:curso_id>', methods=['GET', 'POST'])
def editar_curso(curso_id):
    token = request.args.get('token')
    datos_usuario = verificar_token(token)

    if not datos_usuario:
        return redirect(url_for('login_admin'))

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Si es una petición POST, actualizamos los datos del curso
            if request.method == 'POST':
                nombre = request.form.get('nombre', '').strip()
                profesor_id = request.form.get('profesor_id', '').strip()
                # Actualizamos el curso con los nuevos datos
                cursor.execute('UPDATE Cursos SET nombre = ?, profesor = ? WHERE id = ?', 
                             (nombre, profesor_id, curso_id))
                conn.commit()
                return redirect(url_for('admin_dashboard', token=token))

            # Si es GET, obtenemos los datos del curso a editar
            cursor.execute('SELECT * FROM Cursos WHERE id = ?', (curso_id,))
            curso = cursor.fetchone()

            # Obtenemos la lista de profesores para el formulario
            cursor.execute('SELECT id, nombre FROM Profesores')
            profesores = cursor.fetchall()

        # Renderizamos el template con los datos del curso y profesores
        return render_template('editar_curso.html', curso=curso, profesores=profesores, jwt_payload=datos_usuario)

    except sqlite3.Error as e:
        print(f"Error de base de datos: {e}")
        return "Ocurrió un error al editar el curso."

@app.route('/editar_profesor/<int:profesor_id>', methods=['GET', 'POST'])
def editar_profesor(profesor_id):
    token = request.args.get('token')
    datos_usuario = verificar_token(token)

    if not datos_usuario:
        return redirect(url_for('login_admin'))

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Si es una petición POST, actualizamos los datos del profesor
            if request.method == 'POST':
                nombre = request.form.get('nombre', '').strip()
                # Actualizamos el nombre del profesor
                cursor.execute('UPDATE Profesores SET nombre = ? WHERE id = ?', 
                             (nombre, profesor_id))
                conn.commit()
                return redirect(url_for('admin_dashboard'))

            # Si es GET, obtenemos los datos del profesor a editar
            cursor.execute('SELECT * FROM Profesores WHERE id = ?', (profesor_id,))
            profesor = cursor.fetchone()

        # Renderizamos el template con los datos del profesor
        return render_template('editar_profesor.html', profesor=profesor)

    except sqlite3.Error as e:
        print(f"Error de base de datos: {e}")
        return "Ocurrió un error al editar el profesor."


# Modificar la ruta de agregar_curso para manejar correctamente el token JWT
@app.route('/agregar_curso', methods=['GET', 'POST'])
def agregar_curso():
    token = request.args.get('token')
    datos_usuario = verificar_token(token)

    if not datos_usuario:
        return redirect(url_for('login_admin'))

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Obtener todos los profesores para el dropdown de selección
            cursor.execute('SELECT id, nombre, correo FROM Profesores')
            profesores = cursor.fetchall()

            if request.method == 'POST':
                # Obtener y limpiar datos del formulario
                nombre = request.form.get('nombre', '').strip()
                descripcion = request.form.get('descripcion', '').strip() 
                profesor_id = request.form.get('profesor_id', '').strip()

                # Validación de campos requeridos
                if not nombre or not profesor_id:
                    error = 'Todos los campos son obligatorios.'
                    return render_template('agregar_curso.html', error=error, profesores=profesores, jwt_payload=datos_usuario)

                # Insertar el nuevo curso en la base de datos
                cursor.execute('INSERT INTO Cursos (nombre, descripcion, profesor) VALUES (?, ?, ?)', 
                             (nombre, descripcion, profesor_id))
                conn.commit()
                return redirect(url_for('admin_dashboard', token=token))

        # Si es GET, mostrar formulario vacío
        return render_template('agregar_curso.html', profesores=profesores, jwt_payload=datos_usuario)

    except sqlite3.Error as e:
        print(f"Error de base de datos: {e}")
        error = 'Ocurrió un error al agregar el curso. Inténtalo de nuevo más tarde.'
        return render_template('agregar_curso.html', error=error, profesores=profesores, jwt_payload=datos_usuario)

@app.route('/retirarse/<int:curso_id>', methods=['POST'])
def retirarse(curso_id):
    token = request.form.get('token')
    datos_usuario = verificar_token(token)

    if not datos_usuario:
        return redirect(url_for('login_alumno'))

    alumno_id = datos_usuario['id']

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Eliminar la inscripción del alumno en el curso
            cursor.execute('DELETE FROM Inscripciones WHERE alumno_id = ? AND curso_id = ?', 
                         (alumno_id, curso_id))
            conn.commit()

        return redirect(url_for('ver_cursos', token=token))

    except sqlite3.Error as e:
        print(f"Error de base de datos: {e}")
        error = 'Ocurrió un error al retirarse del curso. Inténtalo de nuevo más tarde.'
        return redirect(url_for('ver_cursos', token=token, error=error))

@app.route('/logout')
def logout():
    """
    # Ruta para cerrar sesión
    # Elimina todas las variables de sesión
    # Redirecciona al inicio
    """
    return redirect(url_for('inicio'))

# Utilidad para generar hash de contraseña del administrador
# hash_pw = generate_password_hash('admin123')  
# print(hash_pw)  # Comentar después de obtener el hash
